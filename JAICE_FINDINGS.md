# JAICE × Transparent Crypt4GH Staging — Consolidated Findings

Date: 2026-07-11, updated 2026-07-29 after a full read of the source PDF.
Author: analysis session led by Martin Cech.
Companion documents: `JAICE_PLAN.md` (implementation plan),
`JAICE_CONFLICT_ANALYSIS.md` (step-by-step conflict inventory),
`JAICE_DOC.md` (verbatim markdown transcription of `jaice.pdf`).

This file consolidates every important finding from the analysis of the
JAICE protocol (CESNET paper by Dominik Pantůček, `jaice.pdf`), the Galaxy
implementation plan, and the compatibility of the plan with davelopez's
`feature/crypt4gh_support` branch — under the decided constraint that
**Galaxy (head node and object store) must never have access to plaintext
data**, with jobs executing on separate hardware inside a security boundary.

---

## 1. Verified facts about the JAICE protocol (from the document)

- Two parties: **CE (Computing Environment)** = Galaxy deployment, and the
  **Repository** (CESNET-Invenio). Data released only when CE is verified
  AND the user authorized release to that CE.
- Three Ed25519 key pairs: **ESK/EPK** (CE instance identity, signs request
  JWTs), **JSK/JPK** (per-job, JPK is both job identifier and Crypt4GH
  recipient), **USK/UPK** (user, Option A only). Ed25519 keys reused for
  X25519 via the RFC 7748 mapping so one keypair serves both signing and
  Crypt4GH. The doc states users AND jobs within the CE must be able to
  process Crypt4GH containers (X25519-compatible key pairs) — users are
  first-class Crypt4GH participants by design.
- The doc **assumes no inherent trust in the CE** ("often referred to as TCEs,
  but within the scope of this protocol, no inherent trust is assumed; all
  actions performed by or within the environment must be authenticated"). A
  layered CE that keeps data keys off the application tier hardens this model
  rather than departing from it.
- Two validation paths: **Option B** (user binds JobID+JPK out-of-band at the
  repository portal — baseline; figure shows the user also sending the DataID
  and the repo binding DataID→JobID) and **Option A** (user signs with USK; CE
  forwards user JWT alongside its own).
- Repository trust model: EPKs and UPKs are **pre-registered** (UPK possibly
  via IAM); the optional `jwk` header claim identifies *which* CE/user is
  calling — when absent the repo identifies the CE "through other means (e.g.,
  IP address)".
- Request authentication: compact JWT with header `{"typ":"JWT","alg":"Ed25519"}`
  and payload `{"sub":"<JobID>","jpk":"<b64url JPK>"}`, signed with ESK.
- Release: repository re-encrypts the dataset as a Crypt4GH container **for
  the JPK**; processor-side decryption happens with JSK (mapped to X25519).

### Open specification gaps (to raise with CESNET, priority order)
1. **The JSK-signing contradiction (highest).** The Definitions define JSK as
   "used by the CE to sign data and requests related to a specific job"; §3
   lists "a signature of the request generated using the JSK" as data-
   authentication component #3 of 4; yet both JWT schemes sign with ESK (Option
   B) / USK (Option A) and §3's components 1–2 (JobID, JPK) travel inside the
   ESK-signed JWT. What a JSK signature would sign, where it would be carried,
   and how it would be verified are nowhere specified. **Load-bearing for the
   zero-plaintext architecture**: if a JSK signature is required at request
   time, JSK cannot sit exclusively in a boundary key tier without exposing a
   signing API (see §6.4 amendment 4).
2. JWT transport (header names, Option A dual-token framing) unspecified —
   propose `Authorization: Bearer <ce-jwt>` + a second header for the user JWT.
3. b64url encoding details: doc confirms `jpk` is "Base64URL-encoded Job PK"
   and `jwk.x` follows RFC 8037 OKP; padding convention still unpinned
   (assume unpadded, JWT-style).
4. Ed25519→X25519 recipient-derivation convention must be pinned (silent
   decryption failure if repo and CE derive differently). The doc invokes
   RFC 7748 for the mapping but not the concrete public-key direction.
5. **`alg:"Ed25519"` is deliberate, not an error**: the doc's JWA definition
   cites "RFC 7518, updated by RFC 9864" — RFC 9864 registers the
   fully-specified `Ed25519` identifier. Remaining risk: most stock JWT
   libraries only accept `EdDSA`; the repository verifier must handle the
   literal. Confirmed intent, verify implementation capability.
6. NEW: container-level hash so the CE can verify integrity of a ciphertext
   download it cannot decrypt (see §5 P3).

---

## 2. Verified facts about Galaxy ("what the plan can rely on")

All references checked against branch `dev` in the `jaice` worktree:

- Deferred datasets + materialize machinery exist and are the natural JAICE
  execution point: `HDAManager.materialize` (`lib/galaxy/managers/hdas.py:174`),
  Celery task `materialize` (`lib/galaxy/celery/tasks.py:220`), deferred-
  input tracking for workflow invocations (`lib/galaxy/model/__init__.py:7663`).
- **Materialize runs on the Galaxy server** (web handler / Celery worker),
  NOT on compute hardware. Consequence: any decryption in `_realize_to`
  happens outside the compute security boundary.
- Remote-data URIs resolve through `gxfiles://<plugin-id>/...` only; a bare
  `jaice://` scheme cannot be registered. Repository URL belongs in the
  file-source plugin's config.
- `Job.states.PAUSED` is first-class with resume API
  (`lib/galaxy/jobs/handler.py:591-594`; `lib/galaxy/webapps/galaxy/api/jobs.py:358`)
  — supports "paused while user authorizes" with no new job state.
  The Celery/fetch path has no Job row, so gating there = fail-and-retrigger.
- Vault subsystem (`lib/galaxy/security/vault.py`): `DatabaseVault`,
  `HashicorpVault`, wrappers. `UserVaultWrapper` prefixes keys `user/<id>/` —
  wrong for the instance-wide ESK; use the plain instance vault.
- **PyNaCl is a hard dependency** (`pynacl==1.6.2`): Ed25519 signatures and
  `nacl.bindings.crypto_sign_ed25519_sk_to_curve25519` satisfy the RFC 7748
  mapping with no new crypto dependency.
- **PyJWT is a hard dependency but signs `EdDSA` only** — the spec's literal
  `alg:"Ed25519"` requires hand-built compact serialization with PyNaCl
  (~3 b64url segments + signature). Use only for *issuing*; never verify
  inbound tokens with hand-rolled code.
- Fetch machinery verifies declared `source_hash`/size against **plaintext**
  returned by `_realize_to` — breaks under ciphertext storage (§5 P3).

---

## 3. Verified facts about davelopez's `feature/crypt4gh_support`

(20 commits, +4,315 lines; examined in the local clone.)

**Architecture:** transparent Crypt4GH staging — datasets encrypted **at
rest in the object store**; plaintext exists only in the job working
directory on compute nodes. Head node handles only ciphertext, Crypt4GH
headers (explicitly non-secret, kept in metadata `crypt4gh_header`), and a
manifest of public values. Two cooperating cryptographic actors:

- **Re-encryptor service** (external to Galaxy): re-wraps headers between
  recipients. API exchanges only base64 headers + public keys
  (`POST /rewrap_for_compute`, `POST /rewrap_for_user`,
  `POST /register-key`, `GET /compute-public-key`). Mock holds user private
  keys in-process (`KeyRegistry`, explicitly "mock only — production = vault").
- **Compute node**: decrypts payload locally with a co-located compute
  private key (`GALAXY_CRYPT4GH_COMPUTE_PRIVATE_KEY`); encrypts outputs.

**Implementation details that matter for JAICE:**
- Dynamic `<inner>.crypt4gh` wrapper datatypes with `matches_any` transparent
  tool-input matching; header-only sniffing; `crypt4gh_inner_ext` metadata.
- Head node never imports `crypt4gh` — pure-Python header parsing only
  (`lib/galaxy/util/crypt4gh.py`). `crypt4gh` (NBIS/EGA PyPI package) is
  worker/service-side only and is not in Galaxy server requirements.
- **Confirmed: `crypt4gh.lib.decrypt`/`encrypt` accept raw in-memory X25519
  key bytes** (`crypt4gh_staging.py:108-115, 165-180`) — no on-disk key files
  needed. Only `crypt4gh.keys.get_private_key` is path-based.
- Job dispatch point: staging plan + pre/post shell fragments
  (`lib/galaxy/jobs/crypt4gh_commands.py`) wrap the tool invocation; written
  into job working dir (`lib/galaxy/job_execution/crypt4gh.py`); Pulsar-run
  jobs additionally depend on worker-side provisioning documented in the
  demo guide (`scripts/crypt4gh_reencryptor/CRYPT4GH_DEMO_GUIDE.md`).
- Test harness reusable by JAICE: `Crypt4GHServiceMockManager`
  (`test/integration/test_crypt4gh_transparent_staging.py`) manages the mock
  service lifecycle.
- Recipient identity throughout is **`owner_email`**-keyed user keypairs —
  the single point of coupling JAICE must bridge (per-job vs per-user).

**Output-lane simplification opportunity found:** the demo encrypts outputs
for the compute key and re-wraps headers to the user key (two hops, egress
path depends on the service). Encryption needs only public keys, so the node
can encrypt outputs **directly to the final recipient** — service-free output
lane.

---

## 4. Deployment topology (decided by Martin)

- **Galaxy head node is structurally untrusted for data**: it must move
  Crypt4GH containers without any key that could see inside.
- **Compute hardware sits inside a security boundary** and is the only
  legitimate place for plaintext ("in use").
- Decryption AND re-encryption of payloads happen on the compute node with
  the node's private key.
- The JAICE repository's release condition ("processed by the authenticated
  CE") is interpreted as: plaintext exists only inside the trusted compute
  tier.

Consequence for the original plan version: **decrypt-at-realize was not
merely less secure — it manufactured plaintext on the head node, outside
the boundary, contradicting JAICE's own release intent.** The composed
design below is the one consistent with the protocol's purpose.

## 5. Conflict inventory between plane JAICE and zero-plaintext (priorities)

| # | Conflict | Verdict | Resolution |
|---|---|---|---|
| P0 | Decrypt-at-realize puts plaintext in the object store | **Architecture-deciding** | Store container as-is (`<inner>.crypt4gh` wrapper datatype + header metadata) |
| P1 | JSK lifetime/location (short-lived in Galaxy vault vs. dataset-lifetime in service) | Blocking | JSK never in Galaxy; key service inside boundary; JobID-keyed registry |
| P2 | Recipient principal mismatch: JAICE per-job JPK vs. staging per-user `owner_email` | Blocking | JobID selector in manifest/service; user-key lane reserved for user-uploaded data |
| P3 | Plaintext hash verification impossible head-side | Pipeline constraint | Skip JAICE-source plaintext hashes; container-structure checks + request CESNET container hash |
| P4 | User downloads arrive as ciphertext | UX/policy | Egress policy: sensitive datasets blocked or ciphertext-only; Galaxy *structurally* cannot decrypt for the user, making the policy self-enforcing |
| P5 | JAICE becomes a hard dependent of the branch | Scheduling only | Base JAICE development on `feature/crypt4gh_support` |

Non-conflicts verified: wire protocol bit-identical; pause/resume/Option A/B
orchestration untouched; file-level merge overlap trivial (`config_schema.yml`,
`jobs/__init__.py`, disjoint spots).

---

## 6. The final architecture ("Topology A")

Data plane: repo →(container for JPK, TLS)→ Galaxy courier → object store
(ciphertext) → staging pre-command → **boundary key service** re-wraps header
JPK → node key → **compute node** decrypts payload with node private key →
tool → node encrypts output directly to final at-rest recipient (public keys
only, no service call).

Control plane (Galaxy): JAICE Job model + JWT forging with ESK; JSK/JPK
generation **inside the key service, Galaxy only ever sees JPK**.

### 6.1 Why JSK cannot live on Galaxy AND why it doesn't have to
The one unavoidable private-key operation is unwrapping a container header
addressed to JPK — needs JSK, by definition, wherever it happens. Placing it
in the boundary key service keeps **one private key per node** (compromise of
a node exposes only in-flight job data, not every released dataset).
Alternative (per-job JSK delivered to the node at dispatch) removes the
service from the input lane but sprawls private keys across nodes with
scrub-discipline burden — rejected.

### 6.2 Per-job release scoping comes out **stronger**, not weaker
With JobID-keyed JSKs in the service and per-staging re-wrap JPK→node key,
no long-lived broadly-usable recipient key is ever created. JAICE's per-job
intent (the P2 policy fear under the earlier "rewrap-to-user-key" idea)
dissolves — no documented exception needed.

### 6.3 Compatibility with the JAICE document: **normatively full, prose positive**
Audited requirement-by-requirement (see `JAICE_CONFLICT_ANALYSIS.md` for the
table). Result:
- All normative requirements (key roles, JWTs, validation channels,
  JPK recipient) — satisfied identically.
- Security property "only the entity holding JSK can make the data readable" —
  preserved.
- Step 4's prose "the CE decrypts with JSK and processes it" describes a
  single-actor flow; Topology A splits it into JSK-header-unwrap (service) +
  node-payload-decrypt (node). **The document is silent, not violated.**
- The §3 JSK-signature ambiguity is now load-bearing: if a JSK-signed request
  is truly required, signing must move into the key tier.

### 6.4 Recommended additive amendments to the JAICE document
(Clarifications only — no changes to keys, JWTs, endpoints, or trust model.)
1. Step 4: allow "JSK makes the container readable to the authorized
   computation (directly or via CE-internal header re-wrap); payload
   decryption occurs within the CE's trusted compute tier."
2. Define "CE" as a tiered deployment (application / key / compute tier).
3. Explicitly permit JSK use by a dedicated key service for header re-wrap.
4. Resolve the §3 JSK-signature ambiguity, including whether the key tier
   may sign on the requester's behalf.
5. Pin the Ed25519→X25519 recipient-derivation convention.
6. The only scenario that would make Topology A non-compliant: a strict
   reading forbidding CE-internal re-wrap — get this on the record in the
   interop session, not assumed.

### 6.5 Key custody matrix and service placement
(From the "who holds JSK" and "can the service sit repo-side" analyses.)

| Component | Holds JSK? | Reasoning |
|---|---|---|
| **Boundary key service** | **Yes — sole holder** | JobID-keyed JSK registry; only performs header re-wrap JPK→node key at staging time. Placed *inside the CE security boundary*. |
| **Galaxy head node** | No — never sees it | `generate-job-key` called on the service returns JPK only; Galaxy stores only JPK/JobID in the DB. |
| **Compute node** | No | Holds only its *own* private key — node compromise exposes in-flight job data only, not every released dataset (this is why Topology B "deliver JSK to the node" was rejected). |
| **Repository** | **No — must never see a JSK** | Receives only JPK as release recipient. |
| **User** | No | Receives only public values (JobID, JPK) for binding/signing. |

**Why the key service must NOT sit repository-side** (would invert the
release model):
1. The service holds JSK, and JSK custody *is* the CE's proof of control —
   a repo-held JSK lets the repo operator decrypt every released payload, so
   "only the CE can make the data readable" ceases to be verifiable.
2. Re-wrap is invoked at **staging time**, repeatedly for every job run —
   a repo-side service would couple every job start to an external endpoint
   and require the repo to track the CE's internal node-key inventory and
   rotation.
3. The protocol pins the release recipient to the per-job **JPK** exactly
   so the repository never needs to know CE-internal keys.
4. Having a repository encrypt directly for the (infrastructure) node key
   instead of JPK collapses the blast radius from "one job's dataset" to
   "everything ever released to that node."

**"Double re-encryption" is a misconception:** the payload is encrypted
once, at the repository, keyed by the DEK. Every subsequent step (release
for JPK, re-wrap for node key, output encryption) rewrites only the few-KB
header packets wrapping the DEK — payload bytes are never re-encrypted, so
there is no meaningful efficiency to gain by moving the re-wrap repo-side.

**Exception:** if one organization operates both repository and CE (e.g., a
CESNET-run Galaxy + CESNET-Invenio), hardware co-location is harmless — but
services should remain logically separate so the deployment still works
when operators differ.

---

## 7. Egress and key-management policy that falls out of the design

- Galaxy structurally cannot produce plaintext for a user → encrypted or
  blocked downloads become self-enforcing for JAICE-classified datasets.
- The compute-side staging adds hard *worker* requirements: `crypt4gh` +
  PyNaCl installed in worker environments, compute private key provisioned
  out-of-band (and referenced via `crypt4gh_compute_private_key_path` /
  `GALAXY_CRYPT4GH_COMPUTE_PRIVATE_KEY`), service URL reachable from nodes.
- ESK remains server-side (identity/signing, not data access) — keep in
  vault; HSM path already noted in the plan.
- davelopez's mock service holding user private keys is dev-only; production
  needs a vault-backed custody story (also for the future user-upload lane).

---

## 8. Outstanding decisions (owner: Martin + CESNET interop session)

| # | Decision | Current recommendation |
|---|---|---|
| D1 | Base branch for JAICE dev | `feature/crypt4gh_support` |
| D2 | Input-lane re-wrap owner | Boundary key service (Topology A) |
| D3 | JSK generation location | Inside boundary service; Galaxy sees JPK only |
| D4 | Manifest recipient selector | Add JobID alongside `owner_email` |
| D5 | Output recipients | Direct node encryption to at-rest recipient; no service hop |
| D6 | Egress policy for JAICE datasets | Ciphertext-only/blocked by default; policy in docs |
| D7 | CESNET spec gaps | §6.4 list + container hash request |
| D8 | JSK-signing contradiction (Definitions + §3 vs JWT schemes) — spec-cluster #1 | Blocking-on-CESNET before Phase 2 ships; if a JSK signature is required, the key tier needs a signing API |
| D9 | Key-service placement | CE-side, inside the boundary (never repo-side — see §6.5) |

---

## 9. One-line summary

JAICE's authenticated-release protocol and a zero-plaintext Galaxy are not
just compatible — when compute runs inside a security boundary, the
ciphertext-only architecture (containers at rest, JobID-keyed JSK in a
boundary key service, node-local decryption, service-free output encryption)
is the implementation that actually *fulfills* the protocol's release
intent; the document needs only additive prose clarifications, and the
remaining substantive unknowns reduce to CESNET's answer on the §3 JSK
signature and their stance on CE-internal header re-wrap.
