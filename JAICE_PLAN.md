# JAICE — Job Authentication in Computation Environment: Implementation Plan for Galaxy

Source document: `jaice.pdf` — *"Job Authentication in Computation Environment"*,
Dominik Pantůček (CESNET). A protocol for authenticating computing-environment
jobs against Crypt4GH-based data repositories (CESNET-Invenio software pack).
Verbatim markdown transcription with editor's notes: `JAICE_DOC.md`.

## 1. Protocol Summary (from the document)

Two parties authenticate: the **Computing Environment (CE)** — that is Galaxy —
and the **Repository** (CESNET-Invenio). Data lives in the repository as
**Crypt4GH** containers. Data is released only when (1) the CE is verified and
(2) the user explicitly authorized the data release to that CE.

**Keys** (all Ed25519, reused for X25519 via the RFC 7748 Montgomery↔
Twisted-Edwards mapping so one keypair serves both signing and Crypt4GH):

| Key | Owner | Purpose |
|---|---|---|
| ESK/EPK | CE (per Galaxy instance) | ESK signs request JWTs; EPK pre-registered at the repository |
| JSK/JPK | CE (per job, generated at job creation) | JPK identifies the job & is the Crypt4GH recipient; JSK decrypts. **The document's Definitions also say JSK is "used by the CE to sign data and requests related to a specific job" — but no scheme below exercises that; see spec gaps** |
| USK/UPK | User (Option A only) | USK signs the authorization JWT; UPK pre-registered at repo (or via IAM) |

Two facts from the document worth keeping front of mind:
- The CE key table is symmetric with a **user** side: the doc states "both users
  and jobs within the CE must be capable of processing Crypt4GH containers;
  this requires that their SK/PK pairs be compatible with X25519." Users are
  first-class Crypt4GH participants in the design — which supports (does not
  hinder) the zero-plaintext composition with per-user keys.
- The doc explicitly **assumes no trust in the CE**: CEs are "often referred
  to as TCEs, but within the scope of this protocol, no inherent trust is
  assumed; all actions performed by or within the environment must be
  authenticated." A layered CE that keeps data keys off the application tier
  hardens this model rather than violating it.

**Flow:**
1. User creates a job → CE allocates **JobID**, generates **JSK/JPK**, hands
   JobID+JPK to the user.
2. Validation, one of:
   - **Option B (baseline):** user submits JobID+JPK to the repository via a
     *separate channel* (repository web portal) to bind the dataset to the job.
   - **Option A:** user signs JobID+JPK with USK, producing a user JWT; CE
     forwards it alongside its own JWT.
3. CE requests data. Authentication is a **CE-signed JWT**:
   - Header: `{"typ":"JWT","alg":"Ed25519"}` plus optional `"jwk"` claim
     carrying the EPK as an RFC 8037 OKP JWK
     (`{"crv":"Ed25519","kty":"OKP","x":"<b64url>"}`) so the repo can select
     which pre-registered EPK to verify with. **Doc detail: when `jwk` is
     absent, the repository identifies the source CE "through other means
     (e.g., IP address)" — the `jwk` claim is for identification, not trust.**
   - Payload: `{"sub":"<JobID>","jpk":"<b64url Job PK>"}` — doc-confirmed:
     `jpk` is the Base64URL-encoded Job PK.
   - Signature over header.payload with **ESK** (compact serialization).
   - Option A adds the **user JWT** (header with UPK as `jwk`, same payload,
     signed with USK); the repo extracts the `jwk` and matches it against its
     user registry (UPK must be pre-registered, possibly via IAM).
4. Repository verifies, then returns the dataset **re-encrypted as a Crypt4GH
   container for the JPK**. The CE decrypts with JSK (mapped to X25519) and
   processes it.

**Known specification gaps to confirm with CESNET during implementation**
(in order of priority after full document review):
- **#1 — The JSK-signing contradiction (highest priority).** Three places
  disagree in the document itself:
  1. The Definitions define JSK as "used by the CE to sign data and requests
     related to a specific job" — an active signing role;
  2. §3 "Job Execution and Data Retrieval" lists four authentication
     components: JobID, JPK, "a signature of the request generated using the
     JSK", and (Option A) the user signature;
  3. The JWT schemes sign only with ESK (Option B) and USK (Option A) — and
     §3's components 1–2 (JobID, JPK) travel *inside* the ESK-signed JWT.
  Nothing specifies what a JSK signature signs, where it is carried, or how it
  is verified. Clarify: is a JSK signature required at all; if so over what
  and in which field; if not, fix the Definitions and §3. Resolution changes
  implementation: if required, JSK cannot live exclusively in a boundary key
  tier without a signing API there.
- **#2 — JWT transport.** Header name(s) and Option A dual-token framing are
  completely unspecified. Proposal to float with CESNET:
  `Authorization: Bearer <ce-jwt>` plus `X-JAICE-User-JWT` for Option A.
- **#3 — Ed25519→X25519 derivation convention for Crypt4GH recipients.** The
  doc invokes RFC 7748 for the Montgomery↔Twisted-Edwards mapping but does not
  pin the concrete direction for the **public** key the repository must derive
  from JPK (libsodium `crypto_sign_ed25519_pk_to_curve25519` semantics).
  Mismatch = silent decryption failure. Pin it in the spec.
- **#4 (partially resolved) — `alg:"Ed25519"` vs `EdDSA`.** The doc's JWA
  definition cites "RFC 7518, updated by RFC 9864": the literal identifier is
  deliberate (RFC 9864 registers fully-specified `Ed25519`). Remaining risk is
  implementation-level: many stock JWT libraries only accept `EdDSA`. Confirm
  the repository verifier handles the literal; document the requirement.
- **#5 (mostly resolved) — encodings.** Doc-confirmed: `jpk` payload claim is
  "Base64URL-encoded Job PK" and header `jwk.x` follows RFC 8037 OKP. Still
  unpinned: padding convention (assume b64url-without-padding, as JWT).
- NEW **#6 — container-level integrity hash.** Needed if the CE cannot
  decrypt at fetch time (zero-plaintext store): ask the repository to
  provide/record a hash of the released container so the CE can verify
  integrity of a download it cannot open.
- NEW **#7 — DataID↔JobID cardinality and partial binding.** Is N:1 DataID→
  JobID binding permitted (the figures show a single Data ID; the normative
  text doesn't pin cardinality)? If the user confirms only a subset of a
  job's DataIDs, what are retrieval semantics? Will the Invenio binding
  endpoint/UI support batch confirmation under one JobID? Load-bearing for
  D10 in `JAICE_FINDINGS.md` §8.

## 2. Mapping onto Galaxy (verified against this codebase)

Everything the protocol needs already exists in Galaxy except the crypto glue
and orchestration:

| Protocol concept | Galaxy component |
|---|---|
| CE = Galaxy instance | one Galaxy deployment; ESK/EPK = per-instance key pair |
| Job / JobID | **materialize job** for a deferred dataset (see below), or a Galaxy `Job` row |
| Deferred data retrieval | `DatasetState.DEFERRED` + attached `DatasetSource` URIs, materialized via `HDAManager.materialize` (`lib/galaxy/managers/hdas.py:174`) and the Celery task `materialize` (`lib/galaxy/celery/tasks.py:220`) |
| HTTP retrieval from Invenio | RDM file-source stack: `lib/galaxy/files/sources/_rdm.py`, `invenio.py` (`InvenioRepositoryInteractor`, `_realize_to`) |
| CE signing-key storage (ESK only) | `lib/galaxy/security/vault.py` — `DatabaseVault` (MultiFernet-encrypted) or `HashicorpVault`, optionally behind `VaultKeyPrefixWrapper`. Use the plain **instance-level** vault for ESK at `jaice/esk` — **not** `UserVaultWrapper`, which prefixes keys `user/<id>/` for per-user secrets. ESK is identity/signing only; no data keys on the server. Hydra-style HSM path = Hashicorp PKCS#11, no code change |
| JSK custody | **NOT on Galaxy** — generated in and held by the **boundary key service** (see Phase 2b); Galaxy sees JPK only (custody matrix: `JAICE_FINDINGS.md` §6.5) |
| Ed25519 keys/signatures + Ed25519→X25519 mapping | **PyNaCl is already a hard dependency** (`requirements.txt: pynacl==1.6.2`): `nacl.signing.SigningKey`, `nacl.bindings.crypto_sign_ed25519_sk_to_curve25519` satisfy the RFC 7748 mapping |
| JWT issuance | **PyJWT is a hard dependency** but signs as `EdDSA`; the spec demands literal `"alg":"Ed25519"` in the header (RFC 9864 style) → build compact serialization manually with PyNaCl (simple: 3 b64url segments + signature). Keep `verify_jwt` for tests only — never verify inbound tokens with hand-rolled code |
| Crypt4GH handling on server | **None** — Galaxy moves ciphertext containers and parses headers in pure Python via `lib/galaxy/util/crypt4gh.py` (from the crypt4gh_support branch). `crypt4gh` package stays **worker/service-side only** |
| Payload decryption | **Compute node only** — via the branch's transparent staging: boundary key service re-wraps header JPK→node key; node decrypts with its own private key. Confirmed `crypt4gh.lib.decrypt` accepts raw in-memory X25519 bytes (`lib/galaxy/job_execution/crypt4gh_staging.py` on the branch) |
| At-rest datatype model | `<inner>.crypt4gh` wrapper datatypes + `crypt4gh_header`/`crypt4gh_inner_ext` metadata + `matches_any` transparent tool matching (all from `davelopez/feature/crypt4gh_support`) |
| "Job paused while user authorizes" | `Job.states.PAUSED` is first-class (`lib/galaxy/jobs/handler.py:591-594`) with a resume API (`lib/galaxy/webapps/galaxy/api/jobs.py:358`) — no new job state needed in v1 |
| User-facing prompts | notifications framework (`lib/galaxy/schema/notifications.py`) |
| Upload/fetch plumbing | `FetchDataPayload` Src union in `lib/galaxy/schema/fetch_data.py` (`url`, `pasted`, `path`, ... — add a `jaice` variant) |

### Core design decisions

**1. JAICE "Job" == Galaxy materialize job.** Represent protected repository
data as a **deferred dataset** whose `DatasetSource` URI carries the record
identity. NOTE: a bare `jaice://` scheme will not resolve — Galaxy maps
remote-data URIs through the `gxfiles://` prefix bound to a registered
file-source plugin id, so sources must look like
`gxfiles://<jaice-plugin-id>/records/<record_id>/files/<path>` (the repository
URL lives in the per-plugin config, not the URI). Galaxy's materialize
mechanism is the natural execution point for the JAICE handshake:

- The user never handles Crypt4GH bytes; datasets stay `deferred` until needed.
- Each materialization = one JAICE Job, with a fresh JSK/JPK and a random JobID
  (128-bit hex; **not** the Galaxy DB job id, which is guessable/leaky).
- Works identically for manual "materialize", on-demand job-input
  materialization, and workflow invocations (`lib/galaxy/model/__init__.py:7663`
  already tracks deferred inputs for invocations).

**2. Zero-plaintext (Topology A) — decided.** Galaxy head node and object store
**never hold plaintext or data keys**; payload decryption happens only on
compute nodes inside the security boundary. Data plane:

```
repo ──(container for JPK, TLS)──> Galaxy courier (ciphertext to object store)
     ──(job staging)──> boundary key service re-wraps header JPK→node key
     ──> compute node decrypts payload with node private key ──> tool
     ──> node encrypts output directly to final at-rest recipient (no service hop)
```

Rationale, custody matrix, document-compliance audit, and the analysis of
alternatives (incl. why the key service must NOT sit repo-side): see
`JAICE_FINDINGS.md` §5–§6 and `JAICE_CONFLICT_ANALYSIS.md`.

### Foundation: `davelopez/feature/crypt4gh_support`

JAICE is built **on top of** the transparent Crypt4GH staging branch. It is a
hard dependency, not an optional complement — JAICE development is based on
that branch (or lands after it). What it provides JAICE:

- `<inner>.crypt4gh` wrapper datatypes + `crypt4gh_header`/`crypt4gh_inner_ext`
  metadata + `matches_any` transparent tool matching (`datatypes/crypt4gh.py`,
  `registry.py`) — JAICE assigns these at fetch time (Phase 2).
- The staging machinery: staging plan + manifest + pre/post command injection
  (`job_execution/crypt4gh.py`, `jobs/crypt4gh_commands.py`,
  `command_factory.py`) — the JAICE input lane plugs into this via a JobID
  selector extension (Phase 2b).
- The external re-encryptor service as the base of the **boundary key service**
  — JAICE extends it with JobID-keyed JSK custody (Phase 2b).
- `lib/galaxy/util/crypt4gh.py` — pure-Python header parsing for the head
  node (non-secret headers only). `crypt4gh` stays worker/service-side.
- Proven raw in-memory key API: `crypt4gh.lib.decrypt`/`encrypt` accept raw
  32-byte X25519 bytes (`lib/galaxy/job_execution/crypt4gh_staging.py`) —
  used by the key service and by tests, never by the Galaxy server.
- Test harness `Crypt4GHServiceMockManager` + `scripts/crypt4gh_reencryptor/`
  as templates for the JAICE mock repository (Phase 4).

Merge-surface note: overlap is confined to disjoint sections of
`config_schema.yml` and disjoint methods of `jobs/__init__.py` — trivial to
rebase either way.

## 3. Implementation Plan

### Phase 0 — Signing & job-identity primitives (`lib/galaxy/security/jaice/`)

New package, no Galaxy-internal dependencies except PyNaCl/typing, and **no
Crypt4GH code** — JAICE on the server is a pure signing/orchestration layer:

- `keys.py` — `generate_ed25519_keypair()` (for tests/dev fixtures and ESK
  generation), JWK (OKP) serialization of public keys, b64url helpers,
  `ed25519_sk_to_curve25519()` / `_pk_to_curve25519()`.
- `jwt.py` — `build_ce_jwt(esk, job_id, jpk, jwk_claim: bool)` and
  `verify_jwt(jwt, pk)` producing the exact spec tokens
  (header `{"typ":"JWT","alg":"Ed25519"[,"jwk":...]}`,
  payload `{"sub","jpk"}`), manual compact serialization, `iat/exp` optional.
- `keyservice_client.py` — thin HTTP client for the boundary key service
  (Phase 2b): `generate_job_key() -> jpk_bytes`, idempotent
  `provision_job_key(job_id)` (if generation happens server-requested),
  `delete_job_key(job_id)` used at the end of JSK lifetime (see DevSec note
  below). Non-secret traffic only: JobIDs, JPKs, headers.
- Key management script `scripts/jaice_es_keygen.py` — generates ESK/EPK,
  writes ESK to the configured **vault** (`jaice/esk`), prints the EPK JWK for
  repository pre-registration.

**DevSec note (Topology A custody):** ESK is the only secret Galaxy holds —
signing identity, not a data key; vault only (DatabaseVault for dev,
Hashicorp Vault for production; the HSM option the paper mentions maps to a
Hashicorp-backed PKCS#11 deployment, no Galaxy code change). JSK **never**
enters Galaxy: generated in the boundary key service (JobID-keyed registry),
Galaxy only sees JPK. JSK lifetime == dataset lifetime (the container at rest
stays addressed to JPK); `delete_job_key()` fires on dataset purge, with a
cleanup sweep in the key service for orphaned keys of expired
`awaiting_user_binding` rows (TTL/purge policy on the Galaxy side drives the
`jaice_job` row TTL; the service sweeps corresponding JSKs). Never put
secrets in job params — they land in DB/logs/persistence files.

### Phase 1 — Configuration & model

- Config schema (`lib/galaxy/config/schema.py` /
  `lib/galaxy/config/schemas/`…): `enable_jaice: bool`,
  `jaice_es_key_vault_key: str` (default `jaice/esk`),
  `jaice_key_service_url: str` (boundary key service, Phase 2b — typically
  the same deployment as `crypt4gh_reencryption_service_url` from the
  crypt4gh_support branch; fail startup/warn-disable JAICE when unset),
  `jaice_request_ttl: str|int` (purge policy for stale
  `awaiting_user_binding` rows), optional
  `jaice_default_repository` / allowed-repository allowlist.
  Expose read-only bits in `lib/galaxy/managers/configuration.py`.
- Small SQLAlchemy model + alembic migration (`lib/galaxy/model/migrations/`):
  table `jaice_job` — `id`, random opaque `job_id` (protocol subject),
  `jpk` (public, stored so we can display/copy it), `job_id_fk` → `job.id`
  when the materialization is bound to a Galaxy job, `repository_url`,
  `record_id`, `state`
  (`awaiting_user_binding` / `authorized` / `requested` / `done` / `error`),
  `user_jwt` (Option A, base64), `user_id`. **All fields public** — there is
  no secret column on Galaxy anymore; the JSK lives exclusively in the
  boundary key service keyed by this row's `job_id`.

### Phase 2 — Authenticated retrieval (file-source extension)

- `lib/galaxy/files/sources/jaice_invenio.py`:
  `JAICEInvenioFilesSource(InvenioRDMFilesSource)` — reuses the existing RDM
  interactor (`_list`, path parsing, pagination) but overrides `_realize_to`:
  1. Resolve the `jaice_job` row for the materializing dataset (via
     `FilesSourceRuntimeContext`-accessible dataset source / trans).
     If the row's state is < `authorized`, see Phase 3 gating — this method is
     only reached after authorization resolved.
  2. Build the CE JWT (+ user JWT for Option A) and issue the HTTP request
     (transport header naming — open spec question; default proposal
     `Authorization: Bearer <ce-jwt>` + `X-JAICE-User-JWT`, confirm with CESNET).
  3. **Stream the Crypt4GH container as-is** through the temp file the
     framework hands us — no decryption, no `crypt4gh` import; structurally
     validate via `lib/galaxy/util/crypt4gh.py` (`check_crypt4gh`,
     `read_crypt4gh_header`) after the transfer.
  4. Integrity: **no plaintext `source_hash` verification** (cannot decrypt
     head-side — P3 in `JAICE_CONFLICT_ANALYSIS.md`). Rely on TLS +
     container-structure checks; if CESNET supplies container-level hashes
     (spec gap #6), verify those. Type metadata comes from the explicit
     extension + header inspection below, not content sniffing.
  5. Mark dataset OK and assign the **wrapper datatype**: `<inner>.crypt4gh`
     (inner ext derived from the source filename per the branch's
     `infer_crypt4gh_file_ext`), set `metadata.crypt4gh_header` (base64) and
     `metadata.crypt4gh_inner_ext` from the parsed header — all using the
     branch's `Crypt4GH.set_meta`. The dataset is now a normal staging-managed
     dataset and flows through the branch's transparent staging (wrapper
     datatype → matches_any → staging plan → node decrypt). JobID++/manifest
     selector wiring: Phase 2b.
- Optional **explicit-fetch path**: extend `lib/galaxy/schema/fetch_data.py`
  Src union with `src: "jaice"` (`repository_url`, `record_id`, `filename`)
  so users can stage protected data directly from the upload dialog /
  `api/tools/fetch`; it lands as a DEFERRED HDA, same as remote file-source
  imports do today.
- `file_sources_conf.yml.sample` entry documenting the plugin and the
  settings needed.

### Phase 2b — Boundary key service (deltas to `scripts/crypt4gh_reencryptor/`)

The branch's re-encryptor service becomes JAICE's key custodian. All changes
are additive to the service; none touch the user-lane API (`/rewrap_for_compute`,
`/rewrap_for_user`, `/register-key` stay as-is for user-uploaded data).

- **JobID-keyed JSK registry** (`keys.py`): new store `job_keys: dict[job_id,
  (jsk_bytes, created_at)]` next to the existing email-keyed registries.
- **`POST /jaice/job-key`** — `generate-job-key`: generate fresh Ed25519→
  X25519 pair, store JSK under the server-generated JobID, **return only
  `{job_id, jpk_b64}`**. Galaxy calls this when creating a `jaice_job` (Phase
  3 orchestration), then transfers JobID+JPK to the user for binding.
- **`POST /jaice/rewrap`** — input: `{job_id, crypt4gh_header_b64}` → service
  parses the header, unwraps the DEK packet with the JSK for `job_id`,
  re-wraps to the compute public key, returns the new header. Invoked by the
  staging side (below). Never returns plaintext/JSK.
- **`DELETE /jaice/job-key/{job_id}`** — JSK deletion on dataset purge /
  TTL sweep (called from Phase 0's `keyservice_client.delete_job_key`; also a
  server-side sweeper so orphaned JSKs of abandoned requests die even if the
  sweeper call is missed).
- **Optional (blocked on CESNET answer §1 #1):** `POST /jaice/sign` — if the
  doc's mentioned JSK request-signature turns out to be required, signing
  happens here (JSK never leaves the boundary); Galaxy forwards the signature.
  Defer until CESNET clarifies.
- **Staging manifest selector**: extend the branch's
  `Crypt4GHInputEntry`/manifest with an optional `jaice_job_id` field
  (alongside existing `owner_email`); the staging helper
  (`crypt4gh_staging.py`) routes job-bound inputs (wrapper datatype +
  `jaice_job_id` present) to `/jaice/rewrap` instead of `/rewrap_for_compute`.
  Rotation/rotation-safe: the compute private key handling stays as-is.
- Hard requirement for deployment docs: the service runs **inside the CE
  security boundary**, reachable from Galaxy (key generation / deletion) and
  from compute nodes (rewrap) — never repo-side (custody matrix §6.5).

### Phase 3 — Orchestration, API & client

- `lib/galaxy/webapps/galaxy/api/jaice.py` (service class per FastAPI router
  conventions):
  - `GET /api/jaice/environment` — admin/published EPK (JWK) + protocol
    version, for repository operators to pre-register the CE.
  - `GET /api/jaice/requests` — the current user's pending JAICE
    authorizations (JobID, JPK, repository, record, state).
  - `GET /api/jaice/requests/{id}` — the JobID + JPK the user must bind at
    the repository portal (Option B), plus the URL to open.
  - `POST /api/jaice/requests/{id}/user_token` — attach an Option A
    user-signed JWT.
  - `POST /api/jaice/requests/{id}/resume` — after the user confirms binding;
    resumes the paused job / re-triggers materialize.
- Materialize/gate logic — note the **two mechanisms needed**, one per path:
  - **Tool-job inputs** (`JobWrapper.prepare` / deferred-input handling): when a
    dataset's source comes from the JAICE plugin and the `jaice_job` is not yet
    `authorized`, pause the job (`Job.states.PAUSED` + datasets PAUSED, already
    supported at `lib/galaxy/jobs/handler.py:591-594`, resume API at
    `lib/galaxy/webapps/galaxy/api/jobs.py:358`).
  - **Celery materialize / fetch path** (no Job row exists): fail the task with
    a retryable marker and let `/api/jaice/requests/{id}/resume` re-trigger
    `materialize` — there is nothing to put in a PAUSED job state.
  On either path emit a **notification** telling the user to complete binding
  at the repository (Option B) or sign (Option A).
- Client (Vue, `client/src/`):
  - "Data Authorization" panel listing pending requests with copyable
    JobID/JPK and deep link to the repository binding page (Option B path).
  - Option A path: a signing widget (WebCrypto Ed25519 with the user's UPK,
    private key never leaves the browser) producing the user JWT to POST
    (WebCrypto Ed25519 support is patchy in older Safari — the Option B
    copy-JobID flow is the documented fallback).
  - Notification click-through to the panel.
- Wire router in API build; add `api/jaice` routes to the client router.

### Phase 4 — Hardening, ops, tests

- EPK rotation procedure (multiple active EPKs at repo side — spec allows
  claiming via header `jwk`). JSK lifecycle ops live in the boundary key
  service (sweeper + `DELETE /jaice/job-key/{job_id}` fires on dataset purge);
  audit log of data releases (`log_structured` job metrics hooks).
- Rate limiting/abuse: repositories may throttle per-EPK; exponential backoff
  in retrieval.
- Egress policy (docs + enforcement): downloads of JAICE-classified datasets
  are ciphertext-only (or blocked); Galaxy structurally cannot decrypt for a
  user. User-view options are client-side decryption with the user's own
  tooling.
- Worker prerequisites documented: `crypt4gh` + PyNaCl in worker envs,
  compute private key provisioned out-of-band
  (`crypt4gh_compute_private_key_path` / `GALAXY_CRYPT4GH_COMPUTE_PRIVATE_KEY`),
  key-service URL reachable from compute nodes.
- Tests:
  - Unit (`test/unit/`): key/JWT against RFC 8037 vectors + the exact
    examples in the PDF; Ed25519→X25519 mapping round-trip via the `crypt4gh`
    CLI as oracle (test env only); keyservice_client mock round-trips; header
    parse/rewrap fixtures via `lib/galaxy/util/crypt4gh.py`.
  - Integration: a mock repository (tiny FastAPI fixture implementing:
    EPK registry, JobID binding endpoint, JWT verification, Crypt4GH
    re-encryption with `crypt4gh` lib) driven through the full Galaxy
    materialize path in `lib/galaxy_test` / selenium-light flow.
    Reuse `scripts/crypt4gh_reencryptor/` (FastAPI app skeleton, thread-safe
    `KeyRegistry`) and the `Crypt4GHServiceMockManager` lifecycle harness from
    `test/integration/test_crypt4gh_transparent_staging.py` as templates —
    but note that branch has **no auth layer**; EPK registry, `alg:"Ed25519"`
    JWT verification, JobID binding, and re-encrypt-to-JPK are all net-new.
    Pair it with the extended key service (Phase 2b) so tests exercise the
    whole chain: fetch (ciphertext stored) → stage → `/jaice/rewrap` →
    node-side decrypt assert (in a test-simulated boundary).
    Verify the mock repo's JWT acceptance with a stock JWT library
    (no `Ed25519` alg special-casing) to surface the alg-literal compat issue early.
- Docs: `doc/source/admin/` page ("Configuring JAICE repositories" — plugin,
  key service co-deployment, egress policy) + user-facing guide section
  (browse-vs-manual DataID, Option B two-tab flow, ciphertext downloads).

### Suggested delivery order

0. **Base:** land or rebase `feature/crypt4gh_support` first (datatype wrappers,
   staging machinery, key-service base, worker-side `crypt4gh`). JAICE
   develops on top of it.
1. **Phase 0+1+2+2b with Option B only**, retrieval via explicit `src: "jaice"`
   fetch — smallest end-to-end vertical slice: fetch stores ciphertext,
   staging decrypts on a (test) compute node through the extended key service.
2. Phase 3 orchestration for Option B (pause/resume + notifications + panel).
3. Option A (user JWT) API + signing widget.
4. Phase 4 hardening; then upstream-ability review (keep `jaice/` package and
   the file-source plugin free of CESNET-deployment specifics so the feature
   is generic "Crypt4GH repository authentication").

## 4. Dependencies & risks

- **Base dependency:** `davelopez/feature/crypt4gh_support` must land first
  (or JAICE is rebased onto it in a feature stack). Merge surface is trivial
  (disjoint `config_schema.yml` sections, disjoint `jobs/__init__.py` methods)
  but the logical dependency on its manifest format is hard (Phase 2b).
- **Server-side dependencies: none new.** Galaxy gains no `crypt4gh`
  dependency — the server moves ciphertext and parses headers in pure Python
  (`lib/galaxy/util/crypt4gh.py`). `crypt4gh` stays worker/service-side,
  same as the base branch. New service: the **boundary key service**
  (extended re-encryptor) must run inside the CE boundary — new ops burden,
  though identical shape to the branch's existing service.
- No new mandatory JS dependencies (Option A signing can use WebCrypto).
- **Interop risk (highest):** underspecified wire details — JWT transport
  header, the JSK-signing contradiction (spec-cluster #1: Definitions + §3 vs
  the JWT schemes), Option B binding API on the Invenio side, Ed25519→X25519
  derivation convention, and `alg:"Ed25519"` literal acceptance by the repo's
  verifier. Needs a reference implementation or interop session with the
  CESNET-Invenio team; the mock repository in the test plan should encode our
  best-guess interpretation and be adjustable. **Spec-cluster #1 is
  blocking for Phase 2b's optional `/jaice/sign` decision** — without a JSK
  signing requirement the current custody model ships as-is; with one, the
  key service gains a signing API (already listed there, flagged optional).
- **UX risk:** Option B's separate-channel binding is inherently two-tab; the
  notification + deep link flow is the mitigation. The cost scales per
  binding event: a job with N deferred JAICE inputs means N portal
  confirmations under the per-materialization JobID default (v1) — the
  per-Galaxy-job batching option (D10 in `JAICE_FINDINGS.md` §8, gated on
  spec gap #7) exists to address exactly this.
- **At-rest posture: resolved by design (Topology A).** Object store holds
  ciphertext exclusively; plaintext exists only transiently in job working
  directories inside the boundary. Docs must state this posture explicitly for
  sensitive-data deployments, along with the egress policy (ciphertext-only
  downloads for JAICE-classified datasets) and the custody matrix
  (`JAICE_FINDINGS.md` §6.5). Post-release per-job scoping is preserved
  natively — no rewrap-to-user-key exception needed.
- **Worker/co-deploy requirements:** `crypt4gh`+PyNaCl in worker
  environments, compute private key provisioned out-of-band, key-service URL
  reachable from both Galaxy and compute nodes. Failing any of these, JAICE
  datasets fetch fine but jobs fail at staging — the
  `Crypt4GHExternalServiceUnavailable`-style dedicated error path from the
  base branch should surface this clearly.
