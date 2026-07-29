# JAICE vs. Transparent Crypt4GH Staging — Conflict Analysis

Date: 2026-07-11
Companion to: `JAICE_PLAN.md`
Compared against: `davelopez/galaxy` branch `feature/crypt4gh_support`
(`https://github.com/galaxyproject/galaxy/compare/dev...davelopez:galaxy:feature/crypt4gh_support`)

**Premise (decided by user):** Galaxy must never have access to plaintext data —
the invariant established by davelopez's transparent Crypt4GH staging design
must hold for JAICE-fetched data as well.

## The two designs in one paragraph each

**JAICE plan (as written):** at materialize time, `JAICEInvenioFilesSource._realize_to`
authenticates to the repository with CE-signed JWTs, receives a Crypt4GH
container re-encrypted for the per-job JPK, streams it through
`decrypt_container_for_jsk()` on the Galaxy server, and stores **plaintext** in
the object store. JSK lives in Galaxy's vault and is deleted right after the
materialization completes.

**davelopez/feature/crypt4gh_support:** datasets stay **encrypted at rest**;
the object store holds only ciphertext. Plaintext exists only in the job
working directory on compute nodes. The Galaxy head node never holds plaintext
or private keys — it deals in public key material and Crypt4GH **headers only**
(non-secret, base64-encoded in a staging manifest). Header re-wrapping
(user key ↔ compute key) is done by an external re-encryptor service; payload
decryption happens locally on the compute node with a co-located compute
private key (`GALAXY_CRYPT4GH_COMPUTE_PRIVATE_KEY`). Tool compatibility comes
from dynamically registered `<inner>.crypt4gh` wrapper datatypes with a
`matches_any` override. The `crypt4gh` package is deliberately kept off the
Galaxy server (worker/service-side only); the server parses headers with pure
Python (`lib/galaxy/util/crypt4gh.py`).

## Conflicts, prioritized

### P0 — Decrypt-at-realize directly violates the invariant — BLOCKING, architecture-deciding

The plan's Phase 2 step 3 (`decrypt_container_for_jsk()` into the object store)
puts plaintext at rest — exactly what the davelopez design exists to prevent.
It also makes `crypt4gh` a **server-side** dependency, which his branch
carefully avoids.

- Evidence in plan: Phase 2 `_realize_to` steps 3–4; §4 "object store holds
  plaintext" risk note (carved out as "acceptable for v1").
- Resolution: `_realize_to` stores the JPK-bound container **as-is**, assigns
  the `<inner>.crypt4gh` wrapper datatype plus `crypt4gh_header` /
  `crypt4gh_inner_ext` metadata, and leaves decryption to his compute-time
  staging. This single decision shapes everything below.

### P1 — JSK lifetime and physical location — BLOCKING

Opposite lifecycle models collide:

- JAICE plan: JSK is short-lived (per materialization), kept in Galaxy's pool,
  deleted after materialize — because decryption happens *during* the same
  task.
- davelopez: decryption keys live in the re-encryptor's registry for the
  **dataset's lifetime** — because decryption happens at every downstream job.

If the container stays encrypted for JPK and JSK is deleted after the fetch,
the dataset is permanently unreadable at compute time. Two resolutions:

1. **Immediate rewrap (recommended):** during materialize, *before* deleting
   JSK, call a new service endpoint (e.g. `rewrap_from_job`: header + JobID →
   re-keyed for the user's keypair). After that the dataset is an ordinary
   user-keyed `.crypt4gh` dataset fully inside the existing staging pipeline.
   JAICE keeps short-lived JSKs; no JAICE-specific lifetime coupling.
2. **JobID-keyed registry:** the re-encryptor holds per-job JSKs for the
   dataset's lifetime, tied to HDA purge/deletion hooks. Simpler service API,
   but JAICE-specific state and lifecycle coupling persist forever.

Hardening nuance: Galaxy generates JSK/JPK locally in order to hand JPK to the
repository, so JSK necessarily transits Galaxy memory in v1. A stronger v2
option moves job-key *generation* into the re-encryptor service
(`generate-job-key` returning only JPK), achieving "no private keys ever on
the head node."

### P2 — Recipient principal mismatch: job key vs. user key — BLOCKING

The two systems bind authorization to different principals:

- JAICE: the repository releases data encrypted for the **per-job JPK**.
- davelopez staging: recipient selection is by **`owner_email`** — a per-user
  keypair in the service registry (`RegisterKeyRequest`; manifest entry
  `Crypt4GHInputEntry.owner_email`).

Bridging requires either the `rewrap_from_job` endpoint (P1, option 1) or
extending the staging manifest with a JobID key. Consequences:

- **New onboarding requirement:** every JAICE user needs a keypair registered
  in the re-encryptor service before fetching protected data. Needs UX
  (auto-registration at first JAICE use, or an explicit "register key" flow).
- **Policy question to decide explicitly:** JAICE's protocol intent is that
  only the *authorized job* reads the data. Rewrapping to a long-lived user
  key lets **any later job of that user** read it. Defensible (the release was
  authorized to the CE; post-release data governance is internal to the CE),
  but it must be a documented decision, not an accident.

### P3 — Fetch-time integrity verification is impossible — PARTIALLY BLOCKING (pipeline breaks)

Galaxy's fetch machinery verifies declared `source_hash`/size against the
**plaintext** returned by `_realize_to`. With ciphertext stored, the head node
cannot verify plaintext hashes; datatype sniffing against plaintext content is
likewise impossible at fetch time.

- Resolution options: skip `source_hash` verification for JAICE sources (rely
  on TLS + Crypt4GH container-structure validation, per
  `lib/galaxy/util/crypt4gh.py`), or ask CESNET for a **container-level hash**
  — add to the JAICE spec-gap list.
- Fetch code must assign the wrapper extension explicitly rather than sniff.

### P4 — Download/display UX: users receive ciphertext — UX-ONLY

JAICE-fetched datasets download as Crypt4GH ciphertext, decryptable only with
the user's private key (davelopez ships a `decrypt-dataset` CLI flow for this).
Consistent with the chosen invariant, but a material change from "user gets a
normal dataset." Needs documentation, and it makes the P2 key-onboarding flow
unavoidable rather than optional.

### P5 — Sequencing: complement becomes hard dependency — SCHEDULING

Zero-plaintext JAICE reuses, from the sibling branch: the
`_register_crypt4gh_datatypes` dynamic registration, wrapper datatypes and
metadata, the staging plan/manifest (`Crypt4GHStagingPlan`,
`Crypt4GHInputEntry.owner_email`), pre/post command injection
(`command_factory.py`, `crypt4gh_commands.py` work), Pulsar plumbing, the
re-encryptor service, and the `Crypt4GHServiceMockManager` test harness.

- File-level merge conflicts remain trivial (shared edits only in
  `config_schema.yml` and `lib/galaxy/jobs/__init__.py`, disjoint
  sections/methods).
- The **logical coupling through the manifest format** is the real dependency
  (`owner_email` is the only recipient selector; JAICE needs either a JobID
  field or the user-key rewrap).
- Action: JAICE development should be based **on top of**
  `feature/crypt4gh_support`, or that branch should land first.

## Non-conflicts (verified worth stating)

- **The JAICE wire protocol is unchanged.** The repository still verifies the
  same JWTs and re-encrypts to JPK. Everything about the zero-plaintext
  composition is internal to the CE and invisible to CESNET. The paper's "the
  CE decrypts with JSK" is satisfied: decryption occurs inside the CE trust
  boundary (compute node), merely not inside the Galaxy application process.
- Orchestration is unaffected: Option B portal binding, Option A user JWTs,
  pause/resume gating (`Job.states.PAUSED` at `handler.py:591-594`, resume API
  at `api/jobs.py:358`), notifications, random opaque JobIDs, ESK handling.
- File-overlap with the sibling branch stays minimal (JAICE: file sources,
  fetch schema, materialize, API layer; davelopez: datatypes, job execution,
  command factory).

## Key facts established during analysis

- `crypt4gh.lib.decrypt(keys=[(0, raw_sk_bytes, None)], infile=..., outfile=...)`
  and `crypt4gh.lib.encrypt` accept **raw in-memory X25519 key bytes** — no
  on-disk key files needed
  (evidence: `lib/galaxy/job_execution/crypt4gh_staging.py` on the branch).
  Only `crypt4gh.keys.get_private_key` is path-based.
- davelopez's Galaxy **server** never imports `crypt4gh`; the package is used
  worker-side (`job_execution/crypt4gh_staging.py`) and in the service
  (`scripts/crypt4gh_reencryptor/`).
- The re-encryptor service API: `POST /rewrap_for_compute`,
  `POST /rewrap_for_user`, `GET /compute-public-key`, `POST /register-key`,
  all exchanging base64 **headers** plus public keys only — payloads and
  private keys never cross the wire. Mock service holds user private keys
  in-memory (`KeyRegistry`, `keys.py`); production story is a vault backend.
- Compute-side payload decryption uses the locally provisioned compute private
  key (`crypt4gh_compute_private_key_path` → `GALAXY_CRYPT4GH_COMPUTE_PRIVATE_KEY`).
- The mock-service lifecycle manager `Crypt4GHServiceMockManager` in
  `test/integration/test_crypt4gh_transparent_staging.py` is a ready-made
  template for JAICE's mock repository harness.

## Priority summary

| # | Conflict | Blocking? | Resolution | Effort |
|---|---|---|---|---|
| P0 | Plaintext in object store at realize | **Architecture-deciding** | Store container as-is; staging decrypts | Medium (rewrite Phase 2 steps 3–4) |
| P1 | JSK lifetime/location | Yes | Immediate rewrap→user key, then delete JSK (new endpoint) | Medium |
| P2 | Job-key vs user-key principal | Yes | Bridge endpoint + user-key onboarding UX + documented policy ruling | Medium + decision |
| P3 | Plaintext hash verification | Partial | Skip for JAICE, or container hash from CESNET (new spec gap) | Small ± CESNET |
| P4 | Ciphertext downloads | UX only | Docs + local-decrypt CLI flow | Small |
| P5 | Dependency on sibling branch | Scheduling only | Base JAICE on `feature/crypt4gh_support` | — |

## Open decisions for the plan rewrite

1. P1 choice: immediate-rewrap (`rewrap_from_job`) vs. JobID-keyed registry.
   Recommendation: immediate rewrap — minimal JAICE-specific long-lived state.
2. P2 policy: accept "any later job of the owning user may read the data"
   as the documented post-release governance model, or keep per-job keys
   (forces P1 option 2). Recommendation: accept user-key model, document it,
   and surface it to CESNET as a note (not a blocker).
3. P2 UX: auto-provision user keypairs at first JAICE use vs. explicit
   registration step. Recommendation: auto-provision with a user-visible
   notice.
4. P3: CESNET spec-gap request for a container-level hash; meanwhile rely on
   TLS + structure checks.
5. Base-branch strategy for development (P5).
