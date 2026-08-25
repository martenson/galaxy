# JAICE MVP — Minimum Viable Product Definition

**Goal:** Prove the JAICE protocol works end-to-end in Galaxy with the smallest
possible code footprint, so the remaining work (UX, HA, Option A, batching) is
sequenced *after* the cryptographic and wire-protocol risks are retired.

**Companion documents:** `JAICE_PLAN.md` (full implementation plan),
`JAICE_FINDINGS.md` (architecture decisions), `JAICE_CONFLICT_ANALYSIS.md`
(conflict history), `JAICE_WIRE_PROTOCOL.md` (wire-level contract: exact JWT
format, endpoints, and the PINNED-vs-ASSUMED status of every wire item the
MVP's Week-1 experiments validate).

---

## 1. MVP Scope Statement

> A Galaxy user can materialize a deferred dataset from a CESNET-Invenio
> repository; Galaxy stores the Crypt4GH container as ciphertext; a compute
> node decrypts it via the boundary key service; and the user learns the
> JobID/JPK through a minimal UI surface (admin debug endpoint or email).

**In scope:** Option B only, per-materialization JobIDs, single key-service
instance, no client-side Vue code, no egress policy, no vault-backed registry.

**Out of scope (deferred to post-MVP):** Option A, `src: "jaice"` upload dialog,
notifications framework, pause/resume API, vault-backed key custody, HA, mTLS,
per-Galaxy-job batching (D10), container hash verification, egress enforcement,
negative-case and concurrency tests, formal user docs.

---

## 2. What the MVP Proves (and Does Not Prove)

### Proven by green MVP

| # | Claim |
|---|-------|
| 1 | Galaxy can generate a spec-compliant CE JWT (`alg:"Ed25519"`, `sub`, `jpk`) |
| 2 | The repository (mock or CESNET staging) accepts the JWT and returns a Crypt4GH container for the JPK |
| 3 | Galaxy stores the container as ciphertext (`<inner>.crypt4gh` wrapper, header metadata) |
| 4 | The boundary key service generates JSK, holds it, and re-wraps the header JPK→node key |
| 5 | The compute node decrypts the payload with its own private key |

### NOT proven by MVP (and why that's OK)

| Claim | Deferred because |
|---|---|
| Option A wire compatibility | Requires WebCrypto widget + dual-JWT transport; spec gap #2 unresolved |
| Concurrent materializations | Requires advisory locks; single-user demo suffices |
| EPK rotation / multi-EPK | Ops concern, not a protocol blocker |
| Production key custody (vault/HSM) | In-memory registry proves the architecture; swap backend later |
| User experience | Email/debug endpoint is enough to validate the flow |

---

## 3. MVP Component Breakdown

### 3.1 Phase 0 — Signing primitives (`lib/galaxy/security/jaice/`)

New package, no `crypt4gh` import, no Galaxy-internal deps beyond PyNaCl.

| File | MVP content | Lines |
|---|---|---|
| `keys.py` | `generate_ed25519_keypair()`, JWK (OKP) serialization, b64url helpers, `ed25519_sk_to_curve25519()`, `_pk_to_curve25519()` | ~120 |
| `jwt.py` | `build_ce_jwt(esk, job_id, jpk, jwk_claim: bool)` producing the exact spec token (header `{"typ":"JWT","alg":"Ed25519"[,"jwk":...]}`, payload `{"sub","jpk"}`), manual compact serialization, optional `iat`/`exp` | ~120 |
| `keyservice_client.py` | Thin HTTP client: `generate_job_key() -> (job_id, jpk_bytes)`, `delete_job_key(job_id)` | ~60 |

**Cut:** `verify_jwt()` (only needed for tests; mock repo uses a stock lib).

**Script:** `scripts/jaice_es_keygen.py` — generates ESK/EPK, writes ESK to
`jaice/esk` in the vault (DatabaseVault for MVP), prints EPK JWK for
pre-registration.

### 3.2 Phase 1 — Config & model

| Item | MVP content |
|---|---|
| Config keys | `enable_jaice: bool`, `jaice_es_key_vault_key: str` (default `jaice/esk`), `jaice_key_service_url: str` (fatal startup error if `enable_jaice: true` and unset) |
| Model | `jaice_job` table: `id`, `job_id` (opaque 128-bit hex), `jpk` (public), `repository_url`, `record_id`, `state` (`awaiting_user_binding` / `authorized` / `requested` / `done` / `error`), `user_id`, `created_at`, `error` |
| Migration | Single Alembic migration |

**Cut:** `job_id_fk` (bind to Galaxy job later), `source_uri`, `dataset_id_fk`
(add when wiring to real HDAs), `user_jwt` column (Option A only).

### 3.3 Phase 2 — Authenticated retrieval

`lib/galaxy/files/sources/jaice_invenio.py`:

```python
class JAICEInvenioFilesSource(InvenioRDMFilesSource):
    def _realize_to(self, source_path, native_path, user_context=None):
        # 1. Resolve jaice_job row for this deferred dataset
        # 2. Build CE JWT (+ fresh iat/exp/jti)
        # 3. HTTP request with Authorization: Bearer <jwt>
        # 4. Stream container as-is to native_path
        # 5. Structurally validate via lib/galaxy.util.crypt4gh
        # 6. Assign wrapper datatype + set metadata
```

**Cut:** `src: "jaice"` fetch schema extension (add post-MVP), upload-dialog
integration, `file_sources_conf.yml.sample` documentation.

### 3.4 Phase 2b — Boundary key service (MVP profile)

Extend `scripts/crypt4gh_reencryptor/` with a minimal JAICE module:

| Endpoint | MVP behavior |
|---|---|
| `POST /jaice/job-key` | Generate Ed25519→X25519 pair, store JSK in-memory under server-generated `job_id`, return `{job_id, jpk_b64}` |
| `POST /jaice/rewrap` | Input `{job_id, crypt4gh_header_b64}` → unwrap with JSK, re-wrap to compute key, return new header |
| `DELETE /jaice/job-key/{job_id}` | Delete JSK on dataset purge (or TTL) |
| `GET /health` | Return 200 OK (used by Galaxy readiness probe) |

**Cut:** Vault-backed registry, mTLS between Galaxy↔service, key-service HA,
`POST /jaice/sign` (blocked on CESNET spec gap #1), server-side orphan sweeper.

### 3.5 Staging integration

Reuse davelopez's `crypt4gh_staging.py` with one additive change:

- Extend `Crypt4GHInputEntry` / staging manifest with optional `jaice_job_id`
- When present, route to `/jaice/rewrap` instead of `/rewrap_for_compute`

**Cut:** Service-free output lane (D5), user-key manifest field, auto-provisioned
user keypairs.

### 3.6 User-facing surface (MVP choice)

Pick **one**:

| Option | Pros | Cons | MVP pick? |
|---|---|---|---|
| **Email** | Zero code, works everywhere | No deep link, ugly | ✅ **Yes** (fastest) |
| **Debug endpoint** (`/api/jaice/requests/{id}`) | One FastAPI route, becomes real API later | Requires auth handling | ✅ **Yes** (cleaner) |
| **Notification** | Reuses framework | Too much code for MVP | ❌ Defer |

**Recommendation:** Implement the debug endpoint (`GET /api/jaice/requests/{id}`)
returning `{job_id, jpk, repository_url, record_id}` for the current user.
This is one route, one Pydantic schema, and becomes the foundation of the real
Phase 3 API.

---

## 4. End-to-End MVP Flow

1. Admin configures `enable_jaice: true`, `jaice_key_service_url`, and runs
   `scripts/jaice_es_keygen.py` (writes ESK to vault, prints EPK JWK).
2. Admin pre-registers the EPK JWK at the CESNET-Invenio repository.
3. User (or test harness) creates a deferred dataset whose `DatasetSource`
   URI is `gxfiles://<jaice-plugin-id>/records/<record_id>/files/<path>`.
4. User clicks **Materialize**.
5. Galaxy calls `POST /jaice/job-key` → gets `{job_id, jpk}`.
6. Galaxy creates `jaice_job` row (`state='awaiting_user_binding'`).
7. User fetches `GET /api/jaice/requests/{id}` → sees JobID + JPK.
8. User opens repository portal, selects DataID, binds it to JobID.
9. User clicks **Materialize** again (or retries).
10. Galaxy builds CE JWT, requests data, streams container to object store.
11. Galaxy marks `jaice_job.state='requested'`, assigns wrapper datatype.
12. User runs a job with the dataset.
13. Staging plan sees `<inner>.crypt4gh` + `jaice_job_id`, calls
    `POST /jaice/rewrap` → re-wrapped header.
14. Compute node decrypts payload with its own key. Tool runs.
15. Output encrypts to compute key (existing davelopez flow, MVP accepts
    the two-hop `/rewrap_for_user` hop).

---

## 5. MVP Test Plan (Happy Path Only)

| Test | What it asserts |
|---|---|
| `test_jaice_jwt_builds` | Header/payload/signature match RFC 8037 vectors + PDF examples |
| `test_ed25519_to_x25519_roundtrip` | `crypt4gh` CLI can decrypt a container encrypted for the derived X25519 pubkey |
| `test_keyservice_job_key_lifecycle` | `POST /jaice/job-key` returns JPK; `DELETE` removes JSK |
| `test_mock_repository_accepts_jwt` | Mock repo verifies `alg:"Ed25519"` literal with a stock JWT library |
| `test_end_to_end_materialize` | Deferred dataset → fetch → ciphertext stored → wrapper assigned |
| `test_staging_decrypts` | Compute node (simulated) calls `/jaice/rewrap` and decrypts payload |

**Cut:** Negative cases (bad signature, wrong EPK, expired JWT), concurrency
races, interop canary against real CESNET staging.

---

## 6. Risks That Must Be Retired in Week 1

| Risk | Experiment | Success criterion |
|---|---|---|
| CESNET rejects `alg:"Ed25519"` | Hand-built JWT via `curl` against their staging repo | 200 OK, container returned |
| Ed25519→X25519 derivation mismatch | Unit test: `crypt4gh` CLI encrypts for derived pubkey, PyNaCl-derived secret decrypts | Container opens cleanly |
| Invenio binding API unknown | Write mock repo with assumed `/bind` endpoint; email CESNET for real contract in parallel | Mock behavior matches their reply |

If any of these fail, the protocol interpretation changes *before* 700 lines
of Galaxy code are written.

---

## 7. Explicitly Deferred (Post-MVP Backlog)

| Item | Why deferred | Re-entry point |
|---|---|---|
| Option A signing widget | Requires WebCrypto + dual-JWT transport spec | After CESNET confirms gap #2 |
| `src: "jaice"` upload dialog | Needs fetch-schema change + client wiring | Phase 3 |
| Pause/resume + notifications | Requires Celery job-state bridge + Vue panel | Phase 3 |
| Vault-backed key custody | Ops hardening, not protocol validation | Phase 4 |
| Key-service HA | Single instance proves architecture | Phase 4 |
| Per-Galaxy-job batching (D10) | Requires CESNET confirmation of N:1 binding | After gap #7 answer |
| Container hash verification | Requires CESNET to supply the hash | After gap #6 answer |
| Egress policy | Policy layer, not protocol layer | Phase 4 |
| Negative-case & concurrency tests | Edge hardening | Phase 4 |
| Admin/user docs | MVP README suffices | Phase 4 |

---

## 8. Definition of Done

The MVP is done when:

1. A Galaxy admin can configure JAICE in under 10 minutes using the MVP README.
2. A deferred dataset can be materialized from a mock repository and stored
   as ciphertext.
3. A compute node (real or simulated) calls `/jaice/rewrap` and decrypts the
   payload.
4. All 6 happy-path tests pass.
5. The CESNET interop curl (risk #1) has been confirmed or the failure is
   documented and the plan updated.

At that point, the protocol interpretation is locked and the team can move to
Phase 3 (UX) and Phase 4 (hardening) with confidence that the cryptographic
foundation is correct.
