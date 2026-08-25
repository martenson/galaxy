# JAICE Wire Protocol — Galaxy MVP Profile

**Purpose:** pin, in one place, the exact bytes Galaxy will put on the wire when
requesting data from a CESNET-Invenio repository, and which parts are
normative (from `JAICE_DOC.md` / the paper) vs. assumed (proposed to CESNET,
pending confirmation).

**Companion documents:** `JAICE_MVP.md` (MVP scope), `JAICE_PLAN.md` (full
plan), `JAICE_DOC.md` (verbatim paper transcription), `JAICE_FINDINGS.md` §1
(spec-gap tracker).

**Status of this document:** anything marked **PINNED** comes from the paper;
anything marked **ASSUMED** is our proposal to CESNET (tracked as a spec gap
and listed in the Week-1 interop experiments in `JAICE_MVP.md` §6).
If CESNET's staging instance rejects an ASSUMED item, this document is the
first thing to update — it is the contract the mock repository encodes.

---

## 1. Transport

| Item | Status | Value |
|---|---|---|
| Protocol | PINNED | HTTPS (TLS) |
| HTTP method | **ASSUMED** (gap #9) | Proposed: `GET` on the file's download URL, or `POST /jaice/request` if CESNET adds a dedicated endpoint. Unresolved. |
| Auth header (Option B) | **ASSUMED** (gap #2) | `Authorization: Bearer <CE JWT>` |
| Option A second token | **ASSUMED** (gap #2) | `X-JAICE-User-JWT: <user JWT>` alongside the Bearer CE JWT |
| Error contract | **ASSUMED** (gap #9) | 401 = JWT invalid/expired; 403 = binding missing or not authorized; 404 = unknown DataID; 5xx = retryable. Confirm with CESNET. |

Nothing else (no query params, no custom body format) is proposed for the MVP.

---

## 2. CE JWT (Option B — the baseline the MVP ships)

### 2.1 Header

**PINNED** (paper, "Data Request Authentication Schemes", Option B §1):

```json
{
  "typ": "JWT",
  "alg": "Ed25519",
  "jwk": {"crv": "Ed25519", "kty": "OKP", "x": "<b64url(EPK, 32 bytes)>"}
}
```

- `alg` is the **literal string `Ed25519`**, not `EdDSA`. **PINNED as intent**
  (the doc's JWA definition cites "RFC 7518, updated by RFC 9864", which is the
  fully-specified-algorithms update registering `Ed25519`). **Risk:** the
  repository's verifier may only accept `EdDSA` — gap #4, Week-1 experiment #1.
- `jwk` is **optional per the paper**: when absent, the repository identifies
  the CE "through other means (e.g., IP address)". The MVP **always sends it** —
  it removes ambiguity and supports multi-EPK rotation later. Per the paper, its
  role is key *selection*, not trust: the repo must still match it against its
  pre-registered EPK set.
- The JWK is an RFC 8037 OKP structure: exactly the three members
  `crv`/`kty`/`x`, `x` = b64url of the raw 32-byte Ed25519 public key.

### 2.2 Payload

**PINNED** (paper, Option B §2):

```json
{
  "sub": "<JobID>",
  "jpk": "<b64url(JPK, 32 bytes)>"
}
```

- `sub`: the JobID. In the MVP this is a random 128-bit hex string generated
  by the **boundary key service** (never the Galaxy DB job id — it's
  guessable/leaky). Format: 32 lowercase hex chars.
- `jpk`: b64url of the raw 32-byte Ed25519 Job Public Key. **PINNED** by the
  doc ("Base64URL-encoded Job PK"); padding convention **ASSUMED** unpadded,
  JWT-style (gap #3/#5 remainder).

### 2.3 MVP additions (proposed hardening — ASSUMED, gap #8)

```json
{
  "sub": "<JobID>",
  "jpk": "<b64url JPK>",
  "iat": 1756030000,
  "exp": 1756030300,
  "jti": "<uuid4>"
}
```

- `iat` + `exp`: 5-minute window, always set by Galaxy in the MVP. The paper is
  silent on token lifetime; without these a captured token is replayable
  forever.
- `jti`: unique per request, so the repository *can* build a nonce cache.
  Cheap for us, and it makes the replay-protection ask concrete.
- All three are registered JWT claims (RFC 7519) — a paper-compliant
  implementation is free to ignore them; they cannot break a strict verifier.

### 2.4 Signature

**PINNED** (paper, Option B §3):

- Algorithm: Ed25519 over the CE's ESK (libsodium/PyNaCl
  `nacl.signing.SigningKey.sign(...).signature`, 64 bytes).
- Signed input: `b64url(header) + "." + b64url(payload)` (standard JWS compact
  signing input, RFC 7515 §7.1).
- Compact serialization: `header.payload.signature`, all b64url, no padding.

### 2.5 Why hand-rolled serialization (implementation note)

PyJWT (a Galaxy hard dependency) only emits `alg:"EdDSA"`. The spec wants the
literal `Ed25519`. Therefore `lib/galaxy/security/jaice/jwt.py` builds the
three b64url segments and signs with PyNaCl directly (~30 lines). **Issue
only, never verify**: `verify_jwt()` exists for tests only; inbound tokens are
never verified by hand-rolled code anywhere in Galaxy.

---

## 3. Option A — user JWT (DEFERRED from MVP, recorded for completeness)

When Option A ships (post-MVP):

- Header: same shape as §2.1 but the `jwk` carries the **user's** UPK.
- Payload: identical to §2.2 (`sub`, `jpk`) — **note: no DataID**, so
  per-dataset granularity exists only in Option B's portal binding, not in the
  wire format (FINDINGS §1).
- Signed with the user's USK, in the browser (WebCrypto), never server-side.
- Transport: **ASSUMED** second header `X-JAICE-User-JWT` (gap #2).
- The repository matches the `jwk` against its user registry (UPK
  pre-registered, possibly via IAM).

---

## 4. Crypt4GH recipient derivation (the silent-failure hazard)

**PINNED as intent** (paper, "Cryptographic Design Rationale"): one keypair
serves signing and Crypt4GH via the RFC 7748 Montgomery↔Twisted-Edwards
mapping.

**ASSUMED as convention** (gap #3): the repository derives the Crypt4GH
recipient X25519 public key from the presented Ed25519 JPK using libsodium
semantics:

```
x25519_pk = crypto_sign_ed25519_pk_to_curve25519(jpk)
```

PyNaCl equivalent (used by the boundary key service for the JSK side):

```python
from nacl.bindings import (
    crypto_sign_ed25519_sk_to_curve25519,
    crypto_sign_ed25519_pk_to_curve25519,
)
```

A mismatch here is a **silent decryption failure at the compute node**, three
hops removed from the cause. Week-1 experiment #2 exists to lock this
direction against the `crypt4gh` CLI as oracle before any Galaxy code depends
on it.

---

## 5. Request/response summary (MVP, Option B)

```
CE                                                          Repository
──                                                            ──────────
1. GET/POST <download endpoint>                               (PINNED: HTTPS)
   Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJFZDI1NTE5...  (ASSUMED)
   ────────────────────────────────────────────────────────────>
2.                                                             verify:
     - EPK from jwk claim (or other means) is pre-registered   (PINNED)
     - signature verifies over header.payload with EPK         (PINNED)
     - binding exists: DataID ↔ sub (JobID)                    (PINNED)
   <────────────────────────────────────────────────────────────
   200 OK, body = Crypt4GH container re-encrypted for JPK      (PINNED)
   (ASSUMED: exp/iat/jti honored; container hash if gap #6)
```

On the CE side the container is then stored **unopened** (zero-plaintext
invariant) and structurally validated with `lib/galaxy/util/crypt4gh.py`
(`check_crypt4gh`, `read_crypt4gh_header`).

---

## 6. Gap tracker → wire-profile mapping

| Spec gap (PLAN §1 / FINDINGS §1) | Affects wire section | MVP stance |
|---|---|---|
| #1 JSK-signing contradiction | None (JWTs sign with ESK/USK only) | Ship as-is; if CESNET requires a JSK signature, gain a signature field/endpoint — do NOT prebuild |
| #2 JWT transport | §1 header names, §3 dual-token | Propose Bearer + `X-JAICE-User-JWT`; validate in interop |
| #3 Ed25519→X25519 direction | §4 | Week-1 experiment #2 (crypt4gh CLI oracle) |
| #4 `alg:"Ed25519"` literal | §2.1 header | Week-1 experiment #1 (curl to staging) |
| #5 encodings/padding | §2.2, §2.4 | Unpadded b64url throughout |
| #6 container hash | §5 response | Not in MVP; structural checks only |
| #7 binding TTL/cardinality | §1, §5 binding step | MVP: 1 DataID ↔ 1 JobID; ask TTL |
| #8 replay protection | §2.3 | MVP always sets `iat`/`exp`/`jti` |
| #9 endpoint & method | §1 | **Largest open hole** — curl experiment + CESNET confirmation |
| #10 binding state machine | §5 step 2 (portal) | Drives retry UX; not MVP-blocking |

---

## 7. Week-1 validation experiments (from JAICE_MVP.md §6, made concrete)

### Experiment 1 — `alg:"Ed25519"` literal acceptance

```bash
# 1. Generate a throwaway Ed25519 key, print EPK as JWK
python3 scripts/jaice_es_keygen.py --dry-run

# 2. Build a token by hand (or via jaice/jwt.py) and send it
python3 - <<'PY'
from galaxy.security.jaice.jwt import build_ce_jwt
print(build_ce_jwt(esk_hex, job_id="0"*32, jpk_hex, jwk_claim=True))
PY

curl -sS -o /dev/null -w "%{http_code}\n" \
  -H "Authorization: Bearer <ce-jwt>" \
  https://<cesnet-staging>/...  # endpoint per gap #9 outcome
```

Pass: any response other than a JWT-format/`alg`-rejection error (a 403
"not bound" is a *pass* — it means the token parsed and verified).

### Experiment 2 — derivation-direction oracle

```bash
# Encrypt a fixture for the derived X25519 pubkey with the reference CLI
crypt4gh encrypt --recipient_pk <jpk-derived-x25519.pub> < fixture.bin > out.c4gh
# Decrypt with the JSK-derived X25519 secret via PyNaCl in a test
pytest test/unit/security/jaice/test_derivation.py
```

Pass: round-trip succeeds with `crypto_sign_ed25519_*_to_curve25519`
direction; fail means the mapping direction or key form is wrong and must be
flipped in `keys.py` before any other work continues.

### Experiment 3 — endpoint & binding contract

Email/issue to CESNET-Invenio team with this document attached, asking:
endpoint + method (gap #9), binding TTL (gap #7), `iat/exp/jti` acceptance
(gap #8). Until answered, the mock repository implements §5 exactly as
written so integration work isn't blocked.

---

## 8. Mock repository contract

The Phase-4 mock repository (`test/integration` fixture) **implements this
document, not its own interpretation**: Bearer-header JWT, literal
`alg:"Ed25519"` verified with a **stock** JWT library (no special-casing —
this surfaces gap #4 early), OKP `jwk` matching against an EPK registry,
`sub`/`jpk` payload checks, `exp` enforcement, binding table DataID↔JobID,
and re-encryption for the presented JPK with the `crypt4gh` library.
If CESNET corrects any ASSUMED row above, the mock changes to match — the
document and the mock stay in lockstep.
