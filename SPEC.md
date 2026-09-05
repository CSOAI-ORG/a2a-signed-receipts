# A2A Extension: `signed-receipts/v1` (draft 0.1, 2026-08-19)

**URI:** `https://councilof.ai/a2a/extensions/signed-receipts/v1`
**Status:** draft — for the A2A two-tier extension path (experimental → official)
**Author:** CSOAI Ltd (Council of AI) — independent measurement body, UK 16939677
**License:** Apache-2.0

## 1. Problem

A2A v1.0 §8.4 standardises the *envelope* for AgentCard signing (JWS/RFC 7515 over
RFC 8785 canonical JSON) but **deliberately leaves the trust root unspecified**, and
message-level attestation of *what an agent actually did* is wholly unstandardised.
Two agents can interoperate, but neither can hand a third party durable evidence of
the interaction's outcome.

## 2. What this extension adds

1. **A key-trust convention for §8.4:** the JWS `kid` is a **DID URL**; the DID *method* is
   the issuer's profile choice, not this convention's. `did:web` is the reference profile
   (e.g. `did:web:csoai.org#site-release-1`) because it resolves over plain HTTPS with no new
   registry, but a verifier MUST NOT require it — resolve `kid` → DID document → key and let
   the method vary. Production deployments already run `did:wba`, and `did:webvh` is coming.
   Verifiers resolve the DID document at
   `https://<host>/.well-known/did.json` and match the verification method. No new
   registry, no new PKI — HTTPS + a JSON file the host already controls.
2. **A signed receipt object** an agent MAY attach to any Task completion
   (`Task.metadata["signed-receipts/v1"]`) or return from a dedicated skill:

```json
{
  "schema": "a2a.signed-receipt/0.1",
  "issuer": "did:web:councilof.ai",
  "subject_card": "https://example.org/.well-known/agent-card.json",
  "task_id": "…",
  "claims": [{ "type": "measurement", "detail": "…", "evidence_sha256": "…" }],
  "issued_at": "2026-08-19T09:00:00Z",
  "content_id": "sha256 of canonical JSON minus signature",
  "signature": { "alg": "Ed25519", "kid": "did:web:councilof.ai#…", "sig": "hex" }
}
```

   Canonicalisation: RFC 8785 (same as §8.4). Verification is offline: recompute
   `content_id`, **read `signature.alg`**, resolve `kid` → DID doc → public key, then check the
   signature *with the algorithm the receipt declares*.

   **`alg` is normative, not decorative.** A verifier MUST read it before selecting a
   verification routine, and MUST report an algorithm it does not implement as **UNCHECKABLE**,
   naming the algorithm — never as INVALID. A receipt in an algorithm you cannot check may be
   perfectly valid; saying otherwise is an untrue statement about someone else's evidence.
   `Ed25519` is the reference algorithm. Additional values are additive and require no schema
   change: [a2aproject/A2A#2150](https://github.com/a2aproject/A2A/issues/2150) proposes
   `ML-DSA-65` (NIST FIPS 204) over this exact wire shape, with `sig`/`signer_public_key` in
   base64 rather than hex — at 3309- and 1952-byte values hex's 100% overhead stops being free.
   Encoding is a per-algorithm profile choice; hex remains correct for Ed25519.

3. **Register (normative):** a receipt is evidence of *what was claimed and when* by
   the issuer — it is **not** a certification, endorsement, or conformity mark, and
   MUST NOT be presented as one.

## 3. AgentCard declaration

```json
{ "capabilities": { "extensions": [ {
  "uri": "https://councilof.ai/a2a/extensions/signed-receipts/v1",
  "required": false,
  "params": { "issuer": "did:web:councilof.ai" }
} ] } }
```

## 4. Reference implementation

`interceptor.py` — an ADK-style client/server interceptor (~100 lines) that attaches a
signed receipt to task completion and verifies inbound ones. Framework-agnostic core;
only `cryptography` required.

## 5. Security considerations

- did:web inherits HTTPS/DNS trust — rotation via DID doc updates; old kids stay
  resolvable with `"revoked": true` markers rather than deletion (append-only).
- Receipts embed the public key AND the kid: offline integrity always verifiable;
  identity verifiable whenever the DID doc is reachable (cache it).
- Never sign secrets or raw user content — claims carry hashes, not payloads.

## 6. Relationship to prior art

Sigstore signs artifacts, not evals; SPIFFE binds workloads, not measurements; §8.4
signs *cards*, not *outcomes*. This extension completes the third leg: signed
evidence of agent behaviour, portable across all three.
