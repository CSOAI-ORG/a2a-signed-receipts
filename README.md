# `signed-receipts/v1` — an A2A extension

A key-trust convention for [A2A](https://github.com/a2aproject/A2A) §8.4 AgentCard signing,
plus a signed receipt object that carries durable evidence of **what an agent actually did**.

- **Extension URI:** `https://councilof.ai/a2a/extensions/signed-receipts/v1`
- **Status:** draft 0.1 — for the A2A two-tier extension path (experimental → official)
- **Discussion:** [a2aproject/A2A#2150](https://github.com/a2aproject/A2A/issues/2150)
- **Spec:** [SPEC.md](./SPEC.md) · **Reference implementation:** [interceptor.py](./interceptor.py)
- **Licence:** Apache-2.0

## The gap it closes

A2A v1.0 §8.4 standardises the *envelope* for AgentCard signing (JWS over RFC 8785 canonical
JSON) but deliberately leaves the **trust root unspecified**. Separately, attestation of a
task's *outcome* is unstandardised. Two agents can interoperate and still be unable to hand a
third party durable evidence of what passed between them.

Sigstore signs artifacts, not evaluations. SPIFFE binds workloads, not measurements. §8.4 signs
*cards*, not *outcomes*. This extension is the third leg.

## What it adds

1. **A `did:web` key-trust convention for §8.4.** The JWS `kid` is a DID URL; verifiers resolve
   `https://<host>/.well-known/did.json` and match the verification method. No new registry and
   no new PKI — HTTPS plus a JSON file the host already controls.
2. **A signed receipt object**, attachable to any Task completion under
   `Task.metadata["signed-receipts/v1"]`. Verification is offline: recompute `content_id`,
   resolve `kid` → DID document → public key, check the signature.

## What a receipt is — and is not

> A receipt is evidence of **what was claimed, and when, by the issuer**. It is **not** a
> certification, an endorsement, or a conformity mark, and MUST NOT be presented as one.

That sentence is normative in the spec, not marketing copy. It is the reason this extension is
safe to adopt: it adds an evidence channel without creating an authority.

## What verifying a signature does not establish

Verifying establishes that the named key produced these bytes and that the bytes have not
changed. It says nothing about the state of that key **now**. Offline verification is a
computation over the parameters you hold; revocation is a property of the present. A consumer
MUST NOT treat a signature that verifies as evidence that the signing key is still valid. Where
a decision depends on revocation state, the key-resolution path and the staleness you accept
are operational parameters of your deployment and must be stated by it; the receipt does not
carry them.

(Stated after the IETF `agentproto` thread of 31 Aug – 2 Sep 2026. The same limitation is
recorded against our own published verification rule as correction
[C-2026-0902-09](https://councilof.ai/api/corrections).)

## Related, running code

- Offline card verifier, Apache-2.0, zero dependencies, three states rather than two —
  [`gspc-verify.mjs`](https://councilof.ai/verifier/gspc-verify.mjs)
- Our published verification rule —
  [HOW-TO-VERIFY.md](https://councilof.ai/signed/HOW-TO-VERIFY.md)

## Who maintains this

CSOAI Ltd (Council of AI), an independent AI-governance measurement body — UK company 16939677.
We measure; we do not certify.

Archived in Software Heritage: `swh:1:snp:99cd0f55ae22e41bc805d56e525d816a8972d82f`
