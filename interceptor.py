"""signed-receipts/v1 — reference interceptor (framework-agnostic core).

Attach: receipt = issue_receipt(signer, task_id, subject_card, claims)
        task.metadata["signed-receipts/v1"] = receipt
Verify: ok, reason = verify_receipt(receipt, resolve_did=fetch_did_document)

Required dependency: cryptography (Ed25519). Optional: pqcrypto, only if you
verify or issue ML-DSA-65 receipts (`pip install pqcrypto`) — the reference
algorithm never needs it. Canonicalisation: RFC 8785-compatible (sorted keys,
no whitespace, UTF-8) for the flat structures used here.
Register: a receipt is evidence of what was claimed and when — never a
certification, endorsement, or conformity mark.
"""

from __future__ import annotations

import base64
import hashlib
import json
import time
from typing import Any, Callable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

SCHEMA = "a2a.signed-receipt/0.1"
EXT_URI = "https://councilof.ai/a2a/extensions/signed-receipts/v1"
REGISTER = (
    "Evidence of what was claimed and when by the issuer. Not a certification, "
    "endorsement, or conformity mark."
)


def _canon(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _build_payload(issuer_did: str, task_id: str, subject_card: str, claims: list[dict]) -> dict:
    payload = {
        "schema": SCHEMA,
        "issuer": issuer_did,
        "subject_card": subject_card,
        "task_id": task_id,
        "claims": claims,
        "register": REGISTER,
        "issued_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    payload["content_id"] = _sha256(_canon({k: v for k, v in payload.items() if k != "content_id"}))
    return payload


def issue_receipt(
    key: Ed25519PrivateKey,
    kid: str,
    issuer_did: str,
    task_id: str,
    subject_card: str,
    claims: list[dict],
) -> dict:
    payload = _build_payload(issuer_did, task_id, subject_card, claims)
    sig = key.sign(_canon(payload))
    pub = key.public_key().public_bytes_raw().hex()
    return {**payload, "signature": {"alg": "Ed25519", "kid": kid, "signer_public_key": pub, "sig": sig.hex()}}


def issue_receipt_ml_dsa_65(
    secret_key: bytes,
    public_key: bytes,
    kid: str,
    issuer_did: str,
    task_id: str,
    subject_card: str,
    claims: list[dict],
) -> dict:
    """Same wire shape and signing procedure as `issue_receipt`, ML-DSA-65 (FIPS 204) instead of
    Ed25519 — the additive algorithm option a2aproject/A2A#2150 proposed. `sig`/`signer_public_key`
    are base64 rather than hex: at 3309-byte signatures and 1952-byte keys, hex's 100% overhead
    stops being free. Requires the optional `pqcrypto` package.
    """
    try:
        from pqcrypto.sign.ml_dsa_65 import sign as _sign
    except ImportError as exc:
        raise RuntimeError(
            "issue_receipt_ml_dsa_65 needs the optional 'pqcrypto' package: pip install pqcrypto"
        ) from exc
    payload = _build_payload(issuer_did, task_id, subject_card, claims)
    sig = _sign(secret_key, _canon(payload))
    pub_b64 = base64.b64encode(public_key).decode("ascii")
    return {
        **payload,
        "signature": {
            "alg": "ML-DSA-65",
            "kid": kid,
            "signer_public_key": pub_b64,
            "sig": base64.b64encode(sig).decode("ascii"),
        },
    }


def _verify_ed25519(pub: bytes, msg: bytes, sig: bytes) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(pub).verify(sig, msg)
        return True
    except InvalidSignature:
        return False


def _verify_ml_dsa_65(pub: bytes, msg: bytes, sig: bytes) -> bool:
    try:
        from pqcrypto.sign.ml_dsa_65 import verify as _verify
    except ImportError as exc:
        raise RuntimeError(
            "ML-DSA-65 verification needs the optional 'pqcrypto' package: pip install pqcrypto"
        ) from exc
    # pqcrypto's verify() returns a bool (unlike cryptography's, which raises); normalise here so
    # verify_receipt can treat every algorithm's verifier the same way.
    return bool(_verify(pub, msg, sig))


# Per-algorithm (decode, verify) pair. `decode` turns the wire string into raw bytes; `verify`
# takes (public_key_bytes, message_bytes, signature_bytes) and returns True/False — it must never
# raise for a merely-invalid signature (only for a malformed input, which the outer except turns
# into UNCHECKABLE, not INVALID).
_ALGS: dict[str, tuple[Callable[[str], bytes], Callable[[bytes, bytes, bytes], bool]]] = {
    "Ed25519": (bytes.fromhex, _verify_ed25519),
    # NIST FIPS 204. Additive per a2aproject/A2A#2150 — same wire shape, same signing procedure,
    # base64 encoding. Optional dependency: only touched when a receipt actually declares this alg.
    "ML-DSA-65": (lambda s: base64.b64decode(s, validate=True), _verify_ml_dsa_65),
}

# Algorithms THIS verifier implements. Not the set the format permits — a2a.signed-receipt/0.1
# carries `alg` precisely so other algorithms can be added without forking the schema. Anything
# not listed here verifies as UNCHECKABLE with the algorithm named, never as INVALID.
SUPPORTED_ALGS = frozenset(_ALGS)


def verify_receipt(
    receipt: dict,
    resolve_did: Callable[[str], dict] | None = None,
) -> tuple[bool, str]:
    """Offline integrity always; identity too when resolve_did is provided.

    resolve_did(did) -> DID document dict (e.g. fetched from
    https://<host>/.well-known/did.json). Never raises.
    """
    try:
        env = receipt["signature"]
        if not isinstance(env, dict):
            return False, "UNCHECKABLE — no signature envelope; nothing to check"
        body = {k: v for k, v in receipt.items() if k != "signature"}
        unsigned = {k: v for k, v in body.items() if k != "content_id"}
        if body.get("content_id") != _sha256(_canon(unsigned)):
            return False, "content_id mismatch"
        # THE DECLARED ALGORITHM IS READ BEFORE ANY KEY IS TOUCHED.
        #
        # This block used to go straight to Ed25519 without ever reading signature.alg. The
        # field was therefore decorative: a receipt declaring "ML-DSA-65" was silently checked
        # as Ed25519 and reported as a bad signature, which is an untrue statement about
        # someone else's valid receipt. It also made algorithm agility impossible without
        # forking the schema, which is what a2aproject/A2A#2150 asked for.
        #
        # An algorithm we do not implement is UNCHECKABLE, named, and never INVALID. We do not
        # own the set of algorithms; we own only what this verifier can actually check.
        alg = env.get("alg")
        if alg is None:
            return False, "UNCHECKABLE — signature declares no alg; refusing to guess one"
        if alg not in SUPPORTED_ALGS:
            return False, (
                f"UNCHECKABLE — signature.alg {alg!r} is not implemented by this verifier "
                f"(implemented: {', '.join(sorted(SUPPORTED_ALGS))}). The receipt may be "
                "perfectly valid; this verifier cannot say either way."
            )
        decode, verify_fn = _ALGS[alg]
        pub_str = env["signer_public_key"]
        try:
            pub_bytes = decode(pub_str)
            sig_bytes = decode(env["sig"])
        except (ValueError, TypeError) as exc:
            return False, f"UNCHECKABLE — signer_public_key/sig is not valid for {alg}: {exc}"
        if not verify_fn(pub_bytes, _canon(body), sig_bytes):
            return False, "INVALID — signature does not verify over these bytes"
        if resolve_did is None:
            # The signature above was checked against signer_public_key — the key THIS RECEIPT
            # carries. That proves the bytes are internally consistent and nothing about who
            # signed them: anyone can mint a receipt with a key they generated. Returning True
            # here let a self-signed receipt pass as VALID, which is the whole property the
            # did:web trust root exists to provide. Integrity without identity is UNCHECKABLE.
            return False, (
                f"UNCHECKABLE — integrity holds against the embedded key, but kid "
                f"{env.get('kid')!r} was not resolved. Pass resolve_did= to establish identity; "
                "a self-embedded key never establishes it."
            )
        # METHOD-AGNOSTIC. The kid is a DID URL; which DID method it names is the issuer's
        # profile choice, not this format's. a2aproject/A2A#2150 raised this from production
        # experience running did:wba. We resolve kid -> DID document -> key and never require
        # the string to start with did:web:.
        did = env.get("kid", "").split("#")[0]
        if not did.startswith("did:"):
            return False, (
                f"UNCHECKABLE — kid {env.get('kid')!r} is not a DID URL, so there is no "
                "document to resolve"
            )
        doc = resolve_did(did)
        published = {
            vm.get("publicKeyHex") or vm.get("publicKeyMultibase") or json.dumps(vm.get("publicKeyJwk", {}))
            for vm in doc.get("verificationMethod", [])
        }
        if any(pub_str in p for p in published if p):
            return True, f"VALID — key matches published DID doc for {did}"
        return False, f"signature valid but key NOT in DID doc for {did}"
    except Exception as e:  # noqa: BLE001
        # Anything else — a malformed field, an unreachable DID document, a missing optional
        # dependency — is a failure to complete the check, not evidence that the receipt is
        # forged. Reporting a DNS timeout (or an uninstalled verifier) as a forgery is the error
        # this extension exists to help others avoid.
        return False, f"UNCHECKABLE — {type(e).__name__}: {e}"


if __name__ == "__main__":
    key = Ed25519PrivateKey.generate()
    r = issue_receipt(
        key,
        "did:web:councilof.ai#eval-test",
        "did:web:councilof.ai",
        "task-1",
        "https://example.org/.well-known/agent-card.json",
        [{"type": "measurement", "detail": "demo", "evidence_sha256": "ab" * 32}],
    )
    print("roundtrip:", verify_receipt(r))
    r2 = json.loads(json.dumps(r))
    r2["task_id"] = "task-2"
    print("tamper:   ", verify_receipt(r2))
