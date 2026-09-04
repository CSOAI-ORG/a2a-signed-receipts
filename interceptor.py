"""signed-receipts/v1 — reference interceptor (framework-agnostic core).

Attach: receipt = issue_receipt(signer, task_id, subject_card, claims)
        task.metadata["signed-receipts/v1"] = receipt
Verify: ok, reason = verify_receipt(receipt, resolve_did=fetch_did_document)

Only dependency: cryptography. Canonicalisation: RFC 8785-compatible
(sorted keys, no whitespace, UTF-8) for the flat structures used here.
Register: a receipt is evidence of what was claimed and when — never a
certification, endorsement, or conformity mark.
"""

from __future__ import annotations

import hashlib
import json
import time
from typing import Any, Callable

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


def issue_receipt(
    key: Ed25519PrivateKey,
    kid: str,
    issuer_did: str,
    task_id: str,
    subject_card: str,
    claims: list[dict],
) -> dict:
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
    sig = key.sign(_canon(payload))
    pub = key.public_key().public_bytes_raw().hex()
    return {**payload, "signature": {"alg": "Ed25519", "kid": kid, "signer_public_key": pub, "sig": sig.hex()}}


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
        pub_hex = env["signer_public_key"]
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex)).verify(
            bytes.fromhex(env["sig"]), _canon(body)
        )
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
        did = env.get("kid", "").split("#")[0]
        doc = resolve_did(did)
        published = {
            vm.get("publicKeyHex") or vm.get("publicKeyMultibase") or json.dumps(vm.get("publicKeyJwk", {}))
            for vm in doc.get("verificationMethod", [])
        }
        if any(pub_hex in p for p in published if p):
            return True, f"VALID — key matches published DID doc for {did}"
        return False, f"signature valid but key NOT in DID doc for {did}"
    except InvalidSignature:
        # A finding about the bytes: the signature does not verify over them.
        return False, "INVALID — signature does not verify over these bytes"
    except Exception as e:  # noqa: BLE001
        # Anything else — a malformed field, an unreachable DID document, a bad hex string — is a
        # failure to complete the check, not evidence that the receipt is forged. Reporting a DNS
        # timeout as a forgery is the error this extension exists to help others avoid.
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
