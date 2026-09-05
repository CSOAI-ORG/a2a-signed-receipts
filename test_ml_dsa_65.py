"""ML-DSA-65 (FIPS 204) as an additive `signature.alg`, over the exact wire shape and signing
procedure `interceptor.py` already uses for Ed25519 — the option a2aproject/A2A#2150 proposed.

Uses the optional `pqcrypto` package (PQClean's ML-DSA-65). Golden-vector methodology matches
the three cases published in `@fractalai/pqc-agent-receipts-conformance` (npm, Apache-2.0), the
open conformance package these vectors also ship in: genuine (verifies), tampered (a field
changed post-signing without recomputing content_id — caught before the signature check even
runs), forged (a different keypair signs a self-consistent receipt claiming the same issuer —
the signature verifies over its own bytes, but is correctly rejected because the key is not the
one the DID document publishes). Skipped automatically if `pqcrypto` is not installed.
"""

from __future__ import annotations

import copy

import pytest

pqcrypto_ml_dsa_65 = pytest.importorskip("pqcrypto.sign.ml_dsa_65")

from interceptor import SUPPORTED_ALGS, issue_receipt_ml_dsa_65, verify_receipt  # noqa: E402


def _receipt(kid="did:web:example.org#k1", issuer="did:web:example.org"):
    pub, sec = pqcrypto_ml_dsa_65.generate_keypair()
    r = issue_receipt_ml_dsa_65(
        sec,
        pub,
        kid,
        issuer,
        task_id="t1",
        subject_card="https://example.org/.well-known/agent-card.json",
        claims=[{"type": "measurement", "detail": "d", "evidence_sha256": "0" * 64}],
    )
    return r, pub, sec


def _doc_for(receipt):
    return {"verificationMethod": [{"publicKeyHex": receipt["signature"]["signer_public_key"]}]}


def test_ml_dsa_65_is_now_implemented():
    assert "ML-DSA-65" in SUPPORTED_ALGS


def test_genuine_ml_dsa_65_receipt_verifies_end_to_end():
    r, _pub, _sec = _receipt()
    assert r["signature"]["alg"] == "ML-DSA-65"
    ok, reason = verify_receipt(r, resolve_did=lambda d: _doc_for(r))
    assert ok is True, reason


def test_tampered_ml_dsa_65_receipt_is_caught_by_content_id_before_the_signature_check():
    r, _pub, _sec = _receipt()
    tampered = copy.deepcopy(r)
    tampered["task_id"] = "t2"  # changed after signing; content_id was never recomputed
    ok, reason = verify_receipt(tampered, resolve_did=lambda d: _doc_for(r))
    assert ok is False
    assert reason == "content_id mismatch"


def test_forged_ml_dsa_65_receipt_verifies_its_own_bytes_but_is_rejected_on_key_trust():
    genuine, _pub, _sec = _receipt()
    attacker_pub, attacker_sec = pqcrypto_ml_dsa_65.generate_keypair()
    forged = issue_receipt_ml_dsa_65(
        attacker_sec,
        attacker_pub,
        genuine["signature"]["kid"],  # same claimed issuer/kid as the genuine receipt
        genuine["issuer"],
        task_id=genuine["task_id"],
        subject_card=genuine["subject_card"],
        claims=genuine["claims"],
    )
    # The forged receipt is internally self-consistent — content_id and signature both check out
    # against the ATTACKER's own embedded key. Only the DID document (publishing the GENUINE key)
    # can catch this.
    ok_self_check, reason_self_check = verify_receipt(forged, resolve_did=lambda d: _doc_for(forged))
    assert ok_self_check is True, reason_self_check  # signature-over-bytes alone proves nothing about authorship

    ok, reason = verify_receipt(forged, resolve_did=lambda d: _doc_for(genuine))
    assert ok is False
    assert "NOT in DID doc" in reason


def test_a_forged_ml_dsa_65_signature_is_invalid_not_a_false_accept():
    # The one case none of the tests above actually exercise: a mismatched (key, signature) pair
    # under an otherwise well-formed ML-DSA-65 envelope. Unlike the "forged" test above, the
    # embedded signer_public_key here is the GENUINE key — only `sig` is replaced with a different
    # keypair's signature over the same bytes. If `_verify_ml_dsa_65` were disabled or replaced
    # with a stub that always returns True, this is the test that would catch it: every other
    # ML-DSA-65 test here either short-circuits on content_id (tampered) or is satisfied by the
    # DID-trust check alone (forged, whose own signature genuinely verifies against its own key).
    genuine, pub, _sec = _receipt()
    attacker_pub, attacker_sec = pqcrypto_ml_dsa_65.generate_keypair()
    body = {k: v for k, v in genuine.items() if k != "signature"}
    from interceptor import _canon

    forged_sig = pqcrypto_ml_dsa_65.sign(attacker_sec, _canon(body))
    tampered = copy.deepcopy(genuine)
    tampered["signature"]["sig"] = __import__("base64").b64encode(forged_sig).decode("ascii")
    assert tampered["signature"]["signer_public_key"] == genuine["signature"]["signer_public_key"]
    ok, reason = verify_receipt(tampered, resolve_did=lambda d: _doc_for(genuine))
    assert ok is False
    assert "INVALID" in reason
    assert "does not verify" in reason


def test_ml_dsa_65_uses_the_same_canonicalisation_as_ed25519():
    # Build an Ed25519 receipt and an ML-DSA-65 receipt from IDENTICAL fields and confirm the
    # body-minus-signature bytes actually signed are byte-for-byte the same regardless of alg —
    # i.e. this is genuinely the same wire shape and signing procedure, not a lookalike schema
    # that happens to share field names. A real regression here (e.g. ML-DSA-65 quietly using a
    # different canonicalisation) would NOT be caught by any test above, since none of them compare
    # across algorithms.
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from interceptor import issue_receipt

    fixed_fields = dict(
        issuer_did="did:web:example.org",
        task_id="t1",
        subject_card="https://example.org/.well-known/agent-card.json",
        claims=[{"type": "measurement", "detail": "d", "evidence_sha256": "0" * 64}],
    )
    ed = issue_receipt(Ed25519PrivateKey.generate(), "did:web:example.org#k1", **fixed_fields)
    pub, sec = pqcrypto_ml_dsa_65.generate_keypair()
    ml = issue_receipt_ml_dsa_65(sec, pub, "did:web:example.org#k1", **fixed_fields)

    # issued_at is a real-time timestamp (time.strftime, second granularity) — not asserted equal
    # or unequal, since two receipts issued in the same wall-clock second legitimately share it.
    # Every OTHER field, including content_id (itself derived from the canonical body), must match
    # exactly: that's the actual proof the two algorithms canonicalise and sign identically.
    ed_body = {k: v for k, v in ed.items() if k not in ("signature", "issued_at")}
    ml_body = {k: v for k, v in ml.items() if k not in ("signature", "issued_at")}
    assert ed_body == ml_body
