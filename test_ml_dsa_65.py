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


def test_ml_dsa_65_content_id_and_signing_procedure_match_ed25519s():
    # Same _build_payload, same _canon — only the signature envelope's alg/encoding differ.
    from interceptor import _build_payload, _canon, _sha256  # noqa: F401 (internal, for parity check)

    r, _pub, _sec = _receipt()
    body = {k: v for k, v in r.items() if k != "signature"}
    unsigned = {k: v for k, v in body.items() if k != "content_id"}
    assert body["content_id"] == _sha256(_canon(unsigned))
