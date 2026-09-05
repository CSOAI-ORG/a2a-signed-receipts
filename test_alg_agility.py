"""signature.alg is read before a key is touched, and the DID method is not ours to fix.

Both defects came out of a2aproject/A2A#2150 and both let the verifier make untrue statements
about other people's receipts:

  · verify_receipt() never read signature.alg. It went straight to Ed25519, so a receipt
    declaring ML-DSA-65 (FIPS 204) was checked with the wrong algorithm and reported as a bad
    signature. The field was decorative, which is exactly why algorithm agility was impossible
    without forking the schema.

  · the spec pinned kid to did:web. A production deployment on did:wba carries a perfectly
    resolvable DID URL, and hard-coding one method makes the format the trust root's owner.
"""

from __future__ import annotations

import copy

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from interceptor import SUPPORTED_ALGS, issue_receipt, verify_receipt


def _receipt(kid="did:web:example.org#k1", issuer="did:web:example.org"):
    key = Ed25519PrivateKey.generate()
    r = issue_receipt(
        key,
        kid,
        issuer,
        task_id="t1",
        subject_card="https://example.org/.well-known/agent-card.json",
        claims=[{"type": "measurement", "detail": "d", "evidence_sha256": "0" * 64}],
    )
    return r, key


def _doc_for(receipt):
    return {"verificationMethod": [{"publicKeyHex": receipt["signature"]["signer_public_key"]}]}


def test_a_declared_algorithm_we_do_not_implement_is_uncheckable_not_invalid():
    r, _ = _receipt()
    # Falcon-512 (NIST round-4 alternate), not ML-DSA-65: this repo now implements ML-DSA-65 (see
    # test_ml_dsa_65.py), so it can no longer stand in as "an algorithm we don't implement".
    r["signature"]["alg"] = "Falcon-512"
    ok, reason = verify_receipt(r, resolve_did=lambda d: _doc_for(r))
    assert ok is False
    assert "UNCHECKABLE" in reason
    assert "Falcon-512" in reason, "the algorithm must be named so the caller knows what is missing"
    assert "INVALID" not in reason


def test_a_missing_alg_is_refused_rather_than_guessed():
    r, _ = _receipt()
    del r["signature"]["alg"]
    ok, reason = verify_receipt(r, resolve_did=lambda d: _doc_for(r))
    assert ok is False and "UNCHECKABLE" in reason


def test_alg_is_read_before_the_key_is_touched():
    # A junk public key must still produce the UNCHECKABLE-alg answer, proving the alg branch
    # runs first rather than the verifier failing on cryptography for the wrong reason.
    r, _ = _receipt()
    r["signature"]["alg"] = "Dilithium-Nonsense"
    r["signature"]["signer_public_key"] = "zz"
    ok, reason = verify_receipt(r, resolve_did=lambda d: {"verificationMethod": []})
    assert "UNCHECKABLE" in reason and "Dilithium-Nonsense" in reason


def test_ed25519_still_verifies_end_to_end():
    r, _ = _receipt()
    assert r["signature"]["alg"] == "Ed25519"
    ok, reason = verify_receipt(r, resolve_did=lambda d: _doc_for(r))
    assert ok is True, reason


def test_a_non_did_web_method_resolves_normally():
    # did:wba is a real, HTTP-resolvable W3C DID method in production use. Nothing in the
    # verifier may require the did:web prefix.
    r, _ = _receipt(kid="did:wba:example.org:agent#k1", issuer="did:wba:example.org:agent")
    seen: list[str] = []

    def resolve(did):
        seen.append(did)
        return _doc_for(r)

    ok, reason = verify_receipt(r, resolve_did=resolve)
    assert ok is True, reason
    assert seen == ["did:wba:example.org:agent"]


def test_a_kid_that_is_not_a_did_url_is_uncheckable():
    r, _ = _receipt(kid="https://example.org/keys/1")
    ok, reason = verify_receipt(r, resolve_did=lambda d: _doc_for(r))
    assert ok is False and "UNCHECKABLE" in reason


def test_the_supported_set_is_this_verifier_not_the_format():
    assert "Ed25519" in SUPPORTED_ALGS
    assert "ML-DSA-65" in SUPPORTED_ALGS  # additive, see test_ml_dsa_65.py — needs pqcrypto to run
    assert "Falcon-512" not in SUPPORTED_ALGS  # honest: still not implemented


def test_a_forged_ed25519_signature_is_invalid_not_a_crash():
    # None of the tests above sign the body with one key and re-embed a DIFFERENT key's signature
    # — the one shape that makes `cryptography`'s Ed25519 verify() actually raise InvalidSignature
    # instead of short-circuiting earlier (content_id mismatch, alg mismatch, bad hex). That
    # exception class was referenced in verify_receipt()'s except clause but never imported, so
    # this exact case raised NameError: name 'InvalidSignature' is not defined instead of
    # returning (False, "INVALID ...") — a forged receipt crashed the verifier rather than being
    # rejected. Confirmed against this file before the fix; this pins it down permanently.
    genuine, _key = _receipt()
    attacker_key = Ed25519PrivateKey.generate()
    forged = copy.deepcopy(genuine)
    body = {k: v for k, v in genuine.items() if k != "signature"}
    from interceptor import _canon

    forged["signature"]["sig"] = attacker_key.sign(_canon(body)).hex()
    ok, reason = verify_receipt(forged, resolve_did=lambda d: _doc_for(genuine))
    assert ok is False
    assert "INVALID" in reason
    assert "does not verify" in reason
