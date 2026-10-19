import pytest

from zksafeguard.crypto.commitments import digest_bytes, open_commitment, sha256_commitment
from zksafeguard.fhe.ckks_scorer import (
    CKKSRiskScorer,
    deterministic_weights,
    extract_features,
    sigmoid,
)


def test_extract_features_normalized_and_hashed():
    f = extract_features("hello world", dim=64)
    assert len(f) == 64
    assert abs(sum(f[i] ** 2 for i in range(64)) - 1.0) < 1e-9
    f2 = extract_features("hello world", dim=64)
    assert f == f2
    assert extract_features("", dim=64) == [0.0] * 64


def test_weights_deterministic():
    w1 = deterministic_weights(32, seed=7)
    w2 = deterministic_weights(32, seed=7)
    assert w1 == w2
    assert deterministic_weights(32, seed=8) != w1


@pytest.mark.parametrize("poly", [4096])
def test_ckks_matches_plaintext(poly):
    scorer = CKKSRiskScorer(poly_modulus_degree=poly, feature_dim=32, model_seed=42)
    feats = extract_features("please summarize this short document for me", dim=32)
    enc = scorer.encrypt_features(feats)
    enc_risk = scorer.encrypted_risk(enc)
    got = sigmoid(scorer.decrypt_risk(enc_risk))
    expected = sigmoid(scorer.plaintext_risk(feats))
    assert abs(got - expected) < 0.05


def test_ciphertext_serialization_roundtrip():
    scorer = CKKSRiskScorer(poly_modulus_degree=4096, feature_dim=16, model_seed=1)
    feats = extract_features("some prompt text", dim=16)
    enc = scorer.encrypt_features(feats)
    loaded = scorer.load_ciphertext(enc.serial())
    val_loaded = scorer.decrypt_risk(scorer.encrypted_risk(loaded))
    val_direct = scorer.decrypt_risk(scorer.encrypted_risk(enc))
    assert abs(val_loaded - val_direct) < 1e-6


def test_public_context_has_no_secret():
    scorer = CKKSRiskScorer(poly_modulus_degree=4096, feature_dim=16, model_seed=1)
    import tenseal as ts

    pub = ts.context_from(scorer.public_context_serial())
    feats = extract_features("secret prompt words", dim=16)
    enc = ts.ckks_vector(pub, feats)
    with pytest.raises(Exception):
        enc.decrypt()


def test_weights_digest_stable():
    s1 = CKKSRiskScorer(poly_modulus_degree=4096, feature_dim=16, model_seed=5)
    s2 = CKKSRiskScorer(poly_modulus_degree=4096, feature_dim=16, model_seed=5)
    assert s1.weights_digest == s2.weights_digest


def test_commitment_binding_and_opening():
    c1, salt1 = sha256_commitment(b"prompt A")
    c2, salt2 = sha256_commitment(b"prompt A")
    assert c1 != c2
    c3, salt3 = sha256_commitment(b"prompt B", salt1)
    assert c3 != c1
    assert open_commitment(b"prompt A", salt1, c1)
    assert not open_commitment(b"prompt X", salt1, c1)
    assert digest_bytes(b"a") == digest_bytes(b"a")
