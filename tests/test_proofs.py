import pytest

from zksafeguard.proofs.scheme import FiatShamirPrototype, ProofArtifact

P = FiatShamirPrototype()
FIELDS = dict(
    commitment="ab" * 32,
    verdict="ALLOW",
    policy_digest="cd" * 32,
    model_digest="ef" * 32,
    nonce="nonce-1",
)


def make_artifact(**overrides):
    return P.generate(**{**FIELDS, **overrides})


def test_honest_artifact_verifies():
    art = make_artifact()
    assert P.verify(art)


def test_tampered_verdict_rejected():
    art = make_artifact()
    tampered = ProofArtifact(**{**art.__dict__, "verdict": "REJECT"})
    assert not P.verify(tampered)


def test_tampered_commitment_rejected():
    art = make_artifact()
    tampered = ProofArtifact(**{**art.__dict__, "commitment": "ff" * 32})
    assert not P.verify(tampered)


def test_tampered_nonce_rejected():
    art = make_artifact()
    tampered = ProofArtifact(**{**art.__dict__, "nonce": "nonce-2"})
    assert not P.verify(tampered)


def test_tampered_challenge_rejected():
    art = make_artifact()
    tampered = ProofArtifact(**{**art.__dict__, "challenge": "00" * 32})
    assert not P.verify(tampered)


def test_modified_context_digests_rejected():
    art = make_artifact()
    tampered = ProofArtifact(**{**art.__dict__, "policy_digest": "11" * 32})
    assert not P.verify(tampered)
    tampered2 = ProofArtifact(**{**art.__dict__, "model_digest": "22" * 32})
    assert not P.verify(tampered2)


def test_json_roundtrip():
    art = make_artifact()
    assert P.verify(ProofArtifact.from_json(art.to_json()))


def test_malformed_handled():
    assert not P.verify(ProofArtifact(
        commitment="x", verdict="BOGUS", policy_digest="y", model_digest="z",
        nonce="n", challenge="c", response="r", backend="fiat_shamir_prototype",
    ))


def test_scope_documentation_is_honest():
    """The prototype is NOT sound: anyone can mint an artifact. The interface
    for a real backend exists and raising is the documented behavior."""
    from zksafeguard.proofs.scheme import ProofBackend

    with pytest.raises(NotImplementedError):
        ProofBackend().generate(commitment="c", verdict="ALLOW",
                                policy_digest="p", model_digest="m", nonce="n")
