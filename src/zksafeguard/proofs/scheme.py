"""Proof-of-decision abstraction + prototype backend.

HONEST SCOPE (see README "What is cryptographically real"): the prototype
backend produces a *transcript-binding artifact*, not a zk-SNARK. It binds the
public decision fields together (commitment, verdict, digests, nonce) via a
challenge hash. Verification recomputes the challenge from the public fields:

  challenge = SHA256(commitment || verdict || policy_digest || model_digest || nonce)
  response  = SHA256(challenge || commitment)

Because everything is public, ANY party can construct a valid artifact for any
verdict it likes. The artifact therefore provides integrity/tamper-evidence for
a recorded decision transcript — it does NOT prove soundness, and it is NOT
zero-knowledge. A real ZK backend (e.g. a zkVM/SNARK circuit over the policy
evaluation) implements the same ProofBackend interface; that is the migration
path and it is deliberately left as an interface, not faked here.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass


@dataclass
class ProofArtifact:
    commitment: str
    verdict: str
    policy_digest: str
    model_digest: str
    nonce: str
    challenge: str
    response: str
    backend: str

    def to_json(self) -> str:
        return json.dumps(asdict(self), sort_keys=True)

    @classmethod
    def from_json(cls, raw: str) -> "ProofArtifact":
        d = json.loads(raw)
        return cls(**d)


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class FiatShamirPrototype:
    """Prototype ProofBackend: hash-transcript binding (see module docstring)."""

    name = "fiat_shamir_prototype"

    def generate(self, commitment: str, verdict: str, policy_digest: str,
                 model_digest: str, nonce: str) -> ProofArtifact:
        if verdict not in ("ALLOW", "REJECT"):
            raise ValueError("verdict must be ALLOW or REJECT")
        challenge = _sha(
            b"|".join([commitment.encode(), verdict.encode(), policy_digest.encode(),
                       model_digest.encode(), nonce.encode()])
        )
        response = _sha(challenge.encode() + b"|" + commitment.encode())
        return ProofArtifact(
            commitment=commitment, verdict=verdict, policy_digest=policy_digest,
            model_digest=model_digest, nonce=nonce, challenge=challenge,
            response=response, backend=self.name,
        )

    def verify(self, artifact: ProofArtifact) -> bool:
        try:
            if artifact.backend != self.name:
                return False
            if artifact.verdict not in ("ALLOW", "REJECT"):
                return False
            challenge = _sha(
                b"|".join([artifact.commitment.encode(), artifact.verdict.encode(),
                           artifact.policy_digest.encode(), artifact.model_digest.encode(),
                           artifact.nonce.encode()])
            )
            response = _sha(challenge.encode() + b"|" + artifact.commitment.encode())
            return hashlib.compare_digest(challenge, artifact.challenge) and \
                hashlib.compare_digest(response, artifact.response)
        except Exception:
            return False


class ProofBackend:
    """Interface for future real SNARK backends."""

    name = "interface"

    def generate(self, *args, **kwargs) -> ProofArtifact:
        raise NotImplementedError(
            "No production ZK backend is configured. The prototype backend "
            "(FiatShamirPrototype) is a transcript-binding demo, not a SNARK. "
            "Implement ProofBackend with a real proving system to get soundness."
        )

    def verify(self, *args, **kwargs) -> bool:
        raise NotImplementedError
