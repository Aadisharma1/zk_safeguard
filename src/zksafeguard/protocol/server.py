"""FastAPI server: receives ONLY encrypted features + commitments/proofs.

Privacy property (intentional, documented): the server never receives the
prompt or the plaintext feature vector — only the serialized CKKS ciphertext.
The server DOES see the decrypted scalar risk score and the verdict, because
the central service must enforce the policy decision. This is the privacy
boundary of this PoC; it is stated explicitly rather than overstated.

Replay protection has two layers: a freshness window on the client timestamp
(created_at) and server-side nonce single-use tracking. Both are documented in
docs/THREAT_MODEL.md along with what they do NOT defend against.
"""

from __future__ import annotations

import base64
import logging
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from zksafeguard.fhe.ckks_scorer import CKKSRiskScorer, sigmoid
from zksafeguard.policy.engine import PolicyEngine, PolicyVerdict
from zksafeguard.proofs.scheme import FiatShamirPrototype, ProofArtifact

logger = logging.getLogger(__name__)


@dataclass
class ServerTranscript:
    """Everything the server has EVER seen (bounded), used by the
    non-disclosure tests. Bounded so a long-running demo cannot grow without
    limit; the nonce set stays unbounded by design — dropping old nonces would
    re-open replay of those nonces."""

    received: deque = field(default_factory=lambda: deque(maxlen=500))
    decisions: deque = field(default_factory=lambda: deque(maxlen=500))
    seen_nonces: set[str] = field(default_factory=set)


class SetupResponse(BaseModel):
    context_serial_b64: str
    policy_digest: str
    model_digest: str


class CheckRequest(BaseModel):
    nonce: str
    created_at: float = Field(description="client epoch seconds when the request was built")
    enc_features_serial_b64: str
    prompt_commitment: str
    policy_digest: str
    model_digest: str


class CheckResponse(BaseModel):
    nonce: str
    risk_score: float
    verdict: str
    decision_proof_json: str
    latency_ms: float


class VerifyRequest(BaseModel):
    decision_proof_json: str


class VerifyResponse(BaseModel):
    valid: bool
    reason: str


class SafetyServer:
    def __init__(self, policy: PolicyEngine, scorer: CKKSRiskScorer):
        self.policy = policy
        self.scorer = scorer
        self.proofs = FiatShamirPrototype()
        self.transcript = ServerTranscript()
        proto = policy.cfg.get("protocol", {})
        self.max_nonce_age = float(proto.get("max_nonce_age_seconds", 300))
        self.max_future_skew = float(proto.get("max_future_skew_seconds", 60))

    def process(self, req: CheckRequest) -> CheckResponse:
        t0 = time.monotonic()
        if req.policy_digest != self.policy.digest():
            raise HTTPException(status_code=400, detail="policy digest mismatch")
        if req.model_digest != self.scorer.weights_digest:
            raise HTTPException(status_code=400, detail="model digest mismatch")

        age = time.time() - req.created_at
        if age > self.max_nonce_age:
            raise HTTPException(status_code=400,
                                detail=f"stale request: nonce older than {self.max_nonce_age:.0f}s")
        if age < -self.max_future_skew:
            raise HTTPException(status_code=400,
                                detail=f"request timestamp more than {self.max_future_skew:.0f}s in the future")

        if req.nonce in self.transcript.seen_nonces:
            raise HTTPException(status_code=409, detail="replay: nonce already used")

        self.transcript.received.append(req.model_dump_json())
        self.transcript.seen_nonces.add(req.nonce)

        try:
            enc = self.scorer.load_ciphertext(base64.b64decode(req.enc_features_serial_b64))
        except Exception as exc:
            raise HTTPException(status_code=400, detail=f"bad ciphertext: {exc}") from exc

        enc_risk = self.scorer.encrypted_risk(enc)
        risk_raw = self.scorer.decrypt_risk(enc_risk)
        amp = float(self.policy.cfg.get("fhe", {}).get("score_amplification", 1.0))
        risk = sigmoid(amp * risk_raw)
        verdict = PolicyVerdict(
            verdict="ALLOW" if risk < self.policy.threshold else "REJECT",
            risk_score=round(risk, 6),
            matched_rules=["fhe_score_threshold"],
        )
        artifact = self.proofs.generate(
            commitment=req.prompt_commitment,
            verdict=verdict.verdict,
            policy_digest=req.policy_digest,
            model_digest=req.model_digest,
            nonce=req.nonce,
        )
        self.transcript.decisions.append(
            {"nonce": req.nonce, "risk_score": verdict.risk_score, "verdict": verdict.verdict}
        )
        latency = (time.monotonic() - t0) * 1000
        return CheckResponse(
            nonce=req.nonce,
            risk_score=verdict.risk_score,
            verdict=verdict.verdict,
            decision_proof_json=artifact.to_json(),
            latency_ms=round(latency, 2),
        )

    def verify_artifact(self, raw: str) -> VerifyResponse:
        try:
            artifact = ProofArtifact.from_json(raw)
            valid = self.proofs.verify(artifact)
        except Exception:
            return VerifyResponse(valid=False, reason="malformed artifact")
        return VerifyResponse(valid=valid, reason="ok" if valid else "challenge/response mismatch")


def _load_policy_and_scorer():
    cfg_path = Path(__file__).resolve().parents[3] / "configs" / "policy.json"
    policy = PolicyEngine.from_file(cfg_path)
    fhe = policy.cfg["fhe"]
    scorer = CKKSRiskScorer(
        poly_modulus_degree=fhe["poly_modulus_degree"],
        scale_bits=fhe["scale_bits"],
        coeff_mod_bit_sizes=fhe["coeff_mod_bit_sizes"],
        feature_dim=fhe["feature_dim"],
        model_seed=fhe["model_seed"],
    )
    return policy, scorer


policy, scorer = _load_policy_and_scorer()
server = SafetyServer(policy, scorer)

app = FastAPI(title="zk-SAFEGUARD PoC", version="0.1.0")


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "policy_digest": policy.digest(), "model_digest": scorer.weights_digest}


@app.get("/setup", response_model=SetupResponse)
def setup() -> SetupResponse:
    return SetupResponse(
        context_serial_b64=base64.b64encode(scorer.public_context_serial()).decode(),
        policy_digest=policy.digest(),
        model_digest=scorer.weights_digest,
    )


@app.post("/check", response_model=CheckResponse)
def check(req: CheckRequest) -> CheckResponse:
    return server.process(req)


@app.post("/verify", response_model=VerifyResponse)
def verify(req: VerifyRequest) -> VerifyResponse:
    return server.verify_artifact(req.decision_proof_json)
