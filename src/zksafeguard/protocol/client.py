"""Client helper: encrypt features locally, build commitments, call server."""

from __future__ import annotations

import base64
import secrets
import time

import tenseal as ts

from zksafeguard.crypto.commitments import sha256_commitment
from zksafeguard.fhe.ckks_scorer import extract_features


class SafetyClient:
    def __init__(self, public_context_serial: bytes, policy_digest: str, model_digest: str):
        self._ctx = ts.context_from(public_context_serial)
        self.policy_digest = policy_digest
        self.model_digest = model_digest

    def build_check_request(self, prompt: str, feature_dim: int, nonce: str | None = None):
        features = extract_features(prompt, feature_dim)
        enc = ts.ckks_vector(self._ctx, features)
        salt = secrets.token_bytes(32)
        commitment, _ = sha256_commitment(prompt.encode(), salt)
        return {
            "nonce": nonce or secrets.token_hex(16),
            "created_at": time.time(),
            "enc_features_serial_b64": base64.b64encode(enc.serial()).decode(),
            "prompt_commitment": commitment,
            "policy_digest": self.policy_digest,
            "model_digest": self.model_digest,
        }
