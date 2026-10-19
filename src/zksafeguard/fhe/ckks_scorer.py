"""CKKS encrypted linear risk scoring with TenSEAL.

Genuinely homomorphic part: feature extraction happens client-side, the
encrypted feature vector is combined with the (public) model weights under
encryption, and only the single aggregated risk value is ever decrypted.
The plaintext feature vector never leaves the client.

This is a LINEAR model under CKKS — real FHE, real limitations. It is not an
LLM and not a production safety classifier.
"""

from __future__ import annotations

import hashlib
import math

import numpy as np

FEATURE_DIM_DEFAULT = 128


def extract_features(prompt: str, dim: int = FEATURE_DIM_DEFAULT) -> list[float]:
    """Hashed bag-of-tokens feature vector, L2-normalized, length `dim`."""
    if dim < 1:
        raise ValueError("dim must be >= 1")
    vec = np.zeros(dim, dtype=np.float64)
    tokens = prompt.lower().split()
    if not tokens:
        return [0.0] * dim
    for tok in tokens:
        h = int(hashlib.sha256(tok.encode()).hexdigest(), 16)
        vec[h % dim] += 1.0
    norm = np.linalg.norm(vec)
    if norm > 0:
        vec /= norm
    return [float(v) for v in vec]


def deterministic_weights(dim: int, seed: int) -> list[float]:
    """Public model parameters (seeded, so the digest is stable)."""
    rng = np.random.default_rng(seed)
    w = rng.uniform(-0.5, 0.5, size=dim)
    return [float(v) for v in w]


def sigmoid(x: float) -> float:
    return 1.0 / (1.0 + math.exp(-x))


class CKKSRiskScorer:
    """Server-style scorer: holds the CKKS secret key, exposes a public
    context (no secret) for clients to encrypt under."""

    def __init__(self, poly_modulus_degree: int = 8192, scale_bits: int = 40,
                 coeff_mod_bit_sizes: list[int] | None = None, feature_dim: int = FEATURE_DIM_DEFAULT,
                 model_seed: int = 1234):
        import tenseal as ts

        coeff = coeff_mod_bit_sizes or [60, 40, 40, 60]
        self._ts = ts
        self._ctx = ts.context(
            ts.SCHEME_TYPE.CKKS,
            poly_modulus_degree=poly_modulus_degree,
            coeff_mod_bit_sizes=coeff,
        )
        self._ctx.global_scale = 2.0**scale_bits
        self._ctx.generate_relin_keys()
        self._ctx.generate_galois_keys()
        self.feature_dim = feature_dim
        self.weights = deterministic_weights(feature_dim, model_seed)

    @property
    def weights_digest(self) -> str:
        import hashlib
        import struct

        packed = struct.pack(f"{len(self.weights)}d", *self.weights)
        return hashlib.sha256(packed).hexdigest()

    def public_context_serial(self) -> bytes:
        """Context WITHOUT the secret key — safe to hand to clients."""
        return self._ctx.serialize(save_secret_key=False)

    def encrypt_features(self, features: list[float]):
        """Client-side: encrypt under the public context (no secret needed)."""
        ctx = self._ts.context_from(self.public_context_serial())
        return self._ts.ckks_vector(ctx, features)

    def load_ciphertext(self, serial: bytes):
        """Server-side: load a client ciphertext into the SECRET-holding
        context so the server can decrypt the aggregated score later."""
        return self._ts.ckks_vector_from(self._ctx, serial)

    def encrypted_risk(self, enc_features):
        """Server-side: homomorphic linear score. Returns encrypted scalar."""
        return enc_features.dot(self.weights)

    def decrypt_risk(self, enc_risk) -> float:
        """Server-side only (holds secret key): decrypt aggregated risk."""
        out = enc_risk.decrypt()
        val = out[0] if isinstance(out, list) else float(out)
        return float(val)

    def plaintext_risk(self, features: list[float]) -> float:
        """Reference plaintext computation (for validation/tests)."""
        dot = float(np.dot(np.asarray(features), np.asarray(self.weights)))
        return dot

    def score_encrypted(self, prompt: str, amplification: float = 1.0) -> float:
        """Full path: features -> encrypt -> homomorphic dot -> decrypt.
        `amplification` scales the logit before the sigmoid (same value the
        server applies; see configs/policy.json fhe.score_amplification)."""
        feats = extract_features(prompt, self.feature_dim)
        enc = self.encrypt_features(feats)
        return sigmoid(amplification * self.decrypt_risk(self.encrypted_risk(enc)))
