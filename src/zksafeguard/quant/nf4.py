"""NF4-style 4-bit quantization study (CPU, no GPU required).

Implements the standard NF4 datatype: 16 levels placed at quantiles of the
standard normal distribution, plus absolute-max scaling per tensor. Used to
measure the quantization error of a linear layer — the building block of the
NF4 quantized-inference idea from the project brief.
"""

from __future__ import annotations

import numpy as np
from scipy.stats import norm

_NF4_LEVELS = np.array(
    [norm.ppf((2 * i + 1) / 32) for i in range(16)]
)


def nf4_quantize(weights: np.ndarray) -> tuple[np.ndarray, float]:
    """Quantize a float32 weight matrix to NF4 code indices.

    Returns (codes int8 [0..15], absmax scale).
    """
    if weights.ndim != 2:
        raise ValueError("expect a 2-D weight matrix")
    absmax = float(np.max(np.abs(weights))) or 1.0
    normalized = weights / absmax
    dist = np.abs(normalized[..., None] - _NF4_LEVELS[None, None, :])
    codes = np.argmin(dist, axis=-1).astype(np.int8)
    return codes, absmax


def nf4_dequantize(codes: np.ndarray, absmax: float) -> np.ndarray:
    return _NF4_LEVELS[codes.astype(int)] * absmax


def nf4_dot_error(W: np.ndarray, x: np.ndarray) -> dict[str, float]:
    """Relative error of y = W x between fp32 and NF4-quantized W."""
    if x.ndim != 1 or x.shape[0] != W.shape[1]:
        raise ValueError("x must be a vector matching W columns")
    codes, absmax = nf4_quantize(W)
    W_q = nf4_dequantize(codes, absmax)
    y_fp = W @ x
    y_q = W_q @ x
    denom = float(np.linalg.norm(y_fp)) or 1.0
    rel_err = float(np.linalg.norm(y_fp - y_q) / denom)
    cos = float(np.dot(y_fp, y_q) / ((np.linalg.norm(y_fp) * np.linalg.norm(y_q)) or 1.0))
    return {
        "relative_error_l2": rel_err,
        "cosine_similarity": cos,
        "max_abs_weight": float(np.max(np.abs(W))),
        "n_weights": int(W.size),
        "bytes_fp32": int(W.size * 4),
        "bytes_nf4_packed": int((W.size + 1) // 2),
        "compression_ratio": float(W.size * 4 / ((W.size + 1) // 2)),
    }
