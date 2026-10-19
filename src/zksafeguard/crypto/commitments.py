"""SHA-256 salted commitments and digests.

Binding commitment under the standard hash assumption. The salt must be
high-entropy and held by the committer; revealing it later opens the
commitment for verification.
"""

from __future__ import annotations

import hashlib
import secrets


def digest_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_commitment(payload: bytes, salt: bytes | None = None) -> tuple[str, bytes]:
    """Return (commitment_hex, salt). Salt generated if not supplied."""
    if salt is None:
        salt = secrets.token_bytes(32)
    return digest_bytes(salt + b":" + payload), salt


def open_commitment(payload: bytes, salt: bytes, commitment_hex: str) -> bool:
    """Verify an opened commitment (constant-time compare on digests)."""
    expected, _ = sha256_commitment(payload, salt)
    return hashlib.compare_digest(expected, commitment_hex)
