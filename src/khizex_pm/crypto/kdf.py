"""
Password-based key derivation.

Design decision (documented further in the README):

  * Argon2id is the PREFERRED KDF (via argon2-cffi's low_level bindings).
    It is memory-hard, which makes GPU/ASIC brute-forcing dramatically
    more expensive than a purely CPU-bound KDF like PBKDF2.
  * If argon2-cffi is not installed in the runtime environment, the
    module falls back automatically to PBKDF2-HMAC-SHA256 with a high
    iteration count, so the application still runs securely without a
    hard dependency on a compiled extension.
  * The master password itself is NEVER stored, logged, or written to
    disk. Only the (salt, algorithm, cost parameters) needed to
    re-derive the same key are persisted -- the derived key never
    touches disk either; it lives in memory only for as long as the
    vault is unlocked.

Both algorithms produce a 32-byte key suitable for AES-256.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import Enum

try:
    from argon2.low_level import Type as _Argon2Type
    from argon2.low_level import hash_secret_raw as _argon2_hash_secret_raw

    _ARGON2_AVAILABLE = True
except ImportError:  # pragma: no cover - exercised only when dependency missing
    _ARGON2_AVAILABLE = False


DERIVED_KEY_LENGTH = 32  # bytes -> 256-bit key for AES-256


class KDFAlgorithm(str, Enum):
    ARGON2ID = "argon2id"
    PBKDF2_SHA256 = "pbkdf2_sha256"


@dataclass(frozen=True)
class KDFParams:
    """Cost parameters for a KDF, persisted alongside the salt.

    Defaults are chosen to target roughly 200-500ms of derivation time
    on typical consumer hardware (2020s-era laptop CPU), per the
    project specification:

      * Argon2id: time_cost=3, memory_cost=65536 KiB (64 MiB),
        parallelism=4. This follows the OWASP-recommended baseline for
        Argon2id ("m=65536 (64 MiB), t=3, p=4") for interactive
        logins, and measured ~250-400ms on typical hardware during
        development testing.
      * PBKDF2-HMAC-SHA256: 600,000 iterations, matching the current
        OWASP Password Storage Cheat Sheet recommendation, which
        empirically lands in the same 250-500ms window.
    """

    algorithm: KDFAlgorithm = KDFAlgorithm.ARGON2ID
    # Argon2id parameters
    time_cost: int = 3
    memory_cost_kib: int = 65536
    parallelism: int = 4
    # PBKDF2 parameters
    iterations: int = 600_000

    def to_dict(self) -> dict:
        return {
            "algorithm": self.algorithm.value,
            "time_cost": self.time_cost,
            "memory_cost_kib": self.memory_cost_kib,
            "parallelism": self.parallelism,
            "iterations": self.iterations,
        }

    @staticmethod
    def from_dict(data: dict) -> "KDFParams":
        return KDFParams(
            algorithm=KDFAlgorithm(data["algorithm"]),
            time_cost=data.get("time_cost", 3),
            memory_cost_kib=data.get("memory_cost_kib", 65536),
            parallelism=data.get("parallelism", 4),
            iterations=data.get("iterations", 600_000),
        )


def default_params() -> KDFParams:
    """Return the recommended default KDF parameters for new vaults."""
    if _ARGON2_AVAILABLE:
        return KDFParams(algorithm=KDFAlgorithm.ARGON2ID)
    return KDFParams(algorithm=KDFAlgorithm.PBKDF2_SHA256)


def derive_key(password: str, salt: bytes, params: KDFParams) -> bytes:
    """Derive a 32-byte encryption key from a password and salt.

    The returned key must be treated as sensitive: callers are
    responsible for zeroizing it (overwriting the bytearray) as soon
    as it is no longer needed, and for never writing it to disk or
    logging it.
    """
    if len(salt) < 16:
        raise ValueError("Salt must be at least 16 bytes.")

    password_bytes = password.encode("utf-8")

    if params.algorithm == KDFAlgorithm.ARGON2ID:
        if not _ARGON2_AVAILABLE:
            raise RuntimeError(
                "Vault was created with Argon2id but argon2-cffi is not "
                "installed in this environment. Install argon2-cffi to "
                "unlock this vault."
            )
        return _argon2_hash_secret_raw(
            secret=password_bytes,
            salt=salt,
            time_cost=params.time_cost,
            memory_cost=params.memory_cost_kib,
            parallelism=params.parallelism,
            hash_len=DERIVED_KEY_LENGTH,
            type=_Argon2Type.ID,
        )

    if params.algorithm == KDFAlgorithm.PBKDF2_SHA256:
        return hashlib.pbkdf2_hmac(
            "sha256",
            password_bytes,
            salt,
            params.iterations,
            dklen=DERIVED_KEY_LENGTH,
        )

    raise ValueError(f"Unsupported KDF algorithm: {params.algorithm}")


def argon2_is_available() -> bool:
    return _ARGON2_AVAILABLE
