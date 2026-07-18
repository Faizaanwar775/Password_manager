"""
Authenticated encryption primitives.

Uses AES-256-GCM from the `cryptography` library (an audited,
well-reviewed implementation) -- no hand-rolled cipher or XOR scheme
is used anywhere in this project.

Every call to `encrypt` generates a fresh, random 96-bit nonce via
`secure_random.generate_nonce`. Nonces are never cached, derived
deterministically, or reused across encryption operations -- reusing
a (key, nonce) pair with GCM catastrophically breaks confidentiality
and authenticity, so this module makes it structurally impossible to
forget: `encrypt()` always generates its own nonce and returns it.
"""

from __future__ import annotations

from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from khizex_pm.crypto.secure_random import generate_nonce

NONCE_LENGTH = 12  # 96 bits, the recommended/standard nonce size for AES-GCM
KEY_LENGTH = 32  # 256 bits


class DecryptionError(Exception):
    """Raised when authenticated decryption fails.

    This can mean either the ciphertext was tampered with/corrupted,
    or the key is wrong (e.g. wrong master password). Callers at the
    vault-service layer are responsible for NOT distinguishing between
    these two cases in any message shown to the end user, so an
    attacker cannot use error content as an oracle.
    """


@dataclass(frozen=True)
class EncryptedPayload:
    """A ciphertext bundled with the nonce used to produce it."""

    nonce: bytes
    ciphertext: bytes


def encrypt(key: bytes, plaintext: bytes, associated_data: bytes | None = None) -> EncryptedPayload:
    """Encrypt `plaintext` with AES-256-GCM using a freshly generated nonce.

    `associated_data` is authenticated but not encrypted -- useful for
    binding ciphertext to non-secret context (e.g. an entry ID) so
    swapping ciphertexts between records is detected.
    """
    if len(key) != KEY_LENGTH:
        raise ValueError(f"Key must be exactly {KEY_LENGTH} bytes for AES-256-GCM.")

    nonce = generate_nonce(NONCE_LENGTH)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)
    return EncryptedPayload(nonce=nonce, ciphertext=ciphertext)


def decrypt(
    key: bytes,
    nonce: bytes,
    ciphertext: bytes,
    associated_data: bytes | None = None,
) -> bytes:
    """Decrypt and verify a ciphertext produced by `encrypt`.

    Raises DecryptionError if the authentication tag does not match,
    i.e. the ciphertext was tampered with, corrupted, or the key is
    wrong. A tampered ciphertext will NEVER silently return garbage
    plaintext -- this is the core guarantee of an AEAD cipher.
    """
    if len(key) != KEY_LENGTH:
        raise ValueError(f"Key must be exactly {KEY_LENGTH} bytes for AES-256-GCM.")
    if len(nonce) != NONCE_LENGTH:
        raise ValueError(f"Nonce must be exactly {NONCE_LENGTH} bytes.")

    aesgcm = AESGCM(key)
    try:
        return aesgcm.decrypt(nonce, ciphertext, associated_data)
    except InvalidTag as exc:
        raise DecryptionError("Authentication failed: ciphertext is invalid or key is incorrect.") from exc
