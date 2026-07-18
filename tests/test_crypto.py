"""Unit tests for the crypto layer, run in isolation from vault/storage."""

from __future__ import annotations

import pytest

from khizex_pm.crypto import aead, kdf
from khizex_pm.crypto.secure_random import (
    generate_key,
    generate_nonce,
    generate_password,
    generate_salt,
)


def test_salt_length_enforced():
    with pytest.raises(ValueError):
        generate_salt(8)
    assert len(generate_salt(16)) == 16
    assert len(generate_salt(32)) == 32


def test_nonces_are_unique():
    nonces = {generate_nonce() for _ in range(1000)}
    assert len(nonces) == 1000  # no collisions in 1000 draws


def test_generated_password_respects_length_and_classes():
    pw = generate_password(length=24, use_symbols=False)
    assert len(pw) == 24
    assert not any(c in "!@#$%^&*()-_=+[]{};:,.<>?/" for c in pw)


def test_generated_password_requires_at_least_one_class():
    with pytest.raises(ValueError):
        generate_password(use_lower=False, use_upper=False, use_digits=False, use_symbols=False)


@pytest.mark.parametrize(
    "algorithm",
    [kdf.KDFAlgorithm.PBKDF2_SHA256] + ([kdf.KDFAlgorithm.ARGON2ID] if kdf.argon2_is_available() else []),
)
def test_kdf_is_deterministic_given_same_salt_and_params(algorithm):
    salt = generate_salt(16)
    params = kdf.KDFParams(algorithm=algorithm, time_cost=1, memory_cost_kib=8192, parallelism=1, iterations=10_000)
    key1 = kdf.derive_key("correct horse battery staple", salt, params)
    key2 = kdf.derive_key("correct horse battery staple", salt, params)
    assert key1 == key2
    assert len(key1) == kdf.DERIVED_KEY_LENGTH


def test_kdf_different_password_gives_different_key():
    salt = generate_salt(16)
    params = kdf.KDFParams(algorithm=kdf.KDFAlgorithm.PBKDF2_SHA256, iterations=10_000)
    key1 = kdf.derive_key("password-one", salt, params)
    key2 = kdf.derive_key("password-two", salt, params)
    assert key1 != key2


def test_aead_round_trip():
    key = generate_key(32)
    plaintext = b"super secret data"
    enc = aead.encrypt(key, plaintext)
    decrypted = aead.decrypt(key, enc.nonce, enc.ciphertext)
    assert decrypted == plaintext


def test_aead_each_encryption_uses_a_fresh_nonce():
    key = generate_key(32)
    enc1 = aead.encrypt(key, b"same plaintext")
    enc2 = aead.encrypt(key, b"same plaintext")
    assert enc1.nonce != enc2.nonce
    assert enc1.ciphertext != enc2.ciphertext


def test_aead_tampered_ciphertext_fails_to_decrypt():
    key = generate_key(32)
    enc = aead.encrypt(key, b"do not tamper with me")
    tampered = bytearray(enc.ciphertext)
    tampered[0] ^= 0xFF
    with pytest.raises(aead.DecryptionError):
        aead.decrypt(key, enc.nonce, bytes(tampered))


def test_aead_wrong_key_fails_to_decrypt():
    key1 = generate_key(32)
    key2 = generate_key(32)
    enc = aead.encrypt(key1, b"secret")
    with pytest.raises(aead.DecryptionError):
        aead.decrypt(key2, enc.nonce, enc.ciphertext)


def test_aead_rejects_wrong_key_length():
    with pytest.raises(ValueError):
        aead.encrypt(b"too-short-key", b"data")
