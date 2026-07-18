"""
Cryptographically secure random generation utilities.

Everything in this module is built on top of Python's `secrets` module,
which draws from the operating system's CSPRNG (os.urandom). The
built-in `random` module is a Mersenne Twister PRNG and is NEVER used
here for anything security-sensitive (salts, nonces, keys, generated
passwords).
"""

from __future__ import annotations

import secrets
import string

# Character classes available for generated passwords.
_LOWER = string.ascii_lowercase
_UPPER = string.ascii_uppercase
_DIGITS = string.digits
_SYMBOLS = "!@#$%^&*()-_=+[]{};:,.<>?/"

# Characters that are visually ambiguous and are excluded by default
# (helps users who need to transcribe a password by hand).
_AMBIGUOUS = set("Il1O0")


def generate_salt(length: int = 16) -> bytes:
    """Generate a cryptographically secure random salt.

    A minimum of 16 bytes is required by the project specification.
    """
    if length < 16:
        raise ValueError("Salt length must be at least 16 bytes for adequate entropy.")
    return secrets.token_bytes(length)


def generate_nonce(length: int = 12) -> bytes:
    """Generate a cryptographically secure random nonce.

    12 bytes (96 bits) is the recommended nonce size for AES-GCM. A
    fresh nonce MUST be generated for every single encryption
    operation -- callers should never cache or reuse the return value.
    """
    return secrets.token_bytes(length)


def generate_key(length: int = 32) -> bytes:
    """Generate a cryptographically secure random symmetric key.

    32 bytes (256 bits) matches AES-256.
    """
    return secrets.token_bytes(length)


def generate_password(
    length: int = 20,
    use_lower: bool = True,
    use_upper: bool = True,
    use_digits: bool = True,
    use_symbols: bool = True,
    exclude_ambiguous: bool = True,
) -> str:
    """Generate a cryptographically secure random password.

    Uses `secrets.choice`, not `random.choice`, so the result is safe
    to use as an actual credential. At least one character class must
    be enabled, and the generator guarantees at least one character
    from each *enabled* class is present (without weakening the
    overall entropy by fixing character positions -- the guaranteed
    characters are shuffled into a secrets-random position).
    """
    if length < 4:
        raise ValueError("Password length should be at least 4 characters.")

    classes: list[str] = []
    if use_lower:
        classes.append(_LOWER)
    if use_upper:
        classes.append(_UPPER)
    if use_digits:
        classes.append(_DIGITS)
    if use_symbols:
        classes.append(_SYMBOLS)

    if not classes:
        raise ValueError("At least one character class must be enabled.")

    if exclude_ambiguous:
        classes = ["".join(c for c in cls if c not in _AMBIGUOUS) for cls in classes]

    alphabet = "".join(classes)

    # Guarantee representation from every requested class.
    required = [secrets.choice(cls) for cls in classes]
    remaining_length = length - len(required)
    if remaining_length < 0:
        # More classes than length allows; trim (extremely short passwords only).
        required = required[:length]
        remaining_length = 0

    body = [secrets.choice(alphabet) for _ in range(remaining_length)]
    all_chars = required + body

    # Use a Fisher-Yates style secure shuffle so the guaranteed
    # characters are not always in the same positions.
    for i in range(len(all_chars) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        all_chars[i], all_chars[j] = all_chars[j], all_chars[i]

    return "".join(all_chars)
