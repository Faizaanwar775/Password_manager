from __future__ import annotations

import base64
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, field_serializer, field_validator


class EncryptedRecord(BaseModel):
    """A single AEAD-encrypted payload: nonce + ciphertext.

    This is the fundamental "unit" that ever gets written to disk for
    anything sensitive (the wrapped vault key, the unlock canary, and
    each entry's encrypted password/notes blob all use this shape).
    """

    model_config = ConfigDict(extra="forbid")

    nonce: bytes = Field(..., min_length=12, max_length=12)
    ciphertext: bytes

    @field_validator("nonce", "ciphertext", mode="before")
    @classmethod
    def _decode_if_str(cls, value):
        # Allows constructing from base64 text (e.g. when loaded from
        # an export/import JSON file) as well as raw bytes.
        if isinstance(value, str):
            return base64.b64decode(value)
        return value

    @field_serializer("nonce", "ciphertext", when_used="json")
    def _encode_for_json(self, value: bytes) -> str:
        return base64.b64encode(value).decode("ascii")


class VaultMetaRecord(BaseModel):
    """Vault-wide metadata persisted in storage.

    Contains everything needed to re-derive the KDF output and unwrap
    the vault master key (VMK) given a correct master password --
    but never the password or key itself.
    """

    model_config = ConfigDict(extra="forbid")

    salt: bytes
    kdf_algorithm: str
    kdf_params: dict
    wrapped_vmk: EncryptedRecord  # VMK encrypted under the password-derived KEK
    canary: EncryptedRecord  # known plaintext encrypted under the KEK, for unlock verification
    created_at: datetime
    updated_at: datetime

    @field_validator("salt", mode="before")
    @classmethod
    def _decode_salt_if_str(cls, value):
        if isinstance(value, str):
            return base64.b64decode(value)
        return value

    @field_serializer("salt", when_used="json")
    def _encode_salt_for_json(self, value: bytes) -> str:
        return base64.b64encode(value).decode("ascii")


class EntryRecord(BaseModel):
    """Storage-layer representation of a single vault entry.

    `site` and `username` are kept as plaintext columns by design (see
    README "Design Decisions") so that listing entries never requires
    decryption. The password and notes are the sensitive payload and
    are always AEAD-encrypted under the vault master key (VMK) with a
    fresh nonce per entry, per save.
    """

    model_config = ConfigDict(extra="forbid")

    id: int | None = None
    site: str
    username: str
    secret: EncryptedRecord  # encrypts a small JSON blob: {"password": ..., "notes": ...}
    created_at: datetime
    updated_at: datetime


class VaultExportFile(BaseModel):
    """Top-level shape of an encrypted vault export/backup file.

    The export remains fully encrypted -- it is effectively a
    serialized copy of the vault_meta row and all entry rows. A
    plaintext export is explicitly disallowed by the specification.
    """

    model_config = ConfigDict(extra="forbid")

    format_version: int = 1
    vault_meta: VaultMetaRecord
    entries: list[EntryRecord]
