
from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator

# Reasonable, documented bounds -- not arbitrary "Any"-typed fields.
_MAX_SITE_LEN = 256
_MAX_USERNAME_LEN = 256
_MAX_PASSWORD_LEN = 1024
_MAX_NOTES_LEN = 4096


class VaultEntryCreate(BaseModel):
    """Input payload for creating a new vault entry (CLI/API -> service)."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    site: str = Field(..., min_length=1, max_length=_MAX_SITE_LEN)
    username: str = Field(..., min_length=1, max_length=_MAX_USERNAME_LEN)
    password: str = Field(..., min_length=1, max_length=_MAX_PASSWORD_LEN)
    notes: str = Field(default="", max_length=_MAX_NOTES_LEN)

    @field_validator("site", "username")
    @classmethod
    def _no_control_chars(cls, value: str) -> str:
        if any(ord(ch) < 32 for ch in value):
            raise ValueError("Control characters are not allowed.")
        return value


class VaultEntryUpdate(BaseModel):
    """Input payload for partially updating an existing entry."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    site: str | None = Field(default=None, min_length=1, max_length=_MAX_SITE_LEN)
    username: str | None = Field(default=None, min_length=1, max_length=_MAX_USERNAME_LEN)
    password: str | None = Field(default=None, min_length=1, max_length=_MAX_PASSWORD_LEN)
    notes: str | None = Field(default=None, max_length=_MAX_NOTES_LEN)


class VaultEntryMetadata(BaseModel):
    """Metadata-only view of an entry, safe to show without decrypting secrets.

    Used for the `list` operation -- deliberately excludes password and
    notes so simply browsing the vault never touches the AEAD layer.
    """

    model_config = ConfigDict(extra="forbid")

    id: int
    site: str
    username: str
    created_at: datetime
    updated_at: datetime


class VaultEntryRevealed(BaseModel):
    """Fully decrypted entry, held in memory only -- never persisted as-is."""

    model_config = ConfigDict(extra="forbid")

    id: int
    site: str
    username: str
    password: str
    notes: str
    created_at: datetime
    updated_at: datetime


class PasswordGenerationRequest(BaseModel):
    """Input payload for the secure password generator."""

    model_config = ConfigDict(extra="forbid")

    length: int = Field(default=20, ge=4, le=256)
    use_lower: bool = True
    use_upper: bool = True
    use_digits: bool = True
    use_symbols: bool = True
    exclude_ambiguous: bool = True


class MasterPasswordChangeRequest(BaseModel):
    """Input payload for changing the master password."""

    model_config = ConfigDict(extra="forbid")

    current_master_password: str = Field(..., min_length=1)
    new_master_password: str = Field(..., min_length=8, max_length=1024)
