"""Vault domain logic: entry CRUD, lock/unlock state, master password management."""

from khizex_pm.vault.exceptions import (
    EntryNotFoundError,
    VaultAlreadyExistsError,
    VaultError,
    VaultLockedError,
    VaultNotInitializedError,
    VaultUnlockError,
)
from khizex_pm.vault.models import (
    MasterPasswordChangeRequest,
    PasswordGenerationRequest,
    VaultEntryCreate,
    VaultEntryMetadata,
    VaultEntryRevealed,
    VaultEntryUpdate,
)
from khizex_pm.vault.export_import import export_vault, import_vault
from khizex_pm.vault.service import VaultService

__all__ = [
    "export_vault",
    "import_vault",
    "EntryNotFoundError",
    "VaultAlreadyExistsError",
    "VaultError",
    "VaultLockedError",
    "VaultNotInitializedError",
    "VaultUnlockError",
    "MasterPasswordChangeRequest",
    "PasswordGenerationRequest",
    "VaultEntryCreate",
    "VaultEntryMetadata",
    "VaultEntryRevealed",
    "VaultEntryUpdate",
    "VaultService",
]
