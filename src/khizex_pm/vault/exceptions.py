from __future__ import annotations


class VaultError(Exception):
    """Base class for all vault-related errors."""


class VaultUnlockError(VaultError):
    """Raised when a vault cannot be unlocked.

    Deliberately does not indicate whether the cause was an incorrect
    master password or a corrupted/tampered vault file.
    """

    def __init__(self) -> None:
        super().__init__("Unable to unlock vault: incorrect master password or corrupted vault data.")


class VaultLockedError(VaultError):
    """Raised when an operation requiring an unlocked vault is attempted while locked."""

    def __init__(self) -> None:
        super().__init__("Vault is locked. Unlock it with your master password first.")


class VaultAlreadyExistsError(VaultError):
    """Raised when attempting to create a vault where one already exists."""


class VaultNotInitializedError(VaultError):
    """Raised when attempting to unlock a vault that has not been created yet."""


class EntryNotFoundError(VaultError):
    """Raised when a requested entry ID does not exist in the vault."""

    def __init__(self, entry_id: int) -> None:
        super().__init__(f"No entry found with id={entry_id}.")
