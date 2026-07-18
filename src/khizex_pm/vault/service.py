"""
Vault service: the only place in the application that ever holds a
derived key or a decrypted secret in memory.

Key architecture ("envelope encryption"), documented in full in the
README:

    master password + salt --[KDF]--> KEK (key-encryption-key)
    KEK encrypts a randomly generated 256-bit VMK (vault master key)
    VMK encrypts every entry's (password, notes) payload

The KEK itself is never stored -- it is re-derived from the master
password every time the vault is unlocked, and held only in a local
variable for the few milliseconds it takes to unwrap the VMK. The VMK
is what actually gets held in memory (as a `bytearray`, zeroized on
lock) while the vault is unlocked, and is what encrypts/decrypts
entries.

This design has a deliberate benefit for the master-password change
flow (3.1.5): changing the master password only needs to re-derive a
new KEK and re-wrap the *same* VMK under it -- no entry ciphertext
needs to be touched, so plaintext entries are never exposed outside
memory during a password change, and the operation is fast regardless
of vault size.

Unlock verification uses a "canary": a known plaintext string
encrypted under the KEK at vault-creation time. On unlock, we attempt
to decrypt the canary; AES-GCM's authentication tag will fail to
verify if the derived KEK is wrong, which is what actually detects an
incorrect master password -- no separate password hash is stored.
"""

from __future__ import annotations

import json
import logging
import threading
from datetime import datetime, timezone

from khizex_pm.crypto import aead, kdf
from khizex_pm.crypto.memory import zero
from khizex_pm.crypto.secure_random import generate_key, generate_salt
from khizex_pm.storage.db import VaultStorage
from khizex_pm.storage.schemas import EncryptedRecord, EntryRecord, VaultMetaRecord
from khizex_pm.vault.exceptions import (
    EntryNotFoundError,
    VaultAlreadyExistsError,
    VaultLockedError,
    VaultNotInitializedError,
    VaultUnlockError,
)
from khizex_pm.vault.models import (
    VaultEntryCreate,
    VaultEntryMetadata,
    VaultEntryRevealed,
    VaultEntryUpdate,
)

logger = logging.getLogger("khizex_pm.vault")

_CANARY_PLAINTEXT = b"KHIZEX-VAULT-OK-V1"


class VaultService:
    """Stateful service object wrapping one vault (one SQLite file).

    Thread safety: a single `threading.RLock` guards every mutation of
    lock state and the in-memory VMK, since both the CLI (main thread)
    and the auto-lock background timer thread touch this state. See
    `session/autolock.py` for the timer side of this.
    """

    def __init__(self, storage: VaultStorage) -> None:
        self._storage = storage
        self._state_lock = threading.RLock()
        self._vmk: bytearray | None = None  # only non-None while unlocked
        self._unlocked = False

    # ---- lifecycle --------------------------------------------------

    @property
    def is_initialized(self) -> bool:
        return self._storage.vault_meta_exists()

    @property
    def is_unlocked(self) -> bool:
        with self._state_lock:
            return self._unlocked

    def create_vault(self, master_password: str) -> None:
        """First-run onboarding: create a brand-new vault."""
        with self._state_lock:
            if self.is_initialized:
                raise VaultAlreadyExistsError("A vault already exists at this location.")

            salt = generate_salt(16)
            params = kdf.default_params()
            kek = bytearray(kdf.derive_key(master_password, salt, params))

            try:
                vmk = generate_key(32)  # the real vault master key
                wrapped_vmk = aead.encrypt(bytes(kek), vmk)
                canary = aead.encrypt(bytes(kek), _CANARY_PLAINTEXT)

                now = datetime.now(timezone.utc)
                meta = VaultMetaRecord(
                    salt=salt,
                    kdf_algorithm=params.algorithm.value,
                    kdf_params=params.to_dict(),
                    wrapped_vmk=EncryptedRecord(nonce=wrapped_vmk.nonce, ciphertext=wrapped_vmk.ciphertext),
                    canary=EncryptedRecord(nonce=canary.nonce, ciphertext=canary.ciphertext),
                    created_at=now,
                    updated_at=now,
                )
                self._storage.save_vault_meta(meta)
                self._vmk = bytearray(vmk)
                self._unlocked = True
                logger.info("Vault created and unlocked.")
            finally:
                zero(kek)

    def unlock(self, master_password: str) -> None:
        """Derive the KEK, verify it via the canary, and unwrap the VMK."""
        with self._state_lock:
            meta = self._storage.load_vault_meta()
            if meta is None:
                raise VaultNotInitializedError("No vault exists yet. Create one first.")

            params = kdf.KDFParams.from_dict(meta.kdf_params)
            kek = bytearray(kdf.derive_key(master_password, meta.salt, params))
            try:
                # Verify via canary. Any failure here -- wrong password OR
                # corrupted data -- surfaces as the SAME generic error, so
                # it cannot be used as an oracle by an attacker.
                try:
                    aead.decrypt(bytes(kek), meta.canary.nonce, meta.canary.ciphertext)
                except aead.DecryptionError:
                    raise VaultUnlockError() from None

                try:
                    vmk_plain = aead.decrypt(bytes(kek), meta.wrapped_vmk.nonce, meta.wrapped_vmk.ciphertext)
                except aead.DecryptionError:
                    raise VaultUnlockError() from None

                self._vmk = bytearray(vmk_plain)
                self._unlocked = True
                logger.info("Vault unlocked.")
            finally:
                zero(kek)

    def lock(self) -> None:
        """Clear the in-memory VMK and mark the vault locked."""
        with self._state_lock:
            if self._vmk is not None:
                zero(self._vmk)
                self._vmk = None
            self._unlocked = False
            logger.info("Vault locked; in-memory key material cleared.")

    def change_master_password(self, current_master_password: str, new_master_password: str) -> None:
        """Re-derive the KEK under a new password and re-wrap the VMK.

        Because entries are encrypted under the VMK (not the KEK
        directly), this never needs to touch entry ciphertext -- the
        VMK itself does not change, only how it is wrapped.
        """
        with self._state_lock:
            if not self._unlocked or self._vmk is None:
                raise VaultLockedError()

            meta = self._storage.load_vault_meta()
            if meta is None:
                raise VaultNotInitializedError("No vault exists yet.")

            old_params = kdf.KDFParams.from_dict(meta.kdf_params)
            old_kek = bytearray(kdf.derive_key(current_master_password, meta.salt, old_params))
            try:
                try:
                    aead.decrypt(bytes(old_kek), meta.canary.nonce, meta.canary.ciphertext)
                except aead.DecryptionError:
                    raise VaultUnlockError() from None
            finally:
                zero(old_kek)

            new_salt = generate_salt(16)
            new_params = kdf.default_params()
            new_kek = bytearray(kdf.derive_key(new_master_password, new_salt, new_params))
            try:
                wrapped_vmk = aead.encrypt(bytes(new_kek), bytes(self._vmk))
                canary = aead.encrypt(bytes(new_kek), _CANARY_PLAINTEXT)

                now = datetime.now(timezone.utc)
                new_meta = VaultMetaRecord(
                    salt=new_salt,
                    kdf_algorithm=new_params.algorithm.value,
                    kdf_params=new_params.to_dict(),
                    wrapped_vmk=EncryptedRecord(nonce=wrapped_vmk.nonce, ciphertext=wrapped_vmk.ciphertext),
                    canary=EncryptedRecord(nonce=canary.nonce, ciphertext=canary.ciphertext),
                    created_at=meta.created_at,
                    updated_at=now,
                )
                self._storage.save_vault_meta(new_meta)
                logger.info("Master password changed; VMK re-wrapped under new KEK.")
            finally:
                zero(new_kek)

    # ---- entry CRUD ---------------------------------------------------

    def _require_unlocked(self) -> bytes:
        with self._state_lock:
            if not self._unlocked or self._vmk is None:
                raise VaultLockedError()
            return bytes(self._vmk)

    def add_entry(self, payload: VaultEntryCreate) -> int:
        vmk = self._require_unlocked()
        secret_plain = json.dumps({"password": payload.password, "notes": payload.notes}).encode("utf-8")
        enc = aead.encrypt(vmk, secret_plain)
        entry_id = self._storage.insert_entry(
            site=payload.site,
            username=payload.username,
            secret=EncryptedRecord(nonce=enc.nonce, ciphertext=enc.ciphertext),
        )
        logger.info("Entry added (id=%s, site=%s).", entry_id, payload.site)
        return entry_id

    def update_entry(self, entry_id: int, payload: VaultEntryUpdate) -> None:
        vmk = self._require_unlocked()
        existing = self._storage.get_entry(entry_id)
        if existing is None:
            raise EntryNotFoundError(entry_id)

        current = self._decrypt_secret(vmk, existing)
        new_site = payload.site if payload.site is not None else existing.site
        new_username = payload.username if payload.username is not None else existing.username
        new_password = payload.password if payload.password is not None else current["password"]
        new_notes = payload.notes if payload.notes is not None else current["notes"]

        secret_plain = json.dumps({"password": new_password, "notes": new_notes}).encode("utf-8")
        enc = aead.encrypt(vmk, secret_plain)
        self._storage.update_entry(
            entry_id,
            site=new_site,
            username=new_username,
            secret=EncryptedRecord(nonce=enc.nonce, ciphertext=enc.ciphertext),
        )
        logger.info("Entry updated (id=%s).", entry_id)

    def delete_entry(self, entry_id: int) -> None:
        self._require_unlocked()
        deleted = self._storage.delete_entry(entry_id)
        if not deleted:
            raise EntryNotFoundError(entry_id)
        logger.info("Entry deleted (id=%s).", entry_id)

    def get_entry(self, entry_id: int) -> VaultEntryRevealed:
        """Retrieve and decrypt a single entry -- the only place plaintext secrets are reconstructed."""
        vmk = self._require_unlocked()
        record = self._storage.get_entry(entry_id)
        if record is None:
            raise EntryNotFoundError(entry_id)

        try:
            secret = self._decrypt_secret(vmk, record)
        except aead.DecryptionError:
            # Tampered/corrupted ciphertext for this specific entry.
            raise VaultUnlockError() from None

        return VaultEntryRevealed(
            id=record.id,
            site=record.site,
            username=record.username,
            password=secret["password"],
            notes=secret["notes"],
            created_at=record.created_at,
            updated_at=record.updated_at,
        )

    def list_entries(self) -> list[VaultEntryMetadata]:
        """List entry metadata ONLY -- never decrypts passwords/notes."""
        self._require_unlocked()
        return [
            VaultEntryMetadata(
                id=r.id,
                site=r.site,
                username=r.username,
                created_at=r.created_at,
                updated_at=r.updated_at,
            )
            for r in self._storage.list_entries()
        ]

    @staticmethod
    def _decrypt_secret(vmk: bytes, record: EntryRecord) -> dict:
        plain = aead.decrypt(vmk, record.secret.nonce, record.secret.ciphertext)
        return json.loads(plain.decode("utf-8"))
