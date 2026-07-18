"""End-to-end tests for the vault pipeline: create -> unlock -> CRUD -> lock."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from khizex_pm.storage.db import VaultStorage
from khizex_pm.vault.exceptions import (
    EntryNotFoundError,
    VaultAlreadyExistsError,
    VaultLockedError,
    VaultNotInitializedError,
    VaultUnlockError,
)
from khizex_pm.vault.export_import import export_vault, import_vault
from khizex_pm.vault.models import VaultEntryCreate, VaultEntryUpdate
from khizex_pm.vault.service import VaultService


@pytest.fixture()
def service(tmp_path: Path) -> VaultService:
    storage = VaultStorage(tmp_path / "vault.db")
    return VaultService(storage)


def test_full_pipeline_create_unlock_crud_lock(service: VaultService):
    assert not service.is_initialized

    service.create_vault("correct-horse-battery-staple")
    assert service.is_initialized
    assert service.is_unlocked

    entry_id = service.add_entry(
        VaultEntryCreate(site="example.com", username="alice", password="hunter2", notes="test note")
    )

    metadata = service.list_entries()
    assert len(metadata) == 1
    assert metadata[0].site == "example.com"
    assert metadata[0].username == "alice"

    revealed = service.get_entry(entry_id)
    assert revealed.password == "hunter2"
    assert revealed.notes == "test note"

    service.update_entry(entry_id, VaultEntryUpdate(password="new-password"))
    assert service.get_entry(entry_id).password == "new-password"
    # Untouched fields survive a partial update.
    assert service.get_entry(entry_id).site == "example.com"

    service.delete_entry(entry_id)
    assert service.list_entries() == []

    service.lock()
    assert not service.is_unlocked


def test_cannot_create_vault_twice(service: VaultService):
    service.create_vault("master-password-1")
    with pytest.raises(VaultAlreadyExistsError):
        service.create_vault("master-password-2")


def test_unlock_requires_existing_vault(service: VaultService):
    with pytest.raises(VaultNotInitializedError):
        service.unlock("whatever")


def test_wrong_master_password_is_rejected(service: VaultService):
    service.create_vault("the-real-password")
    service.lock()
    with pytest.raises(VaultUnlockError):
        service.unlock("totally-wrong-password")
    assert not service.is_unlocked


def test_operations_require_unlocked_vault(service: VaultService):
    service.create_vault("pw")
    service.lock()
    with pytest.raises(VaultLockedError):
        service.add_entry(VaultEntryCreate(site="x.com", username="u", password="p"))
    with pytest.raises(VaultLockedError):
        service.list_entries()


def test_missing_entry_raises_not_found(service: VaultService):
    service.create_vault("pw")
    with pytest.raises(EntryNotFoundError):
        service.get_entry(999)
    with pytest.raises(EntryNotFoundError):
        service.delete_entry(999)


def test_master_password_change_rewraps_key_without_touching_entries(service: VaultService):
    service.create_vault("old-password")
    entry_id = service.add_entry(VaultEntryCreate(site="bank.com", username="bob", password="s3cr3t"))

    service.change_master_password("old-password", "new-password-123")

    # Old password no longer works.
    service.lock()
    with pytest.raises(VaultUnlockError):
        service.unlock("old-password")

    # New password works and the entry is unchanged.
    service.unlock("new-password-123")
    revealed = service.get_entry(entry_id)
    assert revealed.password == "s3cr3t"


def test_storage_file_contains_no_plaintext_secrets(tmp_path: Path):
    """Directly inspects the raw SQLite file bytes for plaintext leakage."""
    db_path = tmp_path / "vault.db"
    storage = VaultStorage(db_path)
    service = VaultService(storage)

    master_password = "S3cr3t-Master-Passw0rd!!"
    secret_password = "UniqueMarkerPlaintextPassword12345"

    service.create_vault(master_password)
    service.add_entry(VaultEntryCreate(site="example.com", username="alice", password=secret_password))
    storage.close()

    raw_bytes = db_path.read_bytes()
    assert master_password.encode("utf-8") not in raw_bytes
    assert secret_password.encode("utf-8") not in raw_bytes


def test_export_import_round_trip(tmp_path: Path):
    storage1 = VaultStorage(tmp_path / "vault1.db")
    service1 = VaultService(storage1)
    service1.create_vault("export-password")
    service1.add_entry(VaultEntryCreate(site="site-a.com", username="u1", password="p1"))
    service1.add_entry(VaultEntryCreate(site="site-b.com", username="u2", password="p2"))

    export_path = tmp_path / "backup.json"
    export_vault(storage1, export_path)

    # Backup file must be text JSON but contain no plaintext secrets.
    backup_text = export_path.read_text(encoding="utf-8")
    assert "export-password" not in backup_text
    assert "p1" not in backup_text
    assert "p2" not in backup_text

    storage2 = VaultStorage(tmp_path / "vault2.db")
    service2 = VaultService(storage2)
    imported_count = import_vault(storage2, export_path)
    assert imported_count == 2

    service2.unlock("export-password")
    entries = service2.list_entries()
    assert {e.site for e in entries} == {"site-a.com", "site-b.com"}
