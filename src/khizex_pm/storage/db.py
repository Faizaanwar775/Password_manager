from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

from khizex_pm.storage.schemas import EncryptedRecord, EntryRecord, VaultMetaRecord

_SCHEMA = """
CREATE TABLE IF NOT EXISTS vault_meta (
    id INTEGER PRIMARY KEY CHECK (id = 1),  -- single-row table, one vault per file
    salt BLOB NOT NULL,
    kdf_algorithm TEXT NOT NULL,
    kdf_params_json TEXT NOT NULL,
    wrapped_vmk_nonce BLOB NOT NULL,
    wrapped_vmk_ciphertext BLOB NOT NULL,
    canary_nonce BLOB NOT NULL,
    canary_ciphertext BLOB NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS entries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    site TEXT NOT NULL,
    username TEXT NOT NULL,
    secret_nonce BLOB NOT NULL,
    secret_ciphertext BLOB NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
"""


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class VaultStorage:
    """Thin, synchronous SQLite access layer.

    A single `sqlite3.Connection` is reused; SQLite connections are not
    guaranteed thread-safe by default when shared across threads doing
    concurrent writes, so all storage calls in this application are
    routed through the vault service's single `threading.Lock` -- see
    `vault/service.py`.
    """

    def __init__(self, db_path: str | Path) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self._conn.execute("PRAGMA foreign_keys = ON;")
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    @contextmanager
    def _cursor(self) -> Iterator[sqlite3.Cursor]:
        cur = self._conn.cursor()
        try:
            yield cur
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise
        finally:
            cur.close()

    # ---- vault_meta -----------------------------------------------------

    def vault_meta_exists(self) -> bool:
        with self._cursor() as cur:
            cur.execute("SELECT 1 FROM vault_meta WHERE id = 1;")
            return cur.fetchone() is not None

    def save_vault_meta(self, meta: VaultMetaRecord) -> None:
        """Insert or replace the single vault_meta row."""
        with self._cursor() as cur:
            cur.execute(
                """
                INSERT INTO vault_meta (
                    id, salt, kdf_algorithm, kdf_params_json,
                    wrapped_vmk_nonce, wrapped_vmk_ciphertext,
                    canary_nonce, canary_ciphertext,
                    created_at, updated_at
                ) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    salt=excluded.salt,
                    kdf_algorithm=excluded.kdf_algorithm,
                    kdf_params_json=excluded.kdf_params_json,
                    wrapped_vmk_nonce=excluded.wrapped_vmk_nonce,
                    wrapped_vmk_ciphertext=excluded.wrapped_vmk_ciphertext,
                    canary_nonce=excluded.canary_nonce,
                    canary_ciphertext=excluded.canary_ciphertext,
                    updated_at=excluded.updated_at;
                """,
                (
                    meta.salt,
                    meta.kdf_algorithm,
                    json.dumps(meta.kdf_params),
                    meta.wrapped_vmk.nonce,
                    meta.wrapped_vmk.ciphertext,
                    meta.canary.nonce,
                    meta.canary.ciphertext,
                    meta.created_at.isoformat(),
                    meta.updated_at.isoformat(),
                ),
            )

    def load_vault_meta(self) -> VaultMetaRecord | None:
        with self._cursor() as cur:
            cur.execute(
                """
                SELECT salt, kdf_algorithm, kdf_params_json,
                       wrapped_vmk_nonce, wrapped_vmk_ciphertext,
                       canary_nonce, canary_ciphertext,
                       created_at, updated_at
                FROM vault_meta WHERE id = 1;
                """
            )
            row = cur.fetchone()
            if row is None:
                return None
            (
                salt,
                kdf_algorithm,
                kdf_params_json,
                wvmk_nonce,
                wvmk_ct,
                canary_nonce,
                canary_ct,
                created_at,
                updated_at,
            ) = row
            return VaultMetaRecord(
                salt=salt,
                kdf_algorithm=kdf_algorithm,
                kdf_params=json.loads(kdf_params_json),
                wrapped_vmk=EncryptedRecord(nonce=wvmk_nonce, ciphertext=wvmk_ct),
                canary=EncryptedRecord(nonce=canary_nonce, ciphertext=canary_ct),
                created_at=datetime.fromisoformat(created_at),
                updated_at=datetime.fromisoformat(updated_at),
            )

    # ---- entries ---------------------------------------------------------

    def insert_entry(self, site: str, username: str, secret: EncryptedRecord) -> int:
        now = _utcnow_iso()
        with self._cursor() as cur:
            cur.execute(
                """
                INSERT INTO entries (site, username, secret_nonce, secret_ciphertext, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?);
                """,
                (site, username, secret.nonce, secret.ciphertext, now, now),
            )
            return int(cur.lastrowid)

    def update_entry(self, entry_id: int, site: str, username: str, secret: EncryptedRecord) -> bool:
        now = _utcnow_iso()
        with self._cursor() as cur:
            cur.execute(
                """
                UPDATE entries
                SET site = ?, username = ?, secret_nonce = ?, secret_ciphertext = ?, updated_at = ?
                WHERE id = ?;
                """,
                (site, username, secret.nonce, secret.ciphertext, now, entry_id),
            )
            return cur.rowcount > 0

    def delete_entry(self, entry_id: int) -> bool:
        with self._cursor() as cur:
            cur.execute("DELETE FROM entries WHERE id = ?;", (entry_id,))
            return cur.rowcount > 0

    def get_entry(self, entry_id: int) -> EntryRecord | None:
        with self._cursor() as cur:
            cur.execute(
                """
                SELECT id, site, username, secret_nonce, secret_ciphertext, created_at, updated_at
                FROM entries WHERE id = ?;
                """,
                (entry_id,),
            )
            row = cur.fetchone()
            if row is None:
                return None
            return self._row_to_entry(row)

    def list_entries(self) -> list[EntryRecord]:
        with self._cursor() as cur:
            cur.execute(
                """
                SELECT id, site, username, secret_nonce, secret_ciphertext, created_at, updated_at
                FROM entries ORDER BY site COLLATE NOCASE ASC;
                """
            )
            return [self._row_to_entry(row) for row in cur.fetchall()]

    @staticmethod
    def _row_to_entry(row: tuple) -> EntryRecord:
        entry_id, site, username, secret_nonce, secret_ct, created_at, updated_at = row
        return EntryRecord(
            id=entry_id,
            site=site,
            username=username,
            secret=EncryptedRecord(nonce=secret_nonce, ciphertext=secret_ct),
            created_at=datetime.fromisoformat(created_at),
            updated_at=datetime.fromisoformat(updated_at),
        )
