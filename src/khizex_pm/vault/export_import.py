from __future__ import annotations

import json
from pathlib import Path

from khizex_pm.storage.db import VaultStorage
from khizex_pm.storage.schemas import VaultExportFile
from khizex_pm.vault.exceptions import VaultNotInitializedError


def export_vault(storage: VaultStorage, output_path: str | Path) -> Path:
    """Write an encrypted backup of the entire vault to `output_path`."""
    meta = storage.load_vault_meta()
    if meta is None:
        raise VaultNotInitializedError("No vault exists yet; nothing to export.")

    entries = storage.list_entries()
    export = VaultExportFile(vault_meta=meta, entries=entries)

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(export.model_dump_json(indent=2), encoding="utf-8")
    return output_path


def import_vault(storage: VaultStorage, input_path: str | Path) -> int:
    
    input_path = Path(input_path)
    data = json.loads(input_path.read_text(encoding="utf-8"))
    export = VaultExportFile.model_validate(data)

    storage.save_vault_meta(export.vault_meta)
    imported = 0
    for entry in export.entries:
        storage.insert_entry(site=entry.site, username=entry.username, secret=entry.secret)
        imported += 1
    return imported
