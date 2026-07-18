from __future__ import annotations

import argparse
import getpass
import logging
import sys
from pathlib import Path

from pydantic import ValidationError

from khizex_pm.crypto.secure_random import generate_password
from khizex_pm.logging_config import configure_logging
from khizex_pm.session.autolock import AutoLockTimer
from khizex_pm.session.clipboard import ClipboardManager
from khizex_pm.storage.db import VaultStorage
from khizex_pm.vault.exceptions import (
    EntryNotFoundError,
    VaultAlreadyExistsError,
    VaultError,
    VaultLockedError,
    VaultNotInitializedError,
    VaultUnlockError,
)
from khizex_pm.vault.export_import import export_vault, import_vault
from khizex_pm.vault.models import (
    MasterPasswordChangeRequest,
    PasswordGenerationRequest,
    VaultEntryCreate,
    VaultEntryUpdate,
)
from khizex_pm.vault.service import VaultService

logger = logging.getLogger("khizex_pm.cli")

DEFAULT_VAULT_PATH = Path.home() / ".khizex_pm" / "vault.db"
DEFAULT_AUTOLOCK_SECONDS = 60.0
DEFAULT_CLIPBOARD_SECONDS = 20.0

HELP_TEXT = """
Available commands:
  create                  Create a new vault (first run only)
  unlock                  Unlock the vault with your master password
  lock                    Manually lock the vault right now
  add                     Add a new entry
  list                    List entries (site/username only, no passwords)
  get <id>                Reveal an entry and copy its password to the clipboard
  update <id>             Update an existing entry
  delete <id>             Delete an entry
  changepw                Change the master password
  genpw [length]          Generate a secure random password
  export <path>            Export an encrypted backup of the vault
  import <path>            Restore the vault from an encrypted backup
  status                  Show lock status and auto-lock countdown
  help                    Show this help text
  exit / quit             Exit the application
"""


class VaultCLI:
    def __init__(self, vault_path: Path) -> None:
        self._storage = VaultStorage(vault_path)
        self._service = VaultService(self._storage)
        self._clipboard = ClipboardManager(default_timeout_seconds=DEFAULT_CLIPBOARD_SECONDS)
        self._autolock = AutoLockTimer(
            timeout_seconds=DEFAULT_AUTOLOCK_SECONDS,
            on_timeout=self._on_autolock,
        )
        self._autolock.start()

    # ---- autolock callback -------------------------------------------

    def _on_autolock(self) -> None:
        if self._service.is_unlocked:
            self._service.lock()
            # Printing from a background thread interleaved with a
            # blocked input() prompt is a minor cosmetic issue only;
            # functionally the lock state itself is already enforced.
            print("\n[auto-lock] Vault was locked automatically due to inactivity.")

    # ---- main loop -----------------------------------------------------

    def run(self) -> None:
        print("Khizex Secure Local Password Manager")
        print(f"Vault file: {self._storage.db_path}")
        print("Type 'help' for a list of commands.\n")

        try:
            while True:
                try:
                    raw = input("khizex> ").strip()
                except (EOFError, KeyboardInterrupt):
                    print()
                    break

                if not raw:
                    continue

                self._autolock.reset_activity()
                parts = raw.split(maxsplit=1)
                command = parts[0].lower()
                arg = parts[1] if len(parts) > 1 else ""

                if command in ("exit", "quit"):
                    break

                self._dispatch(command, arg)
        finally:
            self._autolock.stop()
            self._service.lock()
            self._storage.close()
            print("Vault locked and closed. Goodbye.")

    def _dispatch(self, command: str, arg: str) -> None:
        handlers = {
            "help": self._cmd_help,
            "create": self._cmd_create,
            "unlock": self._cmd_unlock,
            "lock": self._cmd_lock,
            "add": self._cmd_add,
            "list": self._cmd_list,
            "get": self._cmd_get,
            "update": self._cmd_update,
            "delete": self._cmd_delete,
            "changepw": self._cmd_changepw,
            "genpw": self._cmd_genpw,
            "export": self._cmd_export,
            "import": self._cmd_import,
            "status": self._cmd_status,
        }
        handler = handlers.get(command)
        if handler is None:
            print(f"Unknown command: {command!r}. Type 'help' for a list of commands.")
            return
        try:
            handler(arg)
        except VaultLockedError:
            print("Vault is locked. Run 'unlock' first.")
        except VaultUnlockError:
            # Deliberately generic: covers both "wrong password" and
            # "corrupted vault data" without distinguishing them.
            print("Incorrect master password, or the vault data is invalid.")
        except VaultNotInitializedError:
            print("No vault exists yet. Run 'create' first.")
        except VaultAlreadyExistsError:
            print("A vault already exists. Use 'unlock' instead.")
        except EntryNotFoundError as exc:
            print(str(exc))
        except ValidationError as exc:
            print("Invalid input:")
            for err in exc.errors():
                loc = ".".join(str(p) for p in err["loc"])
                print(f"  - {loc}: {err['msg']}")
        except VaultError as exc:  # pragma: no cover - generic fallback
            print(f"Vault error: {exc}")
        except Exception:  # pragma: no cover - last-resort safety net
            logger.exception("Unexpected error handling command %r", command)
            print("An unexpected error occurred. See logs for details (no secrets are logged).")

    # ---- individual commands -------------------------------------------

    def _cmd_help(self, _arg: str) -> None:
        print(HELP_TEXT)

    def _cmd_create(self, _arg: str) -> None:
        if self._service.is_initialized:
            raise VaultAlreadyExistsError()
        pw1 = getpass.getpass("Choose a master password: ")
        pw2 = getpass.getpass("Confirm master password: ")
        if pw1 != pw2:
            print("Passwords do not match.")
            return
        if len(pw1) < 8:
            print("Master password should be at least 8 characters.")
            return
        self._service.create_vault(pw1)
        print("Vault created and unlocked.")

    def _cmd_unlock(self, _arg: str) -> None:
        pw = getpass.getpass("Master password: ")
        self._service.unlock(pw)
        print("Vault unlocked.")

    def _cmd_lock(self, _arg: str) -> None:
        self._service.lock()
        print("Vault locked.")

    def _cmd_add(self, _arg: str) -> None:
        site = input("Site/label: ").strip()
        username = input("Username: ").strip()
        use_generated = input("Generate a secure password? [Y/n]: ").strip().lower()
        if use_generated in ("", "y", "yes"):
            password = generate_password()
            print(f"Generated password: {password}")
        else:
            password = getpass.getpass("Password: ")
        notes = input("Notes (optional): ").strip()

        payload = VaultEntryCreate(site=site, username=username, password=password, notes=notes)
        entry_id = self._service.add_entry(payload)
        print(f"Entry added with id={entry_id}.")

    def _cmd_list(self, _arg: str) -> None:
        entries = self._service.list_entries()
        if not entries:
            print("(no entries yet)")
            return
        print(f"{'ID':<5}{'Site':<30}{'Username':<30}")
        print("-" * 65)
        for e in entries:
            print(f"{e.id:<5}{e.site[:29]:<30}{e.username[:29]:<30}")

    def _cmd_get(self, arg: str) -> None:
        entry_id = self._parse_id(arg)
        if entry_id is None:
            return
        entry = self._service.get_entry(entry_id)
        print(f"Site:     {entry.site}")
        print(f"Username: {entry.username}")
        print(f"Password: {entry.password}")
        if entry.notes:
            print(f"Notes:    {entry.notes}")
        copied = self._clipboard.copy_with_autoclear(entry.password)
        if copied:
            print(f"(password copied to clipboard, will auto-clear in {DEFAULT_CLIPBOARD_SECONDS:.0f}s)")
        else:
            print("(clipboard unavailable in this environment; password shown above only)")

    def _cmd_update(self, arg: str) -> None:
        entry_id = self._parse_id(arg)
        if entry_id is None:
            return
        print("Leave a field blank to keep its current value.")
        site = input("New site/label: ").strip() or None
        username = input("New username: ").strip() or None
        change_password = input("Change password? [y/N]: ").strip().lower() in ("y", "yes")
        password = getpass.getpass("New password: ") if change_password else None
        notes_raw = input("New notes (leave blank to keep current, type '-' to clear): ").strip()
        notes = None if notes_raw == "" else ("" if notes_raw == "-" else notes_raw)

        payload = VaultEntryUpdate(site=site, username=username, password=password, notes=notes)
        self._service.update_entry(entry_id, payload)
        print("Entry updated.")

    def _cmd_delete(self, arg: str) -> None:
        entry_id = self._parse_id(arg)
        if entry_id is None:
            return
        confirm = input(f"Delete entry {entry_id}? This cannot be undone. [y/N]: ").strip().lower()
        if confirm not in ("y", "yes"):
            print("Cancelled.")
            return
        self._service.delete_entry(entry_id)
        print("Entry deleted.")

    def _cmd_changepw(self, _arg: str) -> None:
        current = getpass.getpass("Current master password: ")
        new1 = getpass.getpass("New master password: ")
        new2 = getpass.getpass("Confirm new master password: ")
        if new1 != new2:
            print("New passwords do not match.")
            return
        request = MasterPasswordChangeRequest(current_master_password=current, new_master_password=new1)
        self._service.change_master_password(request.current_master_password, request.new_master_password)
        print("Master password changed successfully.")

    def _cmd_genpw(self, arg: str) -> None:
        length = 20
        if arg.strip():
            try:
                length = int(arg.strip())
            except ValueError:
                print("Length must be an integer.")
                return
        try:
            request = PasswordGenerationRequest(length=length)
        except ValidationError as exc:
            raise exc
        password = generate_password(
            length=request.length,
            use_lower=request.use_lower,
            use_upper=request.use_upper,
            use_digits=request.use_digits,
            use_symbols=request.use_symbols,
            exclude_ambiguous=request.exclude_ambiguous,
        )
        print(f"Generated password: {password}")

    def _cmd_export(self, arg: str) -> None:
        if not arg.strip():
            print("Usage: export <output-path>")
            return
        path = export_vault(self._storage, arg.strip())
        print(f"Encrypted vault backup written to {path}")
        print("(the export file contains only ciphertext, nonces, and salts -- never plaintext secrets)")

    def _cmd_import(self, arg: str) -> None:
        if not arg.strip():
            print("Usage: import <input-path>")
            return
        confirm = input("This will overwrite the current vault. Continue? [y/N]: ").strip().lower()
        if confirm not in ("y", "yes"):
            print("Cancelled.")
            return
        self._service.lock()
        count = import_vault(self._storage, arg.strip())
        print(f"Imported {count} entrie(s). Vault is locked -- unlock with the backup's master password.")

    def _cmd_status(self, _arg: str) -> None:
        if self._service.is_unlocked:
            remaining = self._autolock.seconds_until_lock()
            print(f"Status: UNLOCKED (auto-lock in ~{remaining:.0f}s of inactivity)")
        else:
            print("Status: LOCKED")

    @staticmethod
    def _parse_id(arg: str) -> int | None:
        if not arg.strip():
            print("Usage: <command> <id>")
            return None
        try:
            return int(arg.strip())
        except ValueError:
            print("Entry id must be an integer.")
            return None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Khizex Secure Local Password Manager")
    parser.add_argument(
        "--vault-path",
        type=Path,
        default=DEFAULT_VAULT_PATH,
        help=f"Path to the vault SQLite file (default: {DEFAULT_VAULT_PATH})",
    )
    parser.add_argument(
        "--log-dir",
        type=Path,
        default=Path("logs"),
        help="Directory for application logs (default: ./logs)",
    )
    args = parser.parse_args(argv)

    configure_logging(log_dir=args.log_dir)
    cli = VaultCLI(vault_path=args.vault_path)
    cli.run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
