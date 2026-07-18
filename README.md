# Khizex Secure Local Password Manager

A fully local, encrypted password manager built for **Khizex Python Engineering Internship — Assignment 02**.

No network calls are ever made. Everything lives in a single SQLite file on disk, protected by a master password that is never stored anywhere.

---

## 1. Project layout

```
khizex_password_manager/
├── main.py                     # entry point: python main.py
├── requirements.txt
├── pyproject.toml
├── src/khizex_pm/
│   ├── crypto/                 # KDF, AEAD encryption, secure randomness — zero UI/storage knowledge
│   │   ├── kdf.py              # Argon2id (preferred) / PBKDF2-HMAC-SHA256
│   │   ├── aead.py             # AES-256-GCM authenticated encryption
│   │   ├── secure_random.py    # salts, nonces, keys, password generation (secrets, not random)
│   │   └── memory.py           # best-effort in-memory zeroization
│   ├── vault/                  # entry CRUD, lock/unlock state, master-password change
│   │   ├── service.py          # the ONLY place that holds a derived key / plaintext secret
│   │   ├── models.py           # Pydantic models — CLI/API boundary
│   │   ├── exceptions.py
│   │   └── export_import.py    # encrypted backup / restore
│   ├── storage/                # SQLite access — knows only ciphertext/nonces/salts/metadata
│   │   ├── db.py
│   │   └── schemas.py          # Pydantic models — storage boundary
│   ├── session/                # background auto-lock + clipboard auto-clear
│   │   ├── autolock.py
│   │   └── clipboard.py
│   ├── cli/app.py              # thin interactive CLI — no crypto logic
│   └── logging_config.py       # logging that never logs secrets
└── tests/
    ├── test_crypto.py          # crypto layer, isolated
    └── test_vault.py           # full pipeline, incl. a raw-file plaintext-leak check
```

---

## 2. Setup

```bash
# from the project root
python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

`argon2-cffi` and `pyperclip` are optional at import time: if `argon2-cffi` is missing, the app automatically falls back to PBKDF2-HMAC-SHA256; if no clipboard backend is available (e.g. a headless Linux box with no `xclip`/`xsel`), clipboard copy is skipped gracefully and the password is still printed to the terminal. Installing both from `requirements.txt` gives you the full experience.

Run the app:

```bash
python main.py
# or, with a custom vault location:
python main.py --vault-path /path/to/vault.db
```

Run the tests:

```bash
pytest
```

> **Note on this submission's test verification:** the code was written and syntax-checked (`python -m py_compile` on every file) in the delivery environment, and the crypto primitives (KDF determinism, AES-GCM round-trip, nonce uniqueness, tamper detection) were smoke-tested directly against the installed `cryptography` library. The sandbox used to build this had no internet access to `pip install` `pydantic`/`argon2-cffi`/`pyperclip`, so the full `pytest` suite (which exercises the Pydantic-validated vault/storage layers end to end, including `test_storage_file_contains_no_plaintext_secrets`) should be run once in your own environment with `pip install -r requirements.txt && pytest` to get a complete green run before you submit.

---

## 3. Using the CLI

On first run:

```
khizex> create
Choose a master password: ********
Confirm master password: ********
Vault created and unlocked.
```

Everyday use:

```
khizex> add                     # add a new entry (offers to auto-generate a password)
khizex> list                    # site/username only — never shows passwords
khizex> get 1                   # reveals entry 1 and copies its password to the clipboard
khizex> update 1                # change site/username/password/notes
khizex> delete 1
khizex> changepw                # rotate the master password
khizex> genpw 24                # generate a standalone secure password
khizex> export backup.json      # write an encrypted backup
khizex> import backup.json      # restore from an encrypted backup
khizex> lock                    # manually lock right now
khizex> unlock                  # unlock again
khizex> status                  # show lock state + auto-lock countdown
khizex> exit
```

Locking (manual or automatic) immediately zeroizes the in-memory vault key; any command that needs the vault unlocked will ask you to `unlock` again.

---

## 4. Cryptographic design

### 4.1 Envelope encryption, not "one key encrypts everything directly"

```
master password + per-vault salt --[KDF]--> KEK  (key-encryption-key, never stored)
KEK encrypts a random 256-bit VMK              (vault master key, wrapped in vault_meta)
VMK encrypts each entry's (password, notes)     (fresh nonce every time)
```

This is the same pattern used by production password managers (1Password, Bitwarden). The benefit that matters most for this spec: **changing the master password only re-derives a new KEK and re-wraps the existing VMK** — no entry ciphertext is ever touched, so plaintext entries are never exposed outside memory during a password change (`vault/service.py::change_master_password`), and the operation's cost doesn't scale with vault size.

### 4.2 Key derivation

- **Preferred:** Argon2id via `argon2-cffi`, params `time_cost=3`, `memory_cost=65536 KiB (64 MiB)`, `parallelism=4` — the OWASP-recommended baseline for interactive logins. Memory-hardness is the key property here: it makes large-scale GPU/ASIC brute-forcing dramatically more expensive than a purely CPU-bound KDF.
- **Fallback:** PBKDF2-HMAC-SHA256, 600,000 iterations (current OWASP Password Storage Cheat Sheet recommendation), used automatically if `argon2-cffi` isn't installed.
- Both target **roughly 200–500ms** of derivation time on typical 2020s consumer hardware — slow enough to meaningfully throttle offline brute-force, fast enough not to annoy a user unlocking their own vault.
- Salt: 16 random bytes (`secrets.token_bytes`) per vault, stored alongside the vault metadata. A fresh salt is also generated on every master-password change.
- **Honest limitation:** *master password strength is the ultimate ceiling on vault security.* No KDF cost parameter can fully compensate for a weak, guessable master password — Argon2id/PBKDF2 slow down each guess, they don't make a weak password strong.

### 4.3 Encryption

- **AES-256-GCM** (an AEAD cipher) via the `cryptography` library — audited, not hand-rolled.
- A **fresh, randomly generated 96-bit nonce for every single encryption call** (`crypto/aead.py::encrypt` always generates its own nonce internally — there is no code path that lets a caller supply or reuse one), stored alongside the ciphertext. Nonce reuse under the same key is the one mistake that breaks GCM catastrophically, so the API is structured to make it impossible to forget.
- Tampering is detected, not silently ignored: a modified ciphertext or auth tag raises `DecryptionError` rather than returning garbage plaintext (`tests/test_crypto.py::test_aead_tampered_ciphertext_fails_to_decrypt`).

### 4.4 Unlock verification without storing a password hash

Instead of storing a separate password hash, vault creation encrypts a fixed known plaintext ("canary") under the derived KEK. Unlocking re-derives the KEK and attempts to decrypt the canary; AES-GCM's authentication tag will only verify if the KEK is correct. A failed canary decryption and a failed VMK-unwrap decryption both surface as the exact same generic error (`VaultUnlockError` → "incorrect master password or corrupted vault data") — the app deliberately does not tell you *which* one failed, so a wrong password can't be distinguished from a corrupted/tampered vault file by an attacker probing it.

### 4.5 Password generation

`crypto/secure_random.py::generate_password` uses `secrets.choice`/`secrets.randbelow` exclusively (never the `random` module), supports configurable length and character classes, guarantees at least one character from each enabled class, and optionally excludes visually ambiguous characters (`Il1O0`).

---

## 5. Auto-lock, session & clipboard safety

### 5.1 Auto-lock (`session/autolock.py`)

- Runs on a **daemon `threading.Thread`**, entirely off the main CLI loop. It polls every second (configurable) rather than doing one long `sleep(timeout)`, which is what lets an activity reset immediately postpone the lock.
- On timeout, it calls back into the CLI, which calls `VaultService.lock()` — this **zeroizes the in-memory VMK** (overwrites the bytearray) and flips the locked flag.
- Default timeout: 60 seconds of inactivity (configurable in `cli/app.py`).

### 5.2 Clipboard auto-clear (`session/clipboard.py`)

- Copying a revealed password spawns a **separate daemon thread** that sleeps in the background (never blocking the CLI) for a configurable window (default 20s), then checks whether the clipboard **still contains the exact value it copied** before clearing it — so if you've since copied something else, the auto-clear correctly does nothing.
- Uses `pyperclip`; if no clipboard backend exists in the environment, the copy is skipped with a clear message instead of crashing.

### 5.3 Race conditions between the timer thread and the main thread

Two threads can touch vault lock state:

1. The auto-lock background thread, when the inactivity timeout elapses.
2. The main thread, handling a user command (which resets the activity timestamp, or explicitly locks/unlocks).

Both paths are funneled through **one `threading.RLock`** owned by `VaultService` (`_state_lock`). Every state-changing method (`create_vault`, `unlock`, `lock`, `change_master_password`) acquires this lock for its full critical section, so a lock-triggered-by-timeout can never interleave with, say, an in-progress `unlock()` call and leave the VMK in an inconsistent state. `AutoLockTimer` additionally uses its own small `threading.Lock` purely to protect its own `_last_activity` timestamp from concurrent read (by the timer thread) and write (by `reset_activity()`, called from the main thread on every command) — this is a separate, narrower lock so the timer's polling loop never has to hold the vault's own state lock.

### 5.4 Main-loop responsiveness

The CLI's `input()` call does block the main thread while it waits for the next keystroke — an accepted characteristic of a synchronous terminal REPL. Critically, this does **not** stop the auto-lock or clipboard-clear timers, since they run on independent daemon threads with their own sleep/poll loops. If the auto-lock fires while the user is away from the keyboard, the vault is already locked and the VMK already zeroized by the time the user's next command is submitted — the CLI checks lock state on every dispatched command, so the "away" period is enforced retroactively and correctly, not just cosmetically.

---

## 6. Secure storage & type safety

- The SQLite file (`storage/db.py`) only ever contains: a salt, KDF algorithm/params, a wrapped VMK (nonce + ciphertext), an unlock canary (nonce + ciphertext), and per-entry `site`/`username` (plaintext metadata, by design — see below) plus each entry's encrypted `(password, notes)` blob (nonce + ciphertext) and timestamps. **No plaintext password, master password, or derived key is ever written to disk, logs, or export files.**
- **Design decision — why `site`/`username` are plaintext columns:** the spec requires listing entries by site/username *without* revealing passwords when just browsing. Keeping `site`/`username` as plaintext SQLite columns lets `list_entries()` work without touching the AEAD layer at all, while `password` and `notes` — the actual sensitive payload — are always encrypted under the VMK with a fresh nonce, whether you're adding, updating, or exporting an entry.
- Export/import (`vault/export_import.py`) serializes the *same* ciphertext/nonce/salt structures to JSON (base64-encoding the `bytes` fields) — nothing is ever decrypted for export, so a restored backup is exactly as encrypted as the live vault.
- Every structure crossing a functional boundary is a **Pydantic model with real validation** (`extra="forbid"`, length bounds, control-character rejection), not a decorative type hint: `VaultEntryCreate`/`VaultEntryUpdate`/`PasswordGenerationRequest`/`MasterPasswordChangeRequest` (CLI → vault service) and `EncryptedRecord`/`VaultMetaRecord`/`EntryRecord`/`VaultExportFile` (vault service → storage/export).
- Type hints are used consistently throughout (`from __future__ import annotations` + full parameter/return annotations). The few places using a broad type (e.g. `dict` for KDF params) are documented inline as intentional, since KDF parameter shapes differ slightly between algorithms.

### Verifying no plaintext ever hits disk

`tests/test_vault.py::test_storage_file_contains_no_plaintext_secrets` creates a vault with a distinctive master password and a distinctive stored password, then reads the **raw bytes** of the SQLite file directly and asserts neither string appears anywhere in it. You can do the same manually:

```bash
python main.py --vault-path /tmp/demo_vault.db
# ... create a vault, add an entry with a memorable password, exit ...
strings /tmp/demo_vault.db | grep -i "your-memorable-password"   # should print nothing
xxd /tmp/demo_vault.db | less                                     # should show only opaque bytes
```

---

## 7. Error handling

- A wrong master password and a corrupted/tampered vault file both surface the same generic message (`VaultUnlockError`) — never a traceback, never a distinguishing detail.
- A missing entry ID (`EntryNotFoundError`), a locked vault (`VaultLockedError`), and invalid Pydantic input (`ValidationError`, with field-level messages) are all caught in `cli/app.py::_dispatch` and shown as friendly one-line messages.
- Any genuinely unexpected exception is caught by a last-resort handler that logs the full traceback (to the rotating file log, never to a place a shoulder-surfer would see) and shows the user a generic "see logs" message — the app never crashes to a raw Python traceback.

## 8. Logging

`logging_config.py` sets up a console handler and a rotating file handler (`logs/khizex_pm.log`, 1MB × 3 backups). The actual guarantee against logging secrets is architectural: `crypto/`, `vault/service.py`, and `storage/` simply never pass a password/key into a `logger.*()` call. A `SecretRedactionFilter` is layered on top as defense-in-depth, scrubbing anything that looks like `password=...`/`master_password=...`/`vmk=...`/`kek=...` from any log line that slips through.

## 9. Sample Pydantic models

See `src/khizex_pm/vault/models.py` (CLI/API boundary: `VaultEntryCreate`, `VaultEntryUpdate`, `VaultEntryMetadata`, `VaultEntryRevealed`, `PasswordGenerationRequest`, `MasterPasswordChangeRequest`) and `src/khizex_pm/storage/schemas.py` (storage boundary: `EncryptedRecord`, `VaultMetaRecord`, `EntryRecord`, `VaultExportFile`).

## 10. Demo checklist (for your screen recording)

1. `python main.py` → `create` → set a master password → vault created.
2. `add` → add one entry, accept the generated password.
3. `get 1` → reveal it, show the clipboard auto-clear message.
4. Sit idle past the auto-lock timeout (default 60s) → show the `[auto-lock]` message firing on its own.
5. `unlock` with a **wrong** password → show the generic rejection message.
6. `unlock` with the correct password → `list` → show the entry is intact.
