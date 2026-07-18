

from __future__ import annotations

import logging
import threading

logger = logging.getLogger("khizex_pm.session.clipboard")

try:
    import pyperclip

    _PYPERCLIP_AVAILABLE = True
except ImportError:  # pragma: no cover - exercised only when dependency/backend missing
    _PYPERCLIP_AVAILABLE = False


class ClipboardManager:
    """Copies a secret to the clipboard and schedules a safe auto-clear."""

    def __init__(self, default_timeout_seconds: float = 20.0) -> None:
        self._default_timeout = default_timeout_seconds

    def is_available(self) -> bool:
        return _PYPERCLIP_AVAILABLE

    def copy_with_autoclear(self, value: str, timeout_seconds: float | None = None) -> bool:
        """Copy `value` to the clipboard; returns False if no backend is available.

        Spawns a daemon thread to perform the delayed clear so the
        caller (the CLI's main loop) returns immediately and stays
        responsive.
        """
        if not _PYPERCLIP_AVAILABLE:
            logger.warning("No clipboard backend available; skipping clipboard copy.")
            return False

        timeout = timeout_seconds if timeout_seconds is not None else self._default_timeout
        try:
            pyperclip.copy(value)
        except Exception:  # pragma: no cover - depends on host clipboard backend
            logger.exception("Failed to copy value to clipboard.")
            return False

        thread = threading.Thread(
            target=self._clear_after_delay,
            args=(value, timeout),
            name="clipboard-autoclear",
            daemon=True,
        )
        thread.start()
        return True

    @staticmethod
    def _clear_after_delay(expected_value: str, timeout_seconds: float) -> None:
        threading.Event().wait(timeout_seconds)  # background sleep; does not block caller
        try:
            current = pyperclip.paste()
        except Exception:  # pragma: no cover
            logger.exception("Failed to read clipboard for auto-clear check.")
            return

        if current == expected_value:
            try:
                pyperclip.copy("")
                logger.info("Clipboard auto-cleared after %.0fs.", timeout_seconds)
            except Exception:  # pragma: no cover
                logger.exception("Failed to clear clipboard.")
        else:
            logger.debug("Clipboard content changed since copy; skipping auto-clear.")
