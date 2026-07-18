from __future__ import annotations

import logging
import threading
import time
from typing import Callable

logger = logging.getLogger("khizex_pm.session.autolock")


class AutoLockTimer:
    """Locks the vault after a configurable period of inactivity."""

    def __init__(
        self,
        timeout_seconds: float,
        on_timeout: Callable[[], None],
        poll_interval_seconds: float = 1.0,
    ) -> None:
        self._timeout_seconds = timeout_seconds
        self._on_timeout = on_timeout
        self._poll_interval = poll_interval_seconds

        self._activity_lock = threading.Lock()
        self._last_activity = time.monotonic()

        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop_event.clear()
        self.reset_activity()
        self._thread = threading.Thread(target=self._run, name="autolock-timer", daemon=True)
        self._thread.start()
        logger.debug("Auto-lock timer started (timeout=%.1fs).", self._timeout_seconds)

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=self._poll_interval * 2)
        logger.debug("Auto-lock timer stopped.")

    def reset_activity(self) -> None:
        """Call this on every user action to postpone the auto-lock."""
        with self._activity_lock:
            self._last_activity = time.monotonic()

    def seconds_until_lock(self) -> float:
        with self._activity_lock:
            elapsed = time.monotonic() - self._last_activity
        return max(0.0, self._timeout_seconds - elapsed)

    def _run(self) -> None:
        while not self._stop_event.is_set():
            if self.seconds_until_lock() <= 0:
                logger.info("Inactivity timeout reached; auto-locking vault.")
                try:
                    self._on_timeout()
                except Exception:  # pragma: no cover - defensive; never crash the timer thread
                    logger.exception("Error while auto-locking the vault.")
                # Reset so we don't fire repeatedly every poll interval
                # while the vault remains locked/idle.
                self.reset_activity()
            # Wait in short increments so `stop()` is responsive.
            self._stop_event.wait(self._poll_interval)
