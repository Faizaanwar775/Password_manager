from __future__ import annotations

import logging
import logging.handlers
import re
from pathlib import Path

_REDACT_PATTERNS = [
    re.compile(r"(password\s*=\s*)([^\s,}]+)", re.IGNORECASE),
    re.compile(r"(master_password\s*=\s*)([^\s,}]+)", re.IGNORECASE),
    re.compile(r"(vmk\s*=\s*)([^\s,}]+)", re.IGNORECASE),
    re.compile(r"(kek\s*=\s*)([^\s,}]+)", re.IGNORECASE),
]

class SecretRedactionFilter(logging.Filter):
    """Defense-in-depth: redacts anything that looks like a logged secret."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()
        except Exception:  # pragma: no cover - malformed record args
            return True

        redacted = message
        for pattern in _REDACT_PATTERNS:
            redacted = pattern.sub(r"\1[REDACTED]", redacted)

        if redacted != message:
            record.msg = redacted
            record.args = ()
        return True

def configure_logging(log_dir: str | Path = "logs", level: int = logging.INFO) -> None:
    """Configure console + rotating file logging for the whole application."""
    log_dir_path = Path(log_dir)
    log_dir_path.mkdir(parents=True, exist_ok=True)

    formatter = logging.Formatter(
        fmt="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)

    file_handler = logging.handlers.RotatingFileHandler(
        log_dir_path / "khizex_pm.log",
        maxBytes=1_000_000,
        backupCount=3,
        encoding="utf-8",
    )
    file_handler.setFormatter(formatter)

    root_logger = logging.getLogger("khizex_pm")
    root_logger.setLevel(level)
    root_logger.handlers.clear()
    root_logger.addFilter(SecretRedactionFilter())
    root_logger.addHandler(console_handler)
    root_logger.addHandler(file_handler)
    root_logger.propagate = False
