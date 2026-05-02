"""Development debug logger for remedyEng.

This logger is intentionally separate from TerminalUI and standard logs.
Enable via runtime config (CLI flags) and write to file + optional stderr.
"""
from __future__ import annotations

import datetime
import json
import sys
from typing import Any

# Levels: 1=INFO,2=VERBOSE,3=TRACE
_LEVELS = {"INFO": 1, "VERBOSE": 2, "TRACE": 3}

_enabled = False
_level = _LEVELS["INFO"]
_file_path: str | None = None
_to_stderr = False


def configure(enabled: bool = False, level: str = "INFO", file_path: str | None = None, to_stderr: bool = False) -> None:
    global _enabled, _level, _file_path, _to_stderr
    _enabled = bool(enabled)
    lvl = (level or "INFO").strip().upper()
    _level = _LEVELS.get(lvl, _LEVELS["INFO"])
    _file_path = file_path
    _to_stderr = bool(to_stderr)


def enabled() -> bool:
    return _enabled


def _write_line(line: str) -> None:
    # Best-effort write to file and optionally stderr; swallow exceptions
    try:
        if _file_path:
            with open(_file_path, "a", encoding="utf-8") as f:
                f.write(line + "\n")
    except Exception:
        pass

    if _to_stderr:
        try:
            sys.stderr.write(line + "\n")
        except Exception:
            pass


def _format(level_name: str, category: str, message: str, meta: Any = None) -> str:
    ts = datetime.datetime.utcnow().isoformat(timespec="milliseconds") + "Z"
    payload = {
        "ts": ts,
        "level": level_name,
        "category": category,
        "message": message,
    }
    if meta:
        try:
            payload["meta"] = meta
        except Exception:
            payload["meta"] = str(meta)
    try:
        return json.dumps(payload, ensure_ascii=False)
    except Exception:
        return f"[{ts}] [{level_name}] [{category}] {message}"


def log(level: str, category: str, message: str, meta: Any = None) -> None:
    if not _enabled:
        return
    name = (level or "INFO").strip().upper()
    if _LEVELS.get(name, 0) > _level:
        return
    line = _format(name, category, message, meta)
    _write_line(line)


def info(category: str, message: str, meta: Any = None) -> None:
    log("INFO", category, message, meta)


def verbose(category: str, message: str, meta: Any = None) -> None:
    log("VERBOSE", category, message, meta)


def trace(category: str, message: str, meta: Any = None) -> None:
    log("TRACE", category, message, meta)
