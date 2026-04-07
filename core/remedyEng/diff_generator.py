"""Diff helpers for remediation review."""

from __future__ import annotations

import difflib
import json
from typing import Any


def generate_unified_diff(before_text: str, after_text: str, file_path: str) -> str:
    """Generate a unified text diff for a single file."""
    before_lines = before_text.splitlines()
    after_lines = after_text.splitlines()

    if before_lines == after_lines:
        return ""

    diff_lines = difflib.unified_diff(
        before_lines,
        after_lines,
        fromfile=f"a/{file_path}",
        tofile=f"b/{file_path}",
        lineterm="",
    )
    return "\n".join(diff_lines)


def generate_ast_fallback_diff(before_ast: Any, after_ast: Any, file_path: str) -> str:
    """Generate a readable fallback diff when config rendering is unavailable."""
    before_text = json.dumps(before_ast, indent=2, sort_keys=True)
    after_text = json.dumps(after_ast, indent=2, sort_keys=True)
    return generate_unified_diff(before_text, after_text, f"{file_path} (AST fallback)")
