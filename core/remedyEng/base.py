from __future__ import annotations

import copy
import difflib
import json
from abc import ABC, abstractmethod
from typing import Any


class BaseRemediation(ABC):
    """Abstract base strategy for a single CIS remediation rule."""

    rule_id: str = ""
    description: str = ""

    def __init__(self) -> None:
        self._before_state: Any | None = None
        self._after_state: Any | None = None

    @abstractmethod
    def check(self, config_json: Any) -> bool:
        """Return True when this rule is violated."""

    @abstractmethod
    def fix(self, config_json: Any) -> Any:
        """Return a remediated config JSON for this rule."""

    def snapshot(self, before_state: Any, after_state: Any) -> None:
        """Store deep-copied snapshots for safe dry-run and diff generation."""
        self._before_state = copy.deepcopy(before_state)
        self._after_state = copy.deepcopy(after_state)

    def get_diff(self) -> str:
        """Generate a unified diff between pre- and post-remediation states."""
        if self._before_state is None or self._after_state is None:
            return ""

        before_json = json.dumps(self._before_state, indent=2, ensure_ascii=False, sort_keys=True)
        after_json = json.dumps(self._after_state, indent=2, ensure_ascii=False, sort_keys=True)

        if before_json == after_json:
            return ""

        diff_lines = difflib.unified_diff(
            before_json.splitlines(),
            after_json.splitlines(),
            fromfile=f"before_{self.rule_id}",
            tofile=f"after_{self.rule_id}",
            lineterm="",
        )
        return "\n".join(diff_lines)
