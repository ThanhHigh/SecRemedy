from __future__ import annotations

import copy
import importlib.util
import inspect
import json
from pathlib import Path
from types import ModuleType
from typing import Any, Dict, Iterable, List, Type

try:
    from .base import BaseRemediation
    from .scan_result_remediation import ScanResultRemediator
except ImportError:  # pragma: no cover - support direct script execution
    from base import BaseRemediation
    from scan_result_remediation import ScanResultRemediator


class RemediationManager:
    """Discover and orchestrate rule-based remediations."""

    def __init__(self, rules_dir: str | None = None, dry_run: bool = True) -> None:
        default_rules_dir = Path(__file__).resolve().parent / "rules"
        self.rules_dir = Path(rules_dir) if rules_dir else default_rules_dir
        self.dry_run = dry_run
        self._registry: Dict[str, Type[BaseRemediation]] = {}
        self._last_backup: Any | None = None
        self.discover_rules()

    @property
    def available_rules(self) -> List[str]:
        return sorted(self._registry.keys())

    @property
    def last_backup(self) -> Any:
        """Return a deep-copied backup of the last input config."""
        return copy.deepcopy(self._last_backup)

    def discover_rules(self) -> None:
        """Auto-discover remediation strategy classes in the rules directory."""
        self._registry.clear()
        if not self.rules_dir.exists():
            return

        for file_path in sorted(self.rules_dir.glob("*.py")):
            if file_path.name.startswith("__"):
                continue
            module = self._load_module(file_path)
            if module is None:
                continue
            self._register_rule_classes(module)

    def run(
        self,
        config_json: Any,
        target_violations: Iterable[str | Dict[str, Any]],
        dry_run: bool | None = None,
    ) -> Dict[str, Any]:
        """Apply fixes for target violations and return execution details."""
        effective_dry_run = self.dry_run if dry_run is None else dry_run

        self._last_backup = copy.deepcopy(config_json)
        working_config = copy.deepcopy(config_json)

        rule_ids = self._normalize_rule_ids(target_violations)
        applied: List[str] = []
        skipped: List[str] = []
        diffs: Dict[str, str] = {}

        for rule_id in rule_ids:
            rule_cls = self._registry.get(rule_id)
            if rule_cls is None:
                skipped.append(rule_id)
                continue

            rule = rule_cls()
            if not rule.check(working_config):
                skipped.append(rule_id)
                continue

            before = copy.deepcopy(working_config)
            candidate = rule.fix(working_config)
            if candidate is not None:
                working_config = candidate
            rule.snapshot(before, working_config)

            applied.append(rule_id)
            rule_diff = rule.get_diff()
            if rule_diff:
                diffs[rule_id] = rule_diff

        if effective_dry_run:
            return {
                "dry_run": True,
                "backup_config": copy.deepcopy(self._last_backup),
                "preview_config": working_config,
                "applied_rules": applied,
                "skipped_rules": skipped,
                "diffs": diffs,
            }

        return {
            "dry_run": False,
            "backup_config": copy.deepcopy(self._last_backup),
            "modified_config": working_config,
            "applied_rules": applied,
            "skipped_rules": skipped,
            "diffs": diffs,
        }

    def _load_module(self, file_path: Path) -> ModuleType | None:
        module_name = f"remedy_rule_{file_path.stem}"
        spec = importlib.util.spec_from_file_location(module_name, str(file_path))
        if spec is None or spec.loader is None:
            return None

        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def _register_rule_classes(self, module: ModuleType) -> None:
        for _, cls in inspect.getmembers(module, inspect.isclass):
            if not issubclass(cls, BaseRemediation) or cls is BaseRemediation:
                continue

            if not getattr(cls, "rule_id", ""):
                continue

            self._registry[cls.rule_id] = cls

    @staticmethod
    def _normalize_rule_ids(target_violations: Iterable[str | Dict[str, Any]]) -> List[str]:
        normalized: List[str] = []
        for item in target_violations:
            if isinstance(item, str):
                normalized.append(item)
                continue
            if isinstance(item, dict) and item.get("rule_id"):
                normalized.append(str(item["rule_id"]))
        return normalized

    def run_from_scan_result(
        self,
        config_json: Any,
        scan_result_json: Any,
        target_rec_ids: List[str] | None = None,
        dry_run: bool | None = None,
    ) -> Dict[str, Any]:
        """Apply remediations from scan_result.json to config.
        
        Args:
            config_json: The parsed config structure
            scan_result_json: The scan_result.json content (dict or loaded from file)
            target_rec_ids: Optional list of recommendation IDs to apply.
                          If None, apply all.
            dry_run: Whether to apply in dry-run mode
        
        Returns:
            Result dict with applied remediations and modified config
        """
        effective_dry_run = self.dry_run if dry_run is None else dry_run
        
        self._last_backup = copy.deepcopy(config_json)
        
        remeditor = ScanResultRemediator()
        result = remeditor.apply_all_recommendations(
            config_json, scan_result_json, target_rec_ids
        )
        
        modified_config = result["config"]
        
        if effective_dry_run:
            return {
                "dry_run": True,
                "backup_config": copy.deepcopy(self._last_backup),
                "preview_config": modified_config,
                "applied_remediations": result["total_applied"],
                "failed_remediations": result["total_failed"],
                "diffs": result["diffs"],
                "errors": result.get("errors", []),
            }
        
        return {
            "dry_run": False,
            "backup_config": copy.deepcopy(self._last_backup),
            "modified_config": modified_config,
            "applied_remediations": result["total_applied"],
            "failed_remediations": result["total_failed"],
            "diffs": result["diffs"],
            "errors": result.get("errors", []),
        }

    @staticmethod
    def load_scan_result(path: Path) -> Dict[str, Any]:
        """Load scan_result.json file."""
        with path.open("r", encoding="utf-8") as f:
            return json.load(f)
