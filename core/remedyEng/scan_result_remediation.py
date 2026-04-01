"""Handler for remediations defined in scan_result.json."""

from __future__ import annotations

import copy
import json
from typing import Any, Dict, List

try:
    from .ast_navigator import ASTNavigator
except ImportError:  # pragma: no cover - support direct script execution
    from ast_navigator import ASTNavigator


class ScanResultRemediator:
    """Apply remediations from scan_result.json to config files."""

    def __init__(self, debug: bool = True) -> None:
        self._before_state: Any | None = None
        self._after_state: Any | None = None
        self.debug = debug
        self.errors: List[str] = []

    def _debug(self, msg: str) -> None:
        """Print debug message."""
        if self.debug:
            print(f"[DEBUG] {msg}")

    def apply_remediation(
        self,
        config_json: Any,
        file_path: str,
        remediation: Dict[str, Any],
    ) -> tuple[bool, Any]:
        """
        Apply a single remediation instruction to the config.
        
        Args:
            config_json: The parsed config structure (could be wrapped or extracted)
            file_path: The file path from the uncompliance (for reference)
            remediation: The remediation dict with action, context, directive, args
        
        Returns:
            Tuple of (success: bool, modified_config: Any)
        """
        config = copy.deepcopy(config_json)
        action = remediation.get("action", "").lower()
        context = remediation.get("context", [])
        directive = remediation.get("directive", "")
        args = remediation.get("args", [])

        self._debug(f"Applying remediation: action={action}, directive={directive}, file={file_path}")
        self._debug(f"Original context: {context}")

        # Adjust context if it starts with "config" but we have an extracted config
        # (i.e., the loaded config is already config[0], not the full wrapper)
        if context and context[0] == "config" and isinstance(config, dict) and "parsed" in config:
            # If config has "parsed" field directly, it's already extracted
            # Remove "config", 0 prefix from context
            adjusted_context = context[2:] if len(context) > 2 else context[1:]
            self._debug(f"Adjusted context (removed 'config', 0): {adjusted_context}")
            context = adjusted_context
        
        self._debug(f"Final context to navigate: {context}")

        # Try to navigate to target and debug what we find
        target = ASTNavigator.get_by_context(config, context)
        if target is None:
            error_msg = f"Failed to navigate to context {context} - target is None (path doesn't exist)"
            self._debug(f"ERROR: {error_msg}")
            self.errors.append(f"{file_path}: {error_msg}")
            return False, config
        
        self._debug(f"Target found, type: {type(target).__name__}, content preview: {str(target)[:100]}")

        if action == "replace":
            return self._apply_replace(config, context, directive, args)
        elif action == "add":
            return self._apply_add(config, context, directive, args)
        else:
            error_msg = f"Unknown action: {action}"
            self._debug(f"ERROR: {error_msg}")
            self.errors.append(f"{file_path}: {error_msg}")
            return False, config

    def _apply_replace(
        self,
        config: Any,
        context: List[int | str],
        directive: str,
        args: Any,
    ) -> tuple[bool, Any]:
        """Replace a directive's args at the given context."""
        target = ASTNavigator.get_by_context(config, context)
        if target is None:
            self._debug(f"REPLACE failed: Cannot navigate to context {context}")
            return False, config

        if isinstance(target, dict):
            # Single directive case
            if target.get("directive") == directive:
                self._debug(f"REPLACE: Found {directive} in dict, updating args")
                target["args"] = copy.deepcopy(args)
                return True, config
            else:
                self._debug(f"REPLACE failed: Target is dict but directive mismatch. Expected '{directive}', got '{target.get('directive')}'")
                return False, config
        elif isinstance(target, list):
            # List of directives case - find and replace
            for i, item in enumerate(target):
                if isinstance(item, dict) and item.get("directive") == directive:
                    self._debug(f"REPLACE: Found {directive} at index {i} in list, updating args")
                    item["args"] = copy.deepcopy(args)
                    return True, config
            self._debug(f"REPLACE failed: Directive '{directive}' not found in list")
            return False, config
        else:
            self._debug(f"REPLACE failed: Target is {type(target).__name__}, expected dict or list")
            return False, config

    def _apply_add(
        self,
        config: Any,
        context: List[int | str],
        directive: str,
        args: Any,
    ) -> tuple[bool, Any]:
        """Add a new directive/block at the given context."""
        target = ASTNavigator.get_by_context(config, context)
        if target is None:
            self._debug(f"ADD failed: Cannot navigate to context {context}")
            return False, config

        if isinstance(target, list):
            # Add to a list at context
            new_item = {"directive": directive, "args": copy.deepcopy(args)}
            self._debug(f"ADD: Appending new {directive} to list at context {context}")
            target.append(new_item)
            return True, config
        else:
            self._debug(f"ADD failed: Target is {type(target).__name__} at context {context}, expected list. Cannot append.")
            return False, config

    def apply_recommendation(
        self,
        config_json: Any,
        recommendation: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Apply all remediations for a single recommendation.
        
        Args:
            config_json: The parsed config structure
            recommendation: The recommendation dict from scan_result.json
        
        Returns:
            Dict with success status, applied steps, and modified config
        """
        result_config = copy.deepcopy(config_json)
        applied_count = 0
        failed_count = 0

        for uncompliance in recommendation.get("uncompliances", []):
            file_path = uncompliance.get("file", "")
            for remediation in uncompliance.get("remediations", []):
                success, result_config = self.apply_remediation(
                    result_config, file_path, remediation
                )
                if success:
                    applied_count += 1
                else:
                    failed_count += 1

        return {
            "applied": applied_count,
            "failed": failed_count,
            "config": result_config,
        }

    def apply_all_recommendations(
        self,
        config_json: Any,
        scan_result: Dict[str, Any],
        target_rec_ids: List[str] | None = None,
    ) -> Dict[str, Any]:
        """
        Apply all recommendations from scan_result to config.
        
        Args:
            config_json: The parsed config structure
            scan_result: The scan_result.json content
            target_rec_ids: Optional list of recommendation IDs to apply.
                          If None, apply all.
        
        Returns:
            Dict with applied/failed counts, diffs, and final config
        """
        self._before_state = copy.deepcopy(config_json)
        self.errors = []
        working_config = copy.deepcopy(config_json)

        total_applied = 0
        total_failed = 0
        diffs: Dict[str, str] = {}

        for rec in scan_result.get("recommendations", []):
            rec_id = rec.get("id", "")
            
            if target_rec_ids and rec_id not in target_rec_ids:
                continue

            self._debug(f"\n--- Processing recommendation {rec_id} ---")
            before = copy.deepcopy(working_config)
            result = self.apply_recommendation(working_config, rec)
            
            working_config = result["config"]
            total_applied += result["applied"]
            total_failed += result["failed"]

            # Generate diff for this recommendation if changed
            if before != working_config:
                diff = self._generate_diff(before, working_config, rec_id)
                if diff:
                    diffs[rec_id] = diff

        self._after_state = copy.deepcopy(working_config)

        return {
            "total_applied": total_applied,
            "total_failed": total_failed,
            "config": working_config,
            "diffs": diffs,
            "errors": self.errors,
        }

    def _generate_diff(self, before: Any, after: Any, label: str) -> str:
        """Generate a unified diff string."""
        import difflib

        before_json = json.dumps(before, indent=2, ensure_ascii=False, sort_keys=True)
        after_json = json.dumps(after, indent=2, ensure_ascii=False, sort_keys=True)

        if before_json == after_json:
            return ""

        diff_lines = difflib.unified_diff(
            before_json.splitlines(),
            after_json.splitlines(),
            fromfile=f"before_{label}",
            tofile=f"after_{label}",
            lineterm="",
        )
        return "\n".join(diff_lines)

    def get_before_state(self) -> Any:
        """Get the state before any remediations."""
        return copy.deepcopy(self._before_state) if self._before_state else None

    def get_after_state(self) -> Any:
        """Get the state after remediations."""
        return copy.deepcopy(self._after_state) if self._after_state else None
