from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List, Tuple

try:
    from .manager import RemediationManager
except ImportError:  # pragma: no cover - support direct script execution
    from manager import RemediationManager


def _parse_rules(rules_arg: str | None) -> List[str]:
    if not rules_arg:
        return []
    return [item.strip() for item in rules_arg.split(",") if item.strip()]


def _load_input(path: Path) -> Tuple[Any, bool]:
    with path.open("r", encoding="utf-8") as f:
        raw = json.load(f)

    # Accept crossplane contract shape: {"config": [{...}]}
    if isinstance(raw, dict) and isinstance(raw.get("config"), list) and raw["config"]:
        first_item = raw["config"][0]
        if isinstance(first_item, dict):
            return first_item, True

    # Accept direct single-config JSON shape: {"parsed": [...]} or parsed list itself
    return raw, False


def _build_default_output_path(input_path: Path, dry_run: bool) -> Path:
    suffix = "_preview" if dry_run else "_remediated"
    return input_path.with_name(f"{input_path.stem}{suffix}.json")


def _print_summary(result: Dict[str, Any]) -> None:
    print(f"dry_run={result['dry_run']}")
    print(f"applied_rules={result['applied_rules']}")
    print(f"skipped_rules={result['skipped_rules']}")

    if result.get("diffs"):
        print("diff_rules=")
        for rule_id in sorted(result["diffs"].keys()):
            print(f"- {rule_id}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Run plugin-based Nginx remediation rules")
    parser.add_argument("--input", required=True, help="Input JSON path (crossplane parsed result)")
    parser.add_argument("--rules", required=True, help="Comma-separated rule IDs, e.g. CIS-2.1.1")
    parser.add_argument("--dry-run", action="store_true", help="Preview changes without applying live output")
    parser.add_argument("--output", help="Optional output JSON path")
    parser.add_argument("--rules-dir", help="Optional custom rules directory")

    args = parser.parse_args()

    input_path = Path(args.input).expanduser().resolve()
    if not input_path.exists():
        raise FileNotFoundError(f"Input not found: {input_path}")

    target_rules = _parse_rules(args.rules)
    if not target_rules:
        raise ValueError("No valid rule IDs provided via --rules")

    config_json, _ = _load_input(input_path)

    manager = RemediationManager(rules_dir=args.rules_dir, dry_run=args.dry_run)
    result = manager.run(config_json, target_rules)

    output_key = "preview_config" if result["dry_run"] else "modified_config"
    output_payload = result[output_key]

    output_path = Path(args.output).expanduser().resolve() if args.output else _build_default_output_path(input_path, args.dry_run)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with output_path.open("w", encoding="utf-8") as f:
        json.dump(output_payload, f, indent=2, ensure_ascii=False)

    _print_summary(result)
    print(f"available_rules={manager.available_rules}")
    print(f"output={output_path}")


if __name__ == "__main__":
    main()
