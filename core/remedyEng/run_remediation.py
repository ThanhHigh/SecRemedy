import argparse
import json
from pathlib import Path
from typing import Any, Dict, List, Tuple

try:
    from .manager import RemediationManager
except ImportError:  # pragma: no cover - support direct script execution
    from manager import RemediationManager


def _load_rules_from_file(path: Path) -> List[str]:
    if not path.exists():
        raise FileNotFoundError(f"Rules file not found: {path}")

    rules: List[str] = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            # Allow comments and blank lines in the rules file.
            clean_line = line.split("#", 1)[0].strip()
            if not clean_line:
                continue
            parts = [item.strip() for item in clean_line.split(",") if item.strip()]
            rules.extend(parts)

    return rules


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


def main() -> None:
    parser = argparse.ArgumentParser(description="Run plugin-based Nginx remediation rules")
    parser.add_argument("--input", required=True, help="Input JSON path (crossplane parsed result)")
    parser.add_argument(
        "--rules-file",
        help="Text file containing rule IDs (one per line or comma-separated). For rule-based remediations.",
    )
    parser.add_argument(
        "--scan-result",
        help="Path to scan_result.json for scan-based remediations (recommended approach)",
    )
    parser.add_argument("--dry-run", action="store_true", help="Preview changes without applying live output")
    parser.add_argument("--output", help="Optional output JSON path")
    parser.add_argument("--rules-dir", help="Optional custom rules directory")
    parser.add_argument(
        "--recommendations",
        help="Comma-separated recommendation IDs from scan_result to apply (e.g., 2.4.1,2.4.2). Used with --scan-result.",
    )

    args = parser.parse_args()

    input_path = Path(args.input).expanduser().resolve()
    if not input_path.exists():
        raise FileNotFoundError(f"Input not found: {input_path}")

    config_json, _ = _load_input(input_path)
    manager = RemediationManager(rules_dir=args.rules_dir, dry_run=args.dry_run)

    # Determine which approach to use
    if args.scan_result:
        # Scan-result based remediation (recommended)
        scan_result_path = Path(args.scan_result).expanduser().resolve()
        if not scan_result_path.exists():
            raise FileNotFoundError(f"Scan result not found: {scan_result_path}")

        scan_result = manager.load_scan_result(scan_result_path)
        
        target_rec_ids = None
        if args.recommendations:
            target_rec_ids = [r.strip() for r in args.recommendations.split(",") if r.strip()]

        result = manager.run_from_scan_result(config_json, scan_result, target_rec_ids, args.dry_run)
        
        output_key = "preview_config" if result["dry_run"] else "modified_config"
        output_payload = result[output_key]
        
        _print_scan_summary(result)
    else:
        # Rule-based remediation (legacy)
        if not args.rules_file:
            raise ValueError("Either --scan-result or --rules-file must be provided")

        rules_file_path = Path(args.rules_file).expanduser().resolve()
        target_rules = _load_rules_from_file(rules_file_path)
        if not target_rules:
            raise ValueError("No valid rule IDs found in --rules-file")

        result = manager.run(config_json, target_rules)
        
        output_key = "preview_config" if result["dry_run"] else "modified_config"
        output_payload = result[output_key]
        
        _print_rule_summary(result)

    output_path = Path(args.output).expanduser().resolve() if args.output else _build_default_output_path(input_path, args.dry_run)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with output_path.open("w", encoding="utf-8") as f:
        json.dump(output_payload, f, indent=2, ensure_ascii=False)

    print(f"output={output_path}")


def _print_scan_summary(result: Dict[str, Any]) -> None:
    """Print summary for scan-result based remediations."""
    print(f"\n=== REMEDIATION SUMMARY ===")
    print(f"dry_run={result['dry_run']}")
    print(f"applied_remediations={result['applied_remediations']}")
    print(f"failed_remediations={result['failed_remediations']}")

    if result.get("diffs"):
        print("diffs_by_recommendation=")
        for rec_id in sorted(result["diffs"].keys()):
            print(f"- {rec_id}")
    
    if result.get("errors"):
        print("\nerrors_encountered=")
        for error in result["errors"]:
            print(f"  ! {error}")


def _print_rule_summary(result: Dict[str, Any]) -> None:
    """Print summary for rule-based remediations (legacy)."""
    print(f"dry_run={result['dry_run']}")
    print(f"applied_rules={result['applied_rules']}")
    print(f"skipped_rules={result['skipped_rules']}")

    if result.get("diffs"):
        print("diff_rules=")
        for rule_id in sorted(result["diffs"].keys()):
            print(f"- {rule_id}")


if __name__ == "__main__":
    main()


if __name__ == "__main__":
    main()
