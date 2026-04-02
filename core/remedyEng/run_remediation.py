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
    """Load input JSON file.
    
    Returns the full JSON structure (not extracted).
    Returns: (json_data, is_crossplane_format)
    """
    with path.open("r", encoding="utf-8") as f:
        raw = json.load(f)

    # Check if it's the full crossplane format
    if isinstance(raw, dict) and isinstance(raw.get("config"), list):
        return raw, True
    
    # Otherwise return as-is
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

    full_ast_json, is_crossplane = _load_input(input_path)
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

        # Process full AST with all configs
        result = _process_full_ast_with_scan_result(
            full_ast_json, is_crossplane, scan_result, manager, target_rec_ids, args.dry_run
        )
        
        output_payload = result["output_ast"]
        
        _print_scan_summary(result)
    else:
        # Rule-based remediation (legacy)
        if not args.rules_file:
            raise ValueError("Either --scan-result or --rules-file must be provided")

        rules_file_path = Path(args.rules_file).expanduser().resolve()
        target_rules = _load_rules_from_file(rules_file_path)
        if not target_rules:
            raise ValueError("No valid rule IDs found in --rules-file")

        # For legacy mode, extract first config if crossplane format
        if is_crossplane and isinstance(full_ast_json, dict) and full_ast_json.get("config"):
            config_json = full_ast_json["config"][0]
        else:
            config_json = full_ast_json

        result = manager.run(config_json, target_rules)
        
        output_key = "preview_config" if result["dry_run"] else "modified_config"
        output_payload = result[output_key]
        
        _print_rule_summary(result)

    output_path = Path(args.output).expanduser().resolve() if args.output else _build_default_output_path(input_path, args.dry_run)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with output_path.open("w", encoding="utf-8") as f:
        json.dump(output_payload, f, indent=2, ensure_ascii=False)

    print(f"output={output_path}")



def _normalize_file_path(file_path: str) -> str:
    """
    Normalize a file path for consistent comparison.
    
    Removes leading/trailing whitespace, normalizes slashes,
    and removes leading './'.
    
    Args:
        file_path: The file path to normalize
    
    Returns:
        The normalized file path
    """
    normalized = file_path.strip()
    normalized = normalized.replace("\\", "/")
    if normalized.startswith("./"):
        normalized = normalized[2:]
    return normalized


def _is_config_file(file_path: str) -> bool:
    """
    Validate that a file is a config file.
    
    Args:
        file_path: Path to the file
    
    Returns:
        True if the file is a configuration file (nginx.conf, *.conf, etc.)
    """
    # Check for common config file patterns
    config_extensions = {".conf", ".config", ".cfg", ".ini", ".yaml", ".yml", ".json"}
    config_names = {"nginx.conf", "apache2.conf", "httpd.conf"}
    
    # Use basename only for comparison
    file_name = file_path.split("/")[-1] if "/" in file_path else file_path
    
    # Check exact names
    if file_name in config_names:
        return True
    
    # Check extensions
    for ext in config_extensions:
        if file_name.endswith(ext):
            return True
    
    return False


def _process_full_ast_with_scan_result(
    full_ast: Any,
    is_crossplane: bool,
    scan_result: Dict[str, Any],
    manager: "RemediationManager",
    target_rec_ids: List[str] | None = None,
    dry_run: bool = True,
) -> Dict[str, Any]:
    """
    Process all configs in the full AST, applying remediations where needed.
    
    For each config file:
    1. Validate that it is a config file
    2. Check if it has uncompliances in scan_result
    3. If yes, apply remediations to that config
    4. If no, keep it unchanged (copy old part)
    5. Fix all blocks/objects in AST if scan_result indicates issues
    
    Returns the full AST with all configs processed, maintaining the full structure.
    """
    import copy
    
    # If not crossplane format, just treat as single config
    if not is_crossplane or not isinstance(full_ast, dict) or "config" not in full_ast:
        # Single config mode - process it
        result = manager.run_from_scan_result(full_ast, scan_result, target_rec_ids, dry_run)
        return {
            "dry_run": result["dry_run"],
            "applied_remediations": result["applied_remediations"],
            "failed_remediations": result["failed_remediations"],
            "diffs": result["diffs"],
            "errors": result.get("errors", []),
            "output_ast": result["preview_config" if result["dry_run"] else "modified_config"],
        }
    
    # Crossplane format - process all configs while preserving full structure
    output_ast = copy.deepcopy(full_ast)
    modified_configs = []
    total_applied = 0
    total_failed = 0
    all_diffs: Dict[str, str] = {}
    all_errors: List[str] = []
    
    # Build a comprehensive map of normalized file paths to recommendations and uncompliances
    # This allows us to fix all blocks in AST based on scan_result data
    file_to_recommendations: Dict[str, List[Dict[str, Any]]] = {}
    
    for rec in scan_result.get("recommendations", []):
        rec_id = rec.get("id", "")
        
        # Skip if filtering recommendations and this one isn't in the list
        if target_rec_ids and rec_id not in target_rec_ids:
            continue
        
        for uncomp in rec.get("uncompliances", []):
            file_path = uncomp.get("file", "")
            normalized_path = _normalize_file_path(file_path)
            
            if normalized_path not in file_to_recommendations:
                file_to_recommendations[normalized_path] = []
            file_to_recommendations[normalized_path].append({
                "rec_id": rec_id,
                "title": rec.get("title", ""),
                "uncompliance": uncomp,
            })
    
    print(f"\n[*] Scan result contains uncompliances for {len(file_to_recommendations)} file(s)")
    for file_path, recs in file_to_recommendations.items():
        print(f"    - {file_path}: {len(recs)} recommendation(s)")
    
    # Process each config in the config array
    for config_idx, config in enumerate(output_ast.get("config", [])):
        config_file = config.get("file", "")
        normalized_config_file = _normalize_file_path(config_file)
        
        # Step 1: Check if this config file is in scan_result uncompliances
        if normalized_config_file not in file_to_recommendations:
            # Step 2: No uncompliances for this config - skip silently (keep original)
            continue
        
        # This config has issues in scan_result
        recs = file_to_recommendations[normalized_config_file]
        
        print(f"\n[*] Processing config {config_idx}: {config_file}")
        
        # Step 3: Validate that this is a config file before processing
        if not _is_config_file(config_file):
            print(f"    [⚠] File is not a recognized config file type - keeping as-is")
            continue
        
        # Step 4: Apply remediations to this config file
        print(f"    [✓] Found {len(recs)} recommendation(s) to apply")
        
        # Create a scan_result structure for this config's recommendations
        temp_scan_result = {
            "recommendations": [
                {
                    "id": item["rec_id"],
                    "title": item["title"],
                    "uncompliances": [item["uncompliance"]],
                }
                for item in recs
            ]
        }
        
        # Apply remediations to this config
        result = manager.run_from_scan_result(config, temp_scan_result, None, dry_run)
        modified_config = result["preview_config" if result["dry_run"] else "modified_config"]
        
        # Update this config in the output AST
        output_ast["config"][config_idx] = modified_config
        modified_configs.append(config_file)
        
        total_applied += result["applied_remediations"]
        total_failed += result["failed_remediations"]
        all_diffs.update(result["diffs"])
        all_errors.extend(result.get("errors", []))
    
    return {
        "dry_run": dry_run,
        "applied_remediations": total_applied,
        "failed_remediations": total_failed,
        "diffs": all_diffs,
        "errors": all_errors,
        "output_ast": output_ast,
    }


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
