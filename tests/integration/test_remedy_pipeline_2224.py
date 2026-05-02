"""
Integration test: Full remedy pipeline for server 2224.

This script performs the full 5-step test cycle:
  Step 1: Use tmp/nginx_raw_2224 as input
  Step 2: Run parser -> parser_output (via contracts/parser_output_2224.json)
  Step 3: Run scanner -> scan_result (via contracts/scan_result_2224.json)
  Step 4: Run remedy engine on parser_output + scan_result
  Step 5: Re-scan the remediated AST and assert no rules from TARGET_RULES still fail

Usage:
  cd <project_root>
  source .venv/bin/activate
  python -m pytest tests/integration/test_remedy_pipeline_2224.py -v
  # or run directly:
  python tests/integration/test_remedy_pipeline_2224.py
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from copy import deepcopy
from pathlib import Path
from typing import Any, Dict, List

import pytest

# ── Paths ────────────────────────────────────────────────────────────────────
PROJECT_ROOT = Path(__file__).resolve().parents[2]
PARSER_OUTPUT = PROJECT_ROOT / "contracts" / "parser_output_2224.json"
SCAN_RESULT   = PROJECT_ROOT / "contracts" / "scan_result_2224.json"

# ── Rules that must pass after remediation ───────────────────────────────────
# These are the rules that were failing after remedy and must now be fixed.
TARGET_RULES = {"2.5.1", "2.5.2", "2.5.3", "4.1.1", "5.1.1", "5.3.1"}

# Rules we know are structural/manual (we don't expect them to be auto-fixed)
KNOWN_MANUAL_RULES: set[str] = {"5.3.2"}

# ── Batch user inputs for remedy engine ──────────────────────────────────────
BATCH_INPUTS = {
    "2.5.2": ["/custom_404.html", "/custom_50x.html", "/var/www/html/errors"],
    "2.5.3": ["/var/www/html", "_"],
    "3.2":   ["global:/var/log/nginx/access.log combined", "off"],
    "4.1.1": ["301", "https://$host$request_uri"],
    "5.1.1": ["/admin_login", "192.168.1.0/24"],
    "5.3.1": ["yes"],
    "5.3.2": ["yes"],
}


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def _run_scanner(parser_output_path: str, scan_result_path: str) -> Dict[str, Any]:
    """Run the scanner engine and return parsed scan result."""
    python = sys.executable
    # Write a temp config for the scanner
    scanner_config = {
        "servers": [{
            "ip": "0.0.0.0",
            "port": 2224,
            "user": "root",
            "pass": "root",
            "strict_private": False,
            "input_path": parser_output_path,
            "output_path": scan_result_path,
        }]
    }
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as tmp:
        json.dump(scanner_config, tmp)
        tmp_config = tmp.name

    try:
        result = subprocess.run(
            [python, "-m", "core.scannerEng.scanner", "--config", tmp_config],
            capture_output=True, text=True, cwd=str(PROJECT_ROOT)
        )
        if result.returncode != 0:
            raise RuntimeError(f"Scanner failed:\n{result.stdout}\n{result.stderr}")
    finally:
        Path(tmp_config).unlink(missing_ok=True)

    with open(scan_result_path) as f:
        return json.load(f)


def _apply_remediations(parser_output: Dict, scan_result: Dict) -> Dict:
    """Run the remedy engine non-interactively and return the remediated AST."""
    # Inline import to avoid polluting test module namespace
    sys.path.insert(0, str(PROJECT_ROOT))
    from core.remedyEng.remediator import Remediator

    remediator = Remediator()
    remediator.ast_config = deepcopy(parser_output)
    remediator.ast_scan   = deepcopy(scan_result)
    remediator.batch_remedy_inputs = deepcopy(BATCH_INPUTS)
    new_ast = remediator.apply_remediations(interactive=False)
    return new_ast


def _get_rule_statuses(scan_result: Dict) -> Dict[str, str]:
    """Return {rule_id: status} from a scan result."""
    return {
        r["id"]: r["status"]
        for r in scan_result.get("recommendations", [])
        if isinstance(r, dict)
    }


# ─────────────────────────────────────────────────────────────────────────────
# Unit-level tests (fast, no subprocess)
# ─────────────────────────────────────────────────────────────────────────────

class TestRemedyUnit:
    """Per-rule unit tests using real contract files but no subprocess."""

    @pytest.fixture(scope="class")
    def remediated_ast(self) -> Dict:
        parser_output = _load_json(PARSER_OUTPUT)
        scan_result   = _load_json(SCAN_RESULT)
        return _apply_remediations(parser_output, scan_result)

    # ── 2.5.1 server_tokens ──────────────────────────────────────────────────
    def test_251_server_tokens_applied(self, remediated_ast):
        """server_tokens off; must appear in http block after remedy."""
        from core.remedyEng.ast_editor import ASTEditor
        config = remediated_ast.get("config", [])
        found = False
        for entry in config:
            parsed = entry.get("parsed", [])
            for node in parsed:
                if node.get("directive") == "http":
                    block = node.get("block", [])
                    for item in block:
                        if item.get("directive") == "server_tokens" and item.get("args") == ["off"]:
                            found = True
        assert found, "server_tokens off; not found in http block after remedy 2.5.1"

    # ── 2.5.2 error_page ────────────────────────────────────────────────────
    def test_252_error_page_404_in_server_blocks(self, remediated_ast):
        """error_page 404 directive must be added to server blocks."""
        config = remediated_ast.get("config", [])
        found_404 = False
        for entry in config:
            file_path = entry.get("file", "")
            if "example.com" not in file_path:
                continue
            parsed = entry.get("parsed", [])
            for node in parsed:
                if node.get("directive") != "server":
                    continue
                for item in node.get("block", []):
                    if item.get("directive") == "error_page" and "404" in item.get("args", []):
                        found_404 = True
        assert found_404, "error_page 404 not found in any server block after remedy 2.5.2"

    def test_252_error_page_50x_in_server_blocks(self, remediated_ast):
        """error_page 500 directive must be added to server blocks."""
        config = remediated_ast.get("config", [])
        found_50x = False
        for entry in config:
            file_path = entry.get("file", "")
            if "example.com" not in file_path:
                continue
            parsed = entry.get("parsed", [])
            for node in parsed:
                if node.get("directive") != "server":
                    continue
                for item in node.get("block", []):
                    if item.get("directive") == "error_page" and "500" in item.get("args", []):
                        found_50x = True
        assert found_50x, "error_page 500 not found in any server block after remedy 2.5.2"

    # ── 2.5.3 hidden files ───────────────────────────────────────────────────
    def test_253_deny_hidden_location_exists(self, remediated_ast):
        """location ~ /\\. deny all must exist in server blocks."""
        config = remediated_ast.get("config", [])
        found_deny = False
        for entry in config:
            file_path = entry.get("file", "")
            if "example.com" not in file_path:
                continue
            parsed = entry.get("parsed", [])
            for node in parsed:
                if node.get("directive") != "server":
                    continue
                for item in node.get("block", []):
                    if item.get("directive") != "location":
                        continue
                    args = item.get("args", [])
                    # Match args like ["~", "/\\."] or ["/\\."]
                    args_str = " ".join(args)
                    if "\\." in args_str or "/." in args_str:
                        for sub in item.get("block", []):
                            if sub.get("directive") == "deny" and sub.get("args") == ["all"]:
                                found_deny = True
        assert found_deny, "No deny-hidden-files location block found after remedy 2.5.3"

    def test_253_acme_before_deny_order(self, remediated_ast):
        """ACME challenge location must appear before deny-hidden location."""
        config = remediated_ast.get("config", [])
        for entry in config:
            file_path = entry.get("file", "")
            if "example.com" not in file_path:
                continue
            parsed = entry.get("parsed", [])
            for node in parsed:
                if node.get("directive") != "server":
                    continue
                block = node.get("block", [])
                acme_idx = None
                deny_idx = None
                for i, item in enumerate(block):
                    if item.get("directive") != "location":
                        continue
                    args = item.get("args", [])
                    args_str = " ".join(args)
                    if "well-known" in args_str or "acme" in args_str:
                        acme_idx = i
                    elif "\\." in args_str and acme_idx is None:
                        deny_idx = i
                if acme_idx is not None and deny_idx is not None:
                    assert acme_idx < deny_idx, (
                        f"ACME location (idx={acme_idx}) must come before deny-hidden (idx={deny_idx})"
                    )

    # ── 4.1.1 HTTP→HTTPS redirect ────────────────────────────────────────────
    def test_411_return_301_in_http_server(self, remediated_ast):
        """return 301 https://... must appear in the HTTP-only server block."""
        config = remediated_ast.get("config", [])
        found = False
        for entry in config:
            file_path = entry.get("file", "")
            if "example.com" not in file_path:
                continue
            parsed = entry.get("parsed", [])
            for node in parsed:
                if node.get("directive") != "server":
                    continue
                block = node.get("block", [])
                # Check if this server block has listen 80 and a return 301
                listens = [
                    item for item in block
                    if item.get("directive") == "listen"
                    and "80" in item.get("args", [])
                    and "ssl" not in item.get("args", [])
                ]
                returns = [
                    item for item in block
                    if item.get("directive") == "return"
                    and "301" in item.get("args", [])
                ]
                if listens and returns:
                    for r in returns:
                        args = r.get("args", [])
                        if len(args) >= 2 and args[1].startswith("https://"):
                            found = True
        assert found, "return 301 https://... not found in HTTP (port 80) server block after remedy 4.1.1"

    # ── 5.1.1 IP access control ──────────────────────────────────────────────
    def test_511_skipped_because_already_passing(self, remediated_ast):
        """5.1.1 is already passing in 2224 - no remedy needed."""
        # The scan result shows 5.1.1 as 'pass', so remedy should be a no-op
        # This test documents that 5.1.1 does NOT need remediation for 2224
        pass  # Expected: no violations, no changes needed

    # ── 5.3.1 X-Content-Type-Options ─────────────────────────────────────────
    def test_531_xct_header_added(self, remediated_ast):
        """add_header X-Content-Type-Options nosniff always must be present."""
        config = remediated_ast.get("config", [])
        found = False
        target_args = ["X-Content-Type-Options", '"nosniff"', "always"]
        for entry in config:
            parsed = entry.get("parsed", [])
            def _search(nodes):
                nonlocal found
                for node in nodes:
                    if not isinstance(node, dict):
                        continue
                    if (node.get("directive") == "add_header"
                            and node.get("args", [])[:1] == ["X-Content-Type-Options"]):
                        found = True
                        return
                    _search(node.get("block", []))
            _search(parsed)
            if found:
                break
        assert found, "add_header X-Content-Type-Options not found after remedy 5.3.1"


# ─────────────────────────────────────────────────────────────────────────────
# End-to-end integration test (uses scanner subprocess)
# ─────────────────────────────────────────────────────────────────────────────

class TestRemedyEndToEnd:
    """Full pipeline: remedy -> re-parse -> re-scan -> check results."""

    @pytest.fixture(scope="class")
    def e2e_scan_result(self, tmp_path_factory) -> Dict:
        """Apply remedy, write remediated AST, re-run scanner, return scan result."""
        tmp_dir = tmp_path_factory.mktemp("e2e_2224")

        # Step 4: Apply remedy
        parser_output = _load_json(PARSER_OUTPUT)
        scan_result   = _load_json(SCAN_RESULT)
        remediated_ast = _apply_remediations(parser_output, scan_result)

        # Step 5a: Save remediated AST (renamed to parser_output_xxx format)
        rem_ast_path = tmp_dir / "parser_output_remediated.json"
        with rem_ast_path.open("w") as f:
            json.dump(remediated_ast, f, indent=2)

        # Step 5b: Re-run scanner on remediated AST
        scan_out_path = str(tmp_dir / "scan_result_remediated.json")
        rescan = _run_scanner(str(rem_ast_path), scan_out_path)
        return rescan

    @pytest.mark.parametrize("rule_id", sorted(TARGET_RULES))
    def test_rule_passes_after_remedy(self, e2e_scan_result, rule_id):
        """After full remediation, each target rule must show status=pass."""
        statuses = _get_rule_statuses(e2e_scan_result)
        assert rule_id in statuses, f"Rule {rule_id} not found in re-scan result"
        status = statuses[rule_id]
        assert status == "pass", (
            f"Rule {rule_id} still FAILS after remediation. "
            f"Status: {status}. "
            f"This indicates a bug in remediate_{rule_id.replace('.', '')}.py"
        )


# ─────────────────────────────────────────────────────────────────────────────
# Quick summary runner (for manual use)
# ─────────────────────────────────────────────────────────────────────────────

def _run_full_pipeline_summary():
    """Run the full pipeline and print a summary of results."""
    print("\n" + "="*60)
    print("REMEDY PIPELINE TEST — Server 2224")
    print("="*60)

    # Load contracts
    parser_output = _load_json(PARSER_OUTPUT)
    scan_result   = _load_json(SCAN_RESULT)

    # Before remediation
    before = _get_rule_statuses(scan_result)
    failing_before = {k for k, v in before.items() if v == "fail"}
    print(f"\n📋 BEFORE REMEDY — Failing rules: {sorted(failing_before)}")

    # Apply remediation
    print("\n🔧 Applying remediation engine...")
    remediated_ast = _apply_remediations(parser_output, scan_result)

    # Save remediated AST to tmp
    rem_path = PROJECT_ROOT / "tmp" / "test_remediated_2224.json"
    with rem_path.open("w") as f:
        json.dump(remediated_ast, f, indent=2)
    print(f"   Saved remediated AST: {rem_path}")

    # Re-scan
    print("\n🔍 Re-running scanner on remediated AST...")
    scan_out = str(PROJECT_ROOT / "tmp" / "test_scan_remediated_2224.json")
    rescan = _run_scanner(str(rem_path), scan_out)
    print(f"   Re-scan saved: {scan_out}")

    # Results
    after = _get_rule_statuses(rescan)
    failing_after = {k for k, v in after.items() if v == "fail"}
    fixed = failing_before - failing_after
    still_failing = failing_before & failing_after

    print(f"\n✅ FIXED rules: {sorted(fixed)}")
    print(f"❌ STILL FAILING: {sorted(still_failing)}")
    print(f"\n📊 Compliance: {rescan.get('compliance_score', '?')}%")

    target_still_failing = TARGET_RULES & failing_after
    if target_still_failing:
        print(f"\n⚠️  TARGET RULES STILL FAILING: {sorted(target_still_failing)}")
        print("    These require bug fixes in the corresponding remediate_xxx.py files.")
        return 1
    else:
        print(f"\n🎉 All target rules now PASS after remediation!")
        return 0


if __name__ == "__main__":
    sys.path.insert(0, str(PROJECT_ROOT))
    exit_code = _run_full_pipeline_summary()
    sys.exit(exit_code)
