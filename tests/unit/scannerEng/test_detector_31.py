"""
Unit tests for Detector31 — CIS Benchmark 3.1
"Ensure detailed logging is enabled (Manual)"

Test Strategy
─────────────
• evaluate() tests — isolate the directive-level logic directly.
  Checks compliance scenarios for the 'http' block with and without 'log_format'.

• scan() tests — exercise the full AST traversal + grouping pipeline
  that BaseRecom provides, with synthetic parser_output payloads.
"""

import pytest
from core.scannerEng.recommendations.detector_31 import Detector31


# ──────────────────────────────────────────────────────────────────────────────
# Fixtures & Helpers
# ──────────────────────────────────────────────────────────────────────────────

@pytest.fixture
def detector():
    """Return a fresh Detector31 instance for every test."""
    return Detector31()


def _http_directive(block: list) -> dict:
    """Helper: build a minimal 'http' crossplane directive dict."""
    return {"directive": "http", "args": [], "block": block}


def _log_format_directive(args: list = None) -> dict:
    """Helper: build a 'log_format' crossplane directive dict."""
    if args is None:
        args = ["main_json", "escape=json", "'{\"...\"}'"]
    return {"directive": "log_format", "args": args}


def _make_parser_output(parsed_directives: list, filepath: str = "/etc/nginx/nginx.conf") -> dict:
    """Helper: wrap directives in a minimal crossplane parser_output structure."""
    return {
        "config": [
            {
                "file": filepath,
                "parsed": parsed_directives,
            }
        ]
    }


# ──────────────────────────────────────────────────────────────────────────────
# Section 1 — Metadata sanity checks
# ──────────────────────────────────────────────────────────────────────────────

class TestMetadata:
    def test_id(self, detector):
        assert detector.id == "3.1"

    def test_title_contains_detailed_logging(self, detector):
        assert "detailed logging" in detector.title.lower()

    def test_has_required_attributes(self, detector):
        for attr in ("description", "audit_procedure", "impact", "remediation"):
            assert getattr(detector, attr, None), f"Missing attribute: {attr}"


# ──────────────────────────────────────────────────────────────────────────────
# Section 2 — evaluate(): compliant cases (must return None)
# ──────────────────────────────────────────────────────────────────────────────

class TestEvaluateCompliant:
    """Directives that should NOT trigger an uncompliance finding."""

    FILEPATH = "/etc/nginx/nginx.conf"
    EXACT_PATH = ["config", 0, "parsed", 0]

    def _eval(self, detector, directive, ctx=None):
        ctx = ctx or []
        return detector.evaluate(directive, self.FILEPATH, ctx, self.EXACT_PATH)

    def test_http_with_log_format(self, detector):
        """Standard behavior: log_format inside http block."""
        http_block = [_log_format_directive()]
        directive = _http_directive(http_block)
        assert self._eval(detector, directive) is None

    def test_http_with_multiple_directives_including_log_format(self, detector):
        """Other directives might exist, as long as log_format is there."""
        http_block = [
            {"directive": "server_tokens", "args": ["off"]},
            _log_format_directive(),
            {"directive": "server", "block": []}
        ]
        directive = _http_directive(http_block)
        assert self._eval(detector, directive) is None

    def test_non_http_directive(self, detector):
        """Detector only targets 'http', others should be ignored."""
        directive = {"directive": "server", "args": [], "block": []}
        assert self._eval(detector, directive) is None

    def test_empty_directive(self, detector):
        """Gracefully handle empty dict."""
        assert self._eval(detector, {}) is None


# ──────────────────────────────────────────────────────────────────────────────
# Section 3 — evaluate(): non-compliant cases (must return a finding)
# ──────────────────────────────────────────────────────────────────────────────

class TestEvaluateNonCompliant:
    """Directives that SHOULD trigger an uncompliance finding."""

    FILEPATH = "/etc/nginx/nginx.conf"
    EXACT_PATH = ["config", 0, "parsed", 0]

    def _eval(self, detector, directive, ctx=None):
        ctx = ctx or []
        return detector.evaluate(directive, self.FILEPATH, ctx, self.EXACT_PATH)

    def test_http_empty_block(self, detector):
        """http block with no children."""
        directive = _http_directive([])
        result = self._eval(detector, directive)
        assert result is not None

    def test_http_without_log_format(self, detector):
        """http block with children but missing log_format."""
        http_block = [
            {"directive": "server_tokens", "args": ["off"]},
            {"directive": "server", "block": []}
        ]
        directive = _http_directive(http_block)
        result = self._eval(detector, directive)
        assert result is not None

    # ── Remediation payload structure checks ──────────────────────────────────

    def test_result_structure(self, detector):
        directive = _http_directive([])
        result = self._eval(detector, directive)

        assert result["file"] == self.FILEPATH
        assert "remediations" in result
        assert isinstance(result["remediations"], list)
        assert len(result["remediations"]) == 2

    def test_remediations_content(self, detector):
        directive = _http_directive([])
        result = self._eval(detector, directive)
        rems = result["remediations"]

        # First remediation is log_format
        assert rems[0]["action"] == "add_directive"
        assert rems[0]["directive"] == "log_format"
        assert rems[0]["context"] == self.EXACT_PATH + ["block"]
        assert "main_json" in rems[0]["args"]

        # Second remediation is access_log
        assert rems[1]["action"] == "add_directive"
        assert rems[1]["directive"] == "access_log"
        assert rems[1]["context"] == self.EXACT_PATH + ["block"]
        assert "main_json" in rems[1]["args"]


# ──────────────────────────────────────────────────────────────────────────────
# Section 4 — scan(): full pipeline tests
# ──────────────────────────────────────────────────────────────────────────────

class TestScan:
    """Integration tests exercising BaseRecom.scan() → _traverse_ast() → evaluate()."""

    # --- Fully compliant configs produce no findings ---

    def test_compliant_config(self, detector):
        parser_output = _make_parser_output([
            _http_directive([_log_format_directive()])
        ])
        findings = detector.scan(parser_output)
        assert findings == []

    def test_empty_config_list(self, detector):
        findings = detector.scan({"config": []})
        assert findings == []

    def test_non_conf_file_skipped(self, detector):
        """Files not ending in .conf must be skipped by BaseRecom.scan()."""
        parser_output = {
            "config": [
                {
                    "file": "/etc/nginx/nginx",     # no .conf extension
                    "parsed": [_http_directive([])]
                }
            ]
        }
        findings = detector.scan(parser_output)
        assert findings == []

    # --- Non-compliant configs ---

    def test_non_compliant_config(self, detector):
        parser_output = _make_parser_output([
            _http_directive([
                {"directive": "server_tokens", "args": ["off"]}
            ])
        ])
        findings = detector.scan(parser_output)
        assert len(findings) == 1

        finding = findings[0]
        assert finding["file"] == "/etc/nginx/nginx.conf"
        assert len(finding["remediations"]) == 2

    def test_scan_multiple_files(self, detector):
        parser_output = {
            "config": [
                {
                    "file": "/etc/nginx/nginx.conf",
                    "parsed": [_http_directive([{"directive": "server_tokens", "args": ["off"]}])],
                },
                {
                    "file": "/etc/nginx/conf.d/other.conf",
                    "parsed": [_http_directive([])],
                },
            ]
        }
        findings = detector.scan(parser_output)
        assert len(findings) == 2
        files = {f["file"] for f in findings}
        assert "/etc/nginx/nginx.conf" in files
        assert "/etc/nginx/conf.d/other.conf" in files

    # --- Result schema completeness ---

    def test_scan_result_keys(self, detector):
        parser_output = _make_parser_output([_http_directive([])])
        findings = detector.scan(parser_output)
        result = findings[0]
        assert "file" in result
        assert "remediations" in result

    def test_scan_remediation_keys(self, detector):
        parser_output = _make_parser_output([_http_directive([])])
        findings = detector.scan(parser_output)
        remediation = findings[0]["remediations"][0]
        assert "action" in remediation
        assert "directive" in remediation
        assert "context" in remediation
