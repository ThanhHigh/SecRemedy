"""
Unit tests for Detector32 — CIS Benchmark 3.2
"Ensure access logging is enabled (Manual)"

Test Strategy
─────────────
• evaluate() tests — isolate the directive-level logic directly.
  Checks compliance scenarios for 'access_log' set to 'off' vs. valid paths.

• scan() tests — exercise the full AST traversal + grouping pipeline
  that BaseRecom provides, with synthetic parser_output payloads.
"""

import pytest
from core.scannerEng.recommendations.detector_32 import Detector32


# ──────────────────────────────────────────────────────────────────────────────
# Fixtures & Helpers
# ──────────────────────────────────────────────────────────────────────────────

@pytest.fixture
def detector():
    """Return a fresh Detector32 instance for every test."""
    return Detector32()


def _access_log_directive(args: list = None) -> dict:
    """Helper: build an 'access_log' crossplane directive dict."""
    if args is None:
        args = ["/var/log/nginx/access.log", "main"]
    return {"directive": "access_log", "args": args}


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
        assert detector.id == "3.2"

    def test_title_contains_access_logging(self, detector):
        assert "access logging" in detector.title.lower()

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

    def test_access_log_enabled(self, detector):
        """Standard behavior: access_log with valid path."""
        directive = _access_log_directive(
            ["/var/log/nginx/access.log", "main"])
        assert self._eval(detector, directive) is None

    def test_non_access_log_directive(self, detector):
        """Detector only targets 'access_log', others should be ignored."""
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

    def test_access_log_off(self, detector):
        """access_log set to 'off'."""
        directive = _access_log_directive(["off"])
        result = self._eval(detector, directive)
        assert result is not None

    # ── Remediation payload structure checks ──────────────────────────────────

    def test_result_structure(self, detector):
        directive = _access_log_directive(["off"])
        result = self._eval(detector, directive)

        assert result["file"] == self.FILEPATH
        assert "remediations" in result
        assert isinstance(result["remediations"], list)
        assert len(result["remediations"]) == 1

    def test_remediations_content(self, detector):
        directive = _access_log_directive(["off"])
        result = self._eval(detector, directive)
        rems = result["remediations"]

        assert rems[0]["action"] == "modify_directive"
        assert rems[0]["directive"] == "access_log"
        assert rems[0]["context"] == self.EXACT_PATH
        assert rems[0]["args"] == ["/var/log/nginx/access.log", "combined"]


# ──────────────────────────────────────────────────────────────────────────────
# Section 4 — scan(): full pipeline tests
# ──────────────────────────────────────────────────────────────────────────────

class TestScan:
    """Integration tests exercising BaseRecom.scan() → _traverse_ast() → evaluate()."""

    # --- Fully compliant configs produce no findings ---

    def test_compliant_config(self, detector):
        parser_output = _make_parser_output([
            _access_log_directive()
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
                    "parsed": [_access_log_directive(["off"])]
                }
            ]
        }
        findings = detector.scan(parser_output)
        assert findings == []

    # --- Non-compliant configs ---

    def test_non_compliant_config(self, detector):
        parser_output = _make_parser_output([
            _access_log_directive(["off"])
        ])
        findings = detector.scan(parser_output)
        assert len(findings) == 1

        finding = findings[0]
        assert finding["file"] == "/etc/nginx/nginx.conf"
        assert len(finding["remediations"]) == 1

    def test_scan_multiple_files(self, detector):
        parser_output = {
            "config": [
                {
                    "file": "/etc/nginx/nginx.conf",
                    "parsed": [_access_log_directive(["off"])],
                },
                {
                    "file": "/etc/nginx/conf.d/other.conf",
                    "parsed": [_access_log_directive(["/var/log/nginx/other.log"])],
                },
            ]
        }
        findings = detector.scan(parser_output)
        assert len(findings) == 1
        assert findings[0]["file"] == "/etc/nginx/nginx.conf"

    # --- Result schema completeness ---

    def test_scan_result_keys(self, detector):
        parser_output = _make_parser_output([_access_log_directive(["off"])])
        findings = detector.scan(parser_output)
        result = findings[0]
        assert "file" in result
        assert "remediations" in result

    def test_scan_remediation_keys(self, detector):
        parser_output = _make_parser_output([_access_log_directive(["off"])])
        findings = detector.scan(parser_output)
        remediation = findings[0]["remediations"][0]
        assert "action" in remediation
        assert "directive" in remediation
        assert "context" in remediation
        assert "args" in remediation
