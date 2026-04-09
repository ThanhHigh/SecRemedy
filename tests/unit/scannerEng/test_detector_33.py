"""
Unit tests for Detector33 — CIS Benchmark 3.3
"Ensure error logging is enabled and set to the info logging level (Manual)"

Test Strategy
─────────────
• evaluate() tests — Detector33 overrides scan() completely, evaluate() always returns None.
• scan() tests — exercise the full AST traversal and the logic that looks for 
  global 'error_log' directives, checking if it modifies existing ones or adds a new one.
"""

import pytest
from core.scannerEng.recommendations.detector_33 import Detector33


# ──────────────────────────────────────────────────────────────────────────────
# Fixtures & Helpers
# ──────────────────────────────────────────────────────────────────────────────

@pytest.fixture
def detector():
    """Return a fresh Detector33 instance for every test."""
    return Detector33()


def _error_log_directive(args: list = None) -> dict:
    """Helper: build a 'error_log' crossplane directive dict."""
    if args is None:
        args = ["/var/log/nginx/error.log", "info"]
    return {"directive": "error_log", "args": args}


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
        assert detector.id == "3.3"

    def test_title_contains_error_logging(self, detector):
        assert "error logging" in detector.title.lower()

    def test_has_required_attributes(self, detector):
        for attr in ("description", "audit_procedure", "impact", "remediation"):
            assert getattr(detector, attr, None), f"Missing attribute: {attr}"


# ──────────────────────────────────────────────────────────────────────────────
# Section 2 — evaluate(): unused in Detector33
# ──────────────────────────────────────────────────────────────────────────────

class TestEvaluate:
    def test_evaluate_returns_none(self, detector):
        """Detector33 overrides scan, evaluate just returns None."""
        assert detector.evaluate({}, "some_path", [], []) is None


# ──────────────────────────────────────────────────────────────────────────────
# Section 3 — scan(): full pipeline tests
# ──────────────────────────────────────────────────────────────────────────────

class TestScan:
    """Integration tests exercising Detector33.scan() since evaluate is bypassed."""

    FILEPATH = "/etc/nginx/nginx.conf"
    EXACT_PATH = ["config", 0, "parsed"]

    # --- Fully compliant configs produce no findings ---

    def test_compliant_config_info(self, detector):
        """Standard behavior: global error_log with 'info' level."""
        parser_output = _make_parser_output([
            _error_log_directive(["/var/log/nginx/error.log", "info"])
        ])
        findings = detector.scan(parser_output)
        assert findings == []

    def test_compliant_config_notice(self, detector):
        """Standard behavior: global error_log with 'notice' level."""
        parser_output = _make_parser_output([
            _error_log_directive(["/var/log/nginx/error.log", "notice"])
        ])
        findings = detector.scan(parser_output)
        assert findings == []

    # --- Missing configurations (Should add directive) ---

    def test_missing_error_log(self, detector):
        """Global error_log missing entirely, should add to nginx.conf."""
        parser_output = _make_parser_output([
            {"directive": "events", "args": [], "block": []}
        ], filepath=self.FILEPATH)

        findings = detector.scan(parser_output)
        assert len(findings) == 1

        finding = findings[0]
        assert finding["file"] == self.FILEPATH
        assert len(finding["remediations"]) == 1

        rem = finding["remediations"][0]
        assert rem["action"] == "add_directive"
        assert rem["directive"] == "error_log"
        assert rem["context"] == self.EXACT_PATH
        assert rem["args"] == ["/var/log/nginx/error.log", "info"]

    # --- Non-compliant configurations (Should modify directive) ---

    def test_non_compliant_level_warn(self, detector):
        """Global error_log present but level is 'warn', should modify to 'info'."""
        parser_output = _make_parser_output([
            _error_log_directive(["/var/log/nginx/error.log", "warn"])
        ])

        findings = detector.scan(parser_output)
        assert len(findings) == 1

        finding = findings[0]
        assert finding["file"] == self.FILEPATH
        assert len(finding["remediations"]) == 1

        rem = finding["remediations"][0]
        assert rem["action"] == "modify_directive"
        assert rem["directive"] == "error_log"
        assert rem["context"] == self.EXACT_PATH + [0]
        assert rem["args"] == ["/var/log/nginx/error.log", "info"]

    def test_non_compliant_no_level_specified(self, detector):
        """Global error_log present but no level specified (only file path)."""
        parser_output = _make_parser_output([
            _error_log_directive(["/var/log/nginx/error.log"])
        ])

        findings = detector.scan(parser_output)
        assert len(findings) == 1

        rem = findings[0]["remediations"][0]
        assert rem["action"] == "modify_directive"
        assert rem["args"] == ["/var/log/nginx/error.log", "info"]

    # --- Context specific testing ---

    def test_empty_config(self, detector):
        """Empty input data should not crash and return empty."""
        findings = detector.scan({"config": []})
        assert findings == []

    def test_non_conf_file_skipped(self, detector):
        """Files not ending in .conf are ignored."""
        parser_output = {
            "config": [
                {
                    "file": "/etc/nginx/nginx",     # no .conf extension
                    "parsed": [_error_log_directive()]
                }
            ]
        }
        findings = detector.scan(parser_output)
        # Because we skip files not ending in .conf, and no nginx.conf exists to add it to,
        # global_error_log_found is False, but nginx_conf_file is None, so it doesn't add either.
        assert findings == []
