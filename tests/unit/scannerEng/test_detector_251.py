"""
Unit tests for Detector251 — CIS Benchmark 2.5.1
"Ensure server_tokens directive is set to `off`"

Test Strategy
─────────────
• evaluate() tests — test explicit server_tokens variations (on, off, build)
  and the check for missing server_tokens in the http block.
• scan() tests — exercise the full AST traversal + grouping pipeline
  that BaseRecom provides, with synthetic parser_output payloads.
"""

import pytest
from core.scannerEng.recommendations.detector_251 import Detector251


# ──────────────────────────────────────────────────────────────────────────────
# Fixtures
# ──────────────────────────────────────────────────────────────────────────────

@pytest.fixture
def detector():
    """Return a fresh Detector251 instance for every test."""
    return Detector251()


def _directive(name: str, args: list, block: list = None) -> dict:
    """Helper: build a minimal crossplane directive dict."""
    d = {"directive": name, "args": args}
    if block is not None:
        d["block"] = block
    return d


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
        assert detector.id == "2.5.1"

    def test_title_contains_server_tokens(self, detector):
        assert "server_tokens" in detector.title.lower()

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

    # --- Explicit server_tokens off ---

    def test_server_tokens_off(self, detector):
        assert self._eval(detector, _directive(
            "server_tokens", ["off"])) is None

    def test_server_tokens_empty_args(self, detector):
        # Even though missing args is invalid nginx syntax, our code handles it gracefully
        assert self._eval(detector, _directive("server_tokens", [])) is None

    # --- http block containing server_tokens (any value) ---

    def test_http_block_with_server_tokens_off(self, detector):
        http_dir = _directive(
            "http", [], [_directive("server_tokens", ["off"])])
        assert self._eval(detector, http_dir) is None

    def test_http_block_with_server_tokens_on(self, detector):
        # NOTE: If server_tokens is 'on', the http block evaluation itself returns None
        # because the directive exists in the block. The separate check on the 'server_tokens'
        # directive itself will catch the 'on' value.
        http_dir = _directive(
            "http", [], [_directive("server_tokens", ["on"])])
        assert self._eval(detector, http_dir) is None

    # --- Irrelevant directives ---

    def test_irrelevant_directive(self, detector):
        assert self._eval(detector, _directive(
            "worker_processes", ["1"])) is None


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

    # --- Explicit server_tokens NOT off ---

    def test_server_tokens_on(self, detector):
        result = self._eval(detector, _directive("server_tokens", ["on"]))
        assert result is not None
        assert result["file"] == self.FILEPATH
        assert len(result["remediations"]) == 1
        rem = result["remediations"][0]
        assert rem["action"] == "replace"
        assert rem["directive"] == "server_tokens"
        assert rem["args"] == ["off"]
        assert rem["context"] == self.EXACT_PATH

    def test_server_tokens_build(self, detector):
        result = self._eval(detector, _directive("server_tokens", ["build"]))
        assert result is not None
        rem = result["remediations"][0]
        assert rem["action"] == "replace"
        assert rem["args"] == ["off"]

    # --- http block WITHOUT server_tokens ---

    def test_http_block_missing_server_tokens(self, detector):
        http_dir = _directive("http", [], [_directive("sendfile", ["on"])])
        result = self._eval(detector, http_dir)
        assert result is not None
        rem = result["remediations"][0]
        assert rem["action"] == "add"
        assert rem["directive"] == "server_tokens"
        assert rem["args"] == ["off"]
        assert rem["context"] == self.EXACT_PATH + ["block"]


# ──────────────────────────────────────────────────────────────────────────────
# Section 4 — scan(): full pipeline tests
# ──────────────────────────────────────────────────────────────────────────────

class TestScan:
    """Integration tests exercising BaseRecom.scan() → _traverse_ast() → evaluate()."""

    def test_compliant_http_block(self, detector):
        parser_output = _make_parser_output([
            _directive("http", [], [
                _directive("server_tokens", ["off"]),
                _directive("server", [], [
                    _directive("listen", ["80"])
                ])
            ])
        ])
        findings = detector.scan(parser_output)
        assert findings == []

    def test_non_compliant_missing_server_tokens(self, detector):
        parser_output = _make_parser_output([
            _directive("http", [], [
                _directive("sendfile", ["on"])
            ])
        ])
        findings = detector.scan(parser_output)
        assert len(findings) == 1
        remediations = findings[0]["remediations"]
        assert len(remediations) == 1
        assert remediations[0]["action"] == "add"
        assert remediations[0]["directive"] == "server_tokens"

    def test_non_compliant_server_tokens_on_in_http(self, detector):
        parser_output = _make_parser_output([
            _directive("http", [], [
                _directive("server_tokens", ["on"])
            ])
        ])
        findings = detector.scan(parser_output)
        assert len(findings) == 1
        remediations = findings[0]["remediations"]
        assert len(remediations) == 1
        assert remediations[0]["action"] == "replace"
        assert remediations[0]["args"] == ["off"]

    def test_multiple_server_tokens_violations(self, detector):
        # Test case where it's missing in http, but present with 'on' inside server
        # This will trigger 'add' in http, and 'replace' in server.
        parser_output = _make_parser_output([
            _directive("http", [], [
                _directive("server", [], [
                    _directive("server_tokens", ["on"])
                ])
            ])
        ])
        findings = detector.scan(parser_output)
        assert len(findings) == 1
        remediations = findings[0]["remediations"]
        assert len(remediations) == 2
        actions = [r["action"] for r in remediations]
        assert "add" in actions
        assert "replace" in actions

    def test_non_conf_file_skipped(self, detector):
        parser_output = {
            "config": [
                {
                    "file": "/etc/nginx/nginx",     # no .conf extension
                    "parsed": [_directive("http", [], [])]
                }
            ]
        }
        findings = detector.scan(parser_output)
        assert findings == []
