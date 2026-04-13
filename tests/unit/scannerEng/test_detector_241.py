"""
Unit tests for Detector241 — CIS Benchmark 2.4.1
"Ensure NGINX only listens for network connections on authorized ports"

Test Strategy
─────────────
• evaluate() tests — isolate the directive-level logic directly.
  All combinations of compliant / non-compliant listen values are tested.

• scan() tests — exercise the full AST traversal + grouping pipeline
  that BaseRecom provides, with synthetic parser_output payloads.

Authorized ports: 80, 443, 8080, 3000
"""

import pytest
from core.scannerEng.recommendations.detector_241 import Detector241


# Fixtures
@pytest.fixture
def detector():
    """Return a fresh Detector241 instance for every test."""
    d = Detector241()
    d.authorized_ports = ["80", "443", "8080", "3000"]
    return d


def _listen_directive(args: list) -> dict:
    """Helper: build a minimal 'listen' crossplane directive dict."""
    return {"directive": "listen", "args": args}


def _server_block(listen_args_list: list) -> dict:
    """
    Helper: build a synthetic 'http > server' crossplane block containing
    one 'listen' directive per entry in listen_args_list.
    """
    listen_directives = [_listen_directive(args) for args in listen_args_list]
    return {
        "directive": "http",
        "args": [],
        "block": [
            {
                "directive": "server",
                "args": [],
                "block": listen_directives,
            }
        ],
    }


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
        assert detector.id == "2.4.1"

    def test_title_contains_authorized_ports(self, detector):
        assert "authorized ports" in detector.title.lower()

    def test_authorized_ports(self, detector):
        assert "80" in detector.authorized_ports
        assert "443" in detector.authorized_ports

    def test_has_required_attributes(self, detector):
        for attr in ("description", "audit_procedure", "impact", "remediation"):
            assert getattr(detector, attr, None), f"Missing attribute: {attr}"


# ──────────────────────────────────────────────────────────────────────────────
# Section 2 — evaluate(): compliant cases (must return None)
# ──────────────────────────────────────────────────────────────────────────────

class TestEvaluateCompliant:
    """Directives that should NOT trigger an uncompliance finding."""

    SERVER_CTX = ["http", "server"]
    FILEPATH = "/etc/nginx/nginx.conf"
    EXACT_PATH = ["config", 0, "parsed", 0, "block", 0, "block", 0]

    def _eval(self, detector, directive, ctx=None):
        ctx = ctx or self.SERVER_CTX
        return detector.evaluate(directive, self.FILEPATH, ctx, self.EXACT_PATH)

    # --- Authorized ports (bare numeric) ---

    def test_listen_port_80(self, detector):
        assert self._eval(detector, _listen_directive(["80"])) is None

    def test_listen_port_443_default_server(self, detector):
        assert self._eval(detector, _listen_directive(
            ["443", "default_server"])) is None

    def test_listen_port_8080(self, detector):
        assert self._eval(detector, _listen_directive(["8080"])) is None

    def test_listen_port_3000_default_server(self, detector):
        assert self._eval(detector, _listen_directive(
            ["3000", "default_server"])) is None

    # --- Authorized ports with SSL/QUIC qualifiers (args[0] is still the port) ---

    def test_listen_443_ssl(self, detector):
        assert self._eval(detector, _listen_directive(["443", "ssl"])) is None

    def test_listen_443_quic(self, detector):
        assert self._eval(detector, _listen_directive(["443", "quic"])) is None

    # --- IP:port format ---

    def test_listen_ip_port_80(self, detector):
        assert self._eval(detector, _listen_directive(
            ["127.0.0.1:80"])) is None

    def test_listen_ip_port_443(self, detector):
        assert self._eval(detector, _listen_directive(["0.0.0.0:443"])) is None

    def test_listen_ip_port_8080(self, detector):
        assert self._eval(detector, _listen_directive(
            ["127.0.0.1:8080"])) is None

    def test_listen_ip_port_3000_default_server(self, detector):
        assert self._eval(detector, _listen_directive(
            ["127.0.0.1:3000", "default_server"])) is None

    def test_listen_ip_port_192_443(self, detector):
        assert self._eval(detector, _listen_directive(
            ["192.168.1.10:443"])) is None

    # --- IPv6 format ---

    def test_listen_ipv6_port_80(self, detector):
        assert self._eval(detector, _listen_directive(["[::]:80"])) is None

    def test_listen_ipv6_port_443(self, detector):
        assert self._eval(detector, _listen_directive(["[::]:443"])) is None

    def test_listen_ipv6_loopback_443(self, detector):
        assert self._eval(detector, _listen_directive(["[::1]:443"])) is None

    # --- Unix socket (must be ignored — not a network port) ---

    def test_listen_unix_socket(self, detector):
        assert self._eval(detector, _listen_directive(
            ["unix:/run/nginx.sock"])) is None

    def test_listen_unix_socket_with_trailing_args(self, detector):
        assert self._eval(detector, _listen_directive(
            ["unix:/var/run/nginx.sock", "default_server"])) is None

    # --- Non-numeric bare value (e.g. hostname) → Nginx defaults to port 80 → compliant ---

    def test_listen_hostname_treated_as_80(self, detector):
        """'listen localhost' → nginx defaults to port 80 → no violation."""
        assert self._eval(detector, _listen_directive(["localhost"])) is None

    def test_listen_star_treated_as_80(self, detector):
        """'listen *' → nginx defaults to port 80 → no violation."""
        assert self._eval(detector, _listen_directive(["*"])) is None

    # --- Empty args → skip gracefully ---

    def test_listen_empty_args(self, detector):
        assert self._eval(detector, _listen_directive([])) is None

    # --- Not a listen directive → ignored ---

    def test_non_listen_directive_server_name(self, detector):
        d = {"directive": "server_name", "args": ["example.com"]}
        assert self._eval(detector, d) is None

    def test_non_listen_directive_root(self, detector):
        d = {"directive": "root", "args": ["/var/www/html"]}
        assert self._eval(detector, d) is None

    # --- listen directive but NOT inside a server block → ignored ---

    def test_listen_outside_server_context_empty(self, detector):
        """Context is [], not inside any server."""
        result = detector.evaluate(
            _listen_directive(["443 default_server"]),
            self.FILEPATH,
            [],        # no server in context
            self.EXACT_PATH,
        )
        assert result is None

    def test_listen_in_events_context(self, detector):
        result = detector.evaluate(
            _listen_directive(["8080"]),
            self.FILEPATH,
            ["events"],  # server not in context
            self.EXACT_PATH,
        )
        assert result is None

    def test_listen_in_http_context_only(self, detector):
        """listen inside http but NOT directly in server block."""
        result = detector.evaluate(
            _listen_directive(["3000"]),
            self.FILEPATH,
            ["http"],   # no "server" in context
            self.EXACT_PATH,
        )
        assert result is None


# ──────────────────────────────────────────────────────────────────────────────
# Section 3 — evaluate(): non-compliant cases (must return uncompliances)
# ──────────────────────────────────────────────────────────────────────────────

class TestEvaluateNonCompliant:
    """Directives that SHOULD trigger an uncompliance finding."""

    SERVER_CTX = ["http", "server"]
    FILEPATH = "/etc/nginx/sites-enabled/app.conf"
    EXACT_PATH = ["config", 0, "parsed", 0, "block", 0, "block", 0]

    def _eval(self, detector, directive, ctx=None):
        ctx = ctx or self.SERVER_CTX
        return detector.evaluate(directive, self.FILEPATH, ctx, self.EXACT_PATH)

    # --- Common non-authorized bare ports ---

    def test_listen_port_8089(self, detector):
        result = self._eval(detector, _listen_directive(["8089"]))
        assert result is not None

    def test_listen_port_8443_default_server(self, detector):
        result = self._eval(detector, _listen_directive(
            ["8443", "default_server"]))
        assert result is not None

    def test_listen_port_3099(self, detector):
        result = self._eval(detector, _listen_directive(["3099"]))
        assert result is not None

    def test_listen_port_22(self, detector):
        result = self._eval(detector, _listen_directive(["22"]))
        assert result is not None

    def test_listen_port_9090_default_server(self, detector):
        result = self._eval(detector, _listen_directive(
            ["9090", "default_server"]))
        assert result is not None

    # --- IP:port format with unauthorized port ---

    def test_listen_ip_port_8089(self, detector):
        result = self._eval(detector, _listen_directive(["127.0.0.1:8089"]))
        assert result is not None

    def test_listen_ip_port_3099(self, detector):
        result = self._eval(detector, _listen_directive(["192.168.0.1:3099"]))
        assert result is not None

    # --- IPv6 with unauthorized port ---

    def test_listen_ipv6_port_8089(self, detector):
        result = self._eval(detector, _listen_directive(["[::]:8089"]))
        assert result is not None

    def test_listen_ipv6_port_9090(self, detector):
        result = self._eval(detector, _listen_directive(["[::1]:9090"]))
        assert result is not None

    # ── Remediation payload structure checks ──────────────────────────────────

    def test_result_contains_file(self, detector):
        result = self._eval(detector, _listen_directive(["8089"]))
        assert result["file"] == self.FILEPATH

    def test_result_has_remediations_list(self, detector):
        result = self._eval(detector, _listen_directive(
            ["3099", "default_server"]))
        assert isinstance(result["remediations"], list)
        assert len(result["remediations"]) == 1

    def test_remediation_action_is_delete(self, detector):
        result = self._eval(detector, _listen_directive(["8089"]))
        remediation = result["remediations"][0]
        assert remediation["action"] == "delete"

    def test_remediation_directive_is_listen(self, detector):
        result = self._eval(detector, _listen_directive(
            ["3099", "default_server"]))
        remediation = result["remediations"][0]
        assert remediation["directive"] == "listen"

    def test_remediation_context_matches_exact_path(self, detector):
        result = self._eval(detector, _listen_directive(["8089"]))
        remediation = result["remediations"][0]
        assert remediation["context"] == self.EXACT_PATH

    def test_remediation_context_is_exact_path_reference(self, detector):
        """exact_path passed in must be preserved exactly (by reference or value)."""
        custom_path = ["config", 2, "parsed", 7, "block", 3, "block", 1]
        result = detector.evaluate(
            _listen_directive(["8089"]),
            self.FILEPATH,
            self.SERVER_CTX,
            custom_path,
        )
        assert result["remediations"][0]["context"] == custom_path


# ──────────────────────────────────────────────────────────────────────────────
# Section 4 — scan(): full pipeline tests
# ──────────────────────────────────────────────────────────────────────────────

class TestScan:
    """Integration tests exercising BaseRecom.scan() → _traverse_ast() → evaluate()."""

    # --- Fully compliant configs produce no findings ---

    def test_all_compliant_ports_returns_empty(self, detector):
        parser_output = _make_parser_output([
            _server_block([["80"], ["443", "ssl"], ["8080"],
                          ["3000", "default_server"]])
        ])
        findings = detector.scan(parser_output)
        assert findings == []

    def test_empty_config_list_returns_empty(self, detector):
        findings = detector.scan({"config": []})
        assert findings == []

    def test_unix_socket_only_returns_empty(self, detector):
        parser_output = _make_parser_output([
            _server_block([["unix:/run/nginx.sock"]])
        ])
        findings = detector.scan(parser_output)
        assert findings == []

    def test_non_conf_file_skipped(self, detector):
        """Files not ending in .conf must be skipped by BaseRecom.scan()."""
        parser_output = {
            "config": [
                {
                    "file": "/etc/nginx/nginx",     # no .conf extension
                    "parsed": [_server_block([["8080"]])]
                }
            ]
        }
        findings = detector.scan(parser_output)
        assert findings == []

    # --- Single violation ---

    def test_single_unauthorized_port_detected(self, detector):
        parser_output = _make_parser_output([
            _server_block([["8089"]])
        ])
        findings = detector.scan(parser_output)
        assert len(findings) == 1

    def test_single_violation_file_path_correct(self, detector):
        path = "/etc/nginx/sites-enabled/test.conf"
        parser_output = _make_parser_output(
            [_server_block([["3099"]])], filepath=path)
        findings = detector.scan(parser_output)
        assert findings[0]["file"] == path

    def test_single_violation_action_is_delete(self, detector):
        parser_output = _make_parser_output(
            [_server_block([["8089", "default_server"]])])
        findings = detector.scan(parser_output)
        assert findings[0]["remediations"][0]["action"] == "delete"

    def test_single_violation_directive_is_listen(self, detector):
        parser_output = _make_parser_output(
            [_server_block([["3099", "default_server"]])])
        findings = detector.scan(parser_output)
        assert findings[0]["remediations"][0]["directive"] == "listen"

    # --- Multiple violations in one server block are grouped into one file entry ---

    def test_two_violations_same_file_grouped(self, detector):
        parser_output = _make_parser_output([
            _server_block([["8089"], ["3099", "default_server"]])
        ])
        findings = detector.scan(parser_output)
        # One file entry only (grouping by file)
        assert len(findings) == 1
        assert len(findings[0]["remediations"]) == 2

    def test_three_violations_same_file_grouped(self, detector):
        parser_output = _make_parser_output([
            _server_block([["8089"], ["3099", "default_server"], ["8433"]])
        ])
        findings = detector.scan(parser_output)
        assert len(findings) == 1
        assert len(findings[0]["remediations"]) == 3

    # --- Mixed compliant + non-compliant in same block ---

    def test_mixed_listen_only_unauthorized_flagged(self, detector):
        """80 is OK, 443 is OK, 8089 should be the only violation."""
        parser_output = _make_parser_output([
            _server_block([["80"], ["443", "ssl"], ["8089"]])
        ])
        findings = detector.scan(parser_output)
        assert len(findings) == 1
        assert len(findings[0]["remediations"]) == 1

    def test_mixed_listen_only_authorized_unflagged(self, detector):
        """8080 is OK, 8089 and 3099 should be flagged."""
        parser_output = _make_parser_output([
            _server_block([["8080"], ["8089"], ["3099", "default_server"]])
        ])
        findings = detector.scan(parser_output)
        assert len(findings) == 1
        assert len(findings[0]["remediations"]) == 2

    # --- Multiple files (multiple config entries) ---

    def test_violations_across_two_files(self, detector):
        parser_output = {
            "config": [
                {
                    "file": "/etc/nginx/conf.d/app1.conf",
                    "parsed": [_server_block([["8089"]])],
                },
                {
                    "file": "/etc/nginx/conf.d/app2.conf",
                    "parsed": [_server_block([["3099"]])],
                },
            ]
        }
        findings = detector.scan(parser_output)
        assert len(findings) == 2
        files = {f["file"] for f in findings}
        assert "/etc/nginx/conf.d/app1.conf" in files
        assert "/etc/nginx/conf.d/app2.conf" in files
        assert len(findings[0]["remediations"]) == 1
        assert len(findings[1]["remediations"]) == 1

    def test_one_clean_file_one_dirty_file(self, detector):
        parser_output = {
            "config": [
                {
                    "file": "/etc/nginx/conf.d/clean.conf",
                    "parsed": [_server_block([["80"], ["443", "ssl"]])],
                },
                {
                    "file": "/etc/nginx/conf.d/dirty.conf",
                    "parsed": [_server_block([["8089", "default_server"]])],
                },
            ]
        }
        findings = detector.scan(parser_output)
        assert len(findings) == 1
        assert findings[0]["file"] == "/etc/nginx/conf.d/dirty.conf"
        assert len(findings[0]["remediations"]) == 1

    # --- listen directive in non-server context must not produce false positives ---

    def test_listen_in_http_context_not_flagged(self, detector):
        """A 'listen' directive sitting directly inside 'http' (not server) must be skipped."""
        parser_output = _make_parser_output([
            {
                "directive": "http",
                "args": [],
                "block": [
                    # listen at http level (no server wrapping)
                    {"directive": "listen", "args": ["8089"]},
                ],
            }
        ])
        findings = detector.scan(parser_output)
        assert findings == []

    def test_listen_in_events_context_not_flagged(self, detector):
        """A 'listen' directive sitting inside 'events' (not server) must be skipped."""
        parser_output = _make_parser_output([
            {
                "directive": "events",
                "args": [],
                "block": [
                    {"directive": "listen", "args": ["8089"]},
                ],
            }
        ])
        findings = detector.scan(parser_output)
        assert findings == []

    def test_listen_at_top_level_not_flagged(self, detector):
        """A 'listen' directive sitting at the top level (not inside any block) must be skipped."""
        parser_output = _make_parser_output([
            {"directive": "listen", "args": ["8089"]},
        ])
        findings = detector.scan(parser_output)
        assert findings == []

    # --- IPv6 unauthorized port via scan ---

    def test_ipv6_unauthorized_port_via_scan(self, detector):
        parser_output = _make_parser_output([
            _server_block([["[::]:3099"]])
        ])
        findings = detector.scan(parser_output)
        assert len(findings) == 1

    # --- Result schema completeness ---

    def test_scan_result_keys(self, detector):
        parser_output = _make_parser_output([_server_block([["8089"]])])
        findings = detector.scan(parser_output)
        result = findings[0]
        assert "file" in result
        assert "remediations" in result

    def test_scan_remediation_keys(self, detector):
        parser_output = _make_parser_output([_server_block([["3099"]])])
        findings = detector.scan(parser_output)
        remediation = findings[0]["remediations"][0]
        assert "action" in remediation
        assert "directive" in remediation
        assert "context" in remediation
