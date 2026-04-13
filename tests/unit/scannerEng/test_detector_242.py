"""
Unit tests cho Detector242 — CIS Benchmark 2.4.2
"Đảm bảo NGINX từ chối các yêu cầu (requests) dành cho các tên miền (hostnames) không xác định"

Chiến lược Kiểm thử
─────────────
• Phần 1: Metadata Sanity Checks - Kiểm tra ID, title, level, các thuộc tính bắt buộc.
• Phần 2: Kiểm thử hàm evaluate() / logic kiểm tra khối Catch-All (Compliant) - 24 test cases.
• Phần 3: Kiểm thử hàm evaluate() (Non-Compliant) - 15 test cases.
• Phần 4: Kiểm thử hàm scan() toàn bộ đường ống - 20 test cases.
"""

import pytest
from core.scannerEng.recommendations.detector_242 import Detector242


@pytest.fixture
def detector():
    """Trả về một instance Detector242 mới cho mỗi test."""
    return Detector242()


def _dir(directive: str, args: list = None, block: list = None) -> dict:
    """Hàm hỗ trợ: tạo một directive dictionary tối thiểu của crossplane."""
    if args is None:
        args = []
    res = {"directive": directive, "args": args}
    if block is not None:
        res["block"] = block
    return res


def _server_block(directives: list) -> dict:
    """Hàm hỗ trợ: tạo một block 'server' giả lập."""
    return _dir("server", [], directives)


def _http_block(servers: list) -> dict:
    """Hàm hỗ trợ: tạo một block 'http' chứa các 'server'."""
    return _dir("http", [], servers)


def _make_parser_output(parsed_directives: list, filepath: str = "/etc/nginx/nginx.conf") -> dict:
    """Hàm hỗ trợ: bọc các directive trong một cấu trúc parser_output tối thiểu."""
    return {
        "config": [
            {
                "file": filepath,
                "parsed": parsed_directives,
            }
        ]
    }


# ──────────────────────────────────────────────────────────────────────────────
# Phần 1 — Kiểm tra tính đúng đắn của Metadata (4 Test Cases)
# ──────────────────────────────────────────────────────────────────────────────

class TestMetadata:
    def test_id(self, detector):
        assert detector.id == "2.4.2"

    def test_title_contains_unknown_host_names(self, detector):
        assert "unknown host names" in detector.title.lower()

    def test_level_assignment(self, detector):
        # Thông thường được khai báo trong profile hoặc tags
        assert hasattr(detector, "profile") or hasattr(detector, "level")
        # Giả định thuộc tính profile chứa thông tin Level 1
        level_info = getattr(detector, "profile",
                             getattr(detector, "level", ""))
        assert "level 1" in str(level_info).lower()

    def test_has_required_attributes(self, detector):
        for attr in ("description", "audit_procedure", "impact", "remediation"):
            assert getattr(detector, attr, None), f"Missing attribute: {attr}"


# ──────────────────────────────────────────────────────────────────────────────
# Phần 2 — evaluate() hoặc logic kiểm tra Catch-All: Compliant (24 Test Cases)
# ──────────────────────────────────────────────────────────────────────────────

class TestEvaluateCompliant:
    """Các cấu hình hợp lệ có chứa khối server mặc định đón các request không hợp lệ (không vi phạm)."""

    HTTP_CTX = ["http"]
    FILEPATH = "/etc/nginx/nginx.conf"
    EXACT_PATH = ["config", 0, "parsed", 0]

    def _eval(self, detector, directive, ctx=None):
        ctx = ctx or self.HTTP_CTX
        return detector.evaluate(directive, self.FILEPATH, ctx, self.EXACT_PATH)

    # --- Trả về mã lỗi 444 (5 test cases) ---
    def test_return_444_port_80(self, detector):
        server = _server_block(
            [_dir("listen", ["80", "default_server"]), _dir("return", ["444"])])
        assert self._eval(detector, _http_block([server])) is None

    def test_return_444_port_8080(self, detector):
        server = _server_block(
            [_dir("listen", ["8080", "default_server"]), _dir("return", ["444"])])
        assert self._eval(detector, _http_block([server])) is None

    def test_return_444_ip_port(self, detector):
        server = _server_block(
            [_dir("listen", ["127.0.0.1:80", "default_server"]), _dir("return", ["444"])])
        assert self._eval(detector, _http_block([server])) is None

    def test_return_444_ipv6(self, detector):
        server = _server_block(
            [_dir("listen", ["[::]:80", "default_server"]), _dir("return", ["444"])])
        assert self._eval(detector, _http_block([server])) is None

    def test_return_444_implicit_port_80(self, detector):
        server = _server_block(
            [_dir("listen", ["default_server"]), _dir("return", ["444"])])
        assert self._eval(detector, _http_block([server])) is None

    # --- Trả về mã lỗi 4xx khác (4 test cases) ---
    def test_return_400(self, detector):
        server = _server_block(
            [_dir("listen", ["80", "default_server"]), _dir("return", ["400"])])
        assert self._eval(detector, _http_block([server])) is None

    def test_return_401(self, detector):
        server = _server_block(
            [_dir("listen", ["80", "default_server"]), _dir("return", ["401"])])
        assert self._eval(detector, _http_block([server])) is None

    def test_return_403(self, detector):
        server = _server_block(
            [_dir("listen", ["80", "default_server"]), _dir("return", ["403"])])
        assert self._eval(detector, _http_block([server])) is None

    def test_return_404(self, detector):
        server = _server_block(
            [_dir("listen", ["80", "default_server"]), _dir("return", ["404"])])
        assert self._eval(detector, _http_block([server])) is None

    # --- Hỗ trợ HTTPS/TLS (5 test cases) ---
    def test_https_reject_handshake(self, detector):
        server = _server_block([_dir("listen", ["443", "ssl", "default_server"]), _dir(
            "ssl_reject_handshake", ["on"])])
        assert self._eval(detector, _http_block([server])) is None

    def test_https_reject_handshake_ipv6(self, detector):
        server = _server_block([_dir("listen", ["[::]:443", "ssl", "default_server"]), _dir(
            "ssl_reject_handshake", ["on"])])
        assert self._eval(detector, _http_block([server])) is None

    def test_https_reject_handshake_http2(self, detector):
        server = _server_block([_dir("listen", ["443", "ssl", "http2", "default_server"]), _dir(
            "ssl_reject_handshake", ["on"])])
        assert self._eval(detector, _http_block([server])) is None

    def test_https_reject_handshake_quic(self, detector):
        server = _server_block([_dir("listen", ["443", "quic", "default_server"]), _dir(
            "ssl_reject_handshake", ["on"])])
        assert self._eval(detector, _http_block([server])) is None

    def test_https_reject_handshake_custom_port(self, detector):
        server = _server_block([_dir("listen", ["8443", "ssl", "default_server"]), _dir(
            "ssl_reject_handshake", ["on"])])
        assert self._eval(detector, _http_block([server])) is None

    # --- Cấu hình kết hợp HTTP và HTTPS (4 test cases) ---
    def test_mixed_http_https_same_block(self, detector):
        server = _server_block([
            _dir("listen", ["80", "default_server"]),
            _dir("listen", ["443", "ssl", "default_server"]),
            _dir("return", ["444"]),
            _dir("ssl_reject_handshake", ["on"])
        ])
        assert self._eval(detector, _http_block([server])) is None

    def test_mixed_http_https_ipv6_same_block(self, detector):
        server = _server_block([
            _dir("listen", ["[::]:80", "default_server"]),
            _dir("listen", ["[::]:443", "ssl", "default_server"]),
            _dir("return", ["444"]),
            _dir("ssl_reject_handshake", ["on"])
        ])
        assert self._eval(detector, _http_block([server])) is None

    def test_mixed_http_https_separate_blocks(self, detector):
        server1 = _server_block(
            [_dir("listen", ["80", "default_server"]), _dir("return", ["444"])])
        server2 = _server_block([_dir("listen", ["443", "ssl", "default_server"]), _dir(
            "ssl_reject_handshake", ["on"])])
        assert self._eval(detector, _http_block([server1, server2])) is None

    def test_mixed_http_https_return_400_and_ssl(self, detector):
        server = _server_block([
            _dir("listen", ["80", "default_server"]),
            _dir("listen", ["443", "ssl", "default_server"]),
            _dir("return", ["400"]),
            _dir("ssl_reject_handshake", ["on"])
        ])
        assert self._eval(detector, _http_block([server])) is None

    # --- Nhiều tham số trong listen (4 test cases) ---
    def test_listen_multiple_params_deferred(self, detector):
        server = _server_block(
            [_dir("listen", ["80", "default_server", "deferred"]), _dir("return", ["444"])])
        assert self._eval(detector, _http_block([server])) is None

    def test_listen_multiple_params_ipv6only(self, detector):
        server = _server_block(
            [_dir("listen", ["[::]:80", "default_server", "ipv6only=on"]), _dir("return", ["444"])])
        assert self._eval(detector, _http_block([server])) is None

    def test_listen_multiple_params_backlog(self, detector):
        server = _server_block([_dir("listen", ["443", "ssl", "default_server", "backlog=512"]), _dir(
            "ssl_reject_handshake", ["on"])])
        assert self._eval(detector, _http_block([server])) is None

    def test_listen_multiple_params_proxy_protocol(self, detector):
        server = _server_block(
            [_dir("listen", ["80", "proxy_protocol", "default_server"]), _dir("return", ["444"])])
        assert self._eval(detector, _http_block([server])) is None

    # --- Khối catch-all hợp lệ nằm ở file cấu hình khác (2 test cases) ---
    def test_catch_all_in_included_http_file(self, detector):
        # Mô phỏng việc scan ở chế độ tích hợp trả về None hoặc rỗng nếu có 1 file hợp lệ
        parser_output = {
            "config": [
                {"file": "/etc/nginx/nginx.conf",
                    "parsed": [_http_block([_dir("include", ["conf.d/*.conf"])])]},
                {"file": "/etc/nginx/conf.d/catchall.conf", "parsed": [_server_block(
                    [_dir("listen", ["80", "default_server"]), _dir("return", ["444"])])]}
            ]
        }
        assert detector.scan(parser_output) == []

    def test_catch_all_in_included_https_file(self, detector):
        parser_output = {
            "config": [
                {"file": "/etc/nginx/nginx.conf", "parsed": [_http_block([_server_block(
                    [_dir("listen", ["80", "default_server"]), _dir("return", ["444"])])])]},
                {"file": "/etc/nginx/conf.d/ssl.conf", "parsed": [_server_block(
                    [_dir("listen", ["443", "ssl", "default_server"]), _dir("ssl_reject_handshake", ["on"])])]}
            ]
        }
        assert detector.scan(parser_output) == []


# ──────────────────────────────────────────────────────────────────────────────
# Phần 3 — evaluate(): Các trường hợp vi phạm (Non-Compliant) (15 Test Cases)
# ──────────────────────────────────────────────────────────────────────────────

class TestEvaluateNonCompliant:
    """Các cấu hình thiếu sót dẫn đến NGINX không chặn được hostname không hợp lệ."""

    HTTP_CTX = ["http"]
    FILEPATH = "/etc/nginx/nginx.conf"
    EXACT_PATH = ["config", 0, "parsed", 0]

    def _eval(self, detector, directive, ctx=None):
        ctx = ctx or self.HTTP_CTX
        return detector.evaluate(directive, self.FILEPATH, ctx, self.EXACT_PATH)

    # --- Không có default_server (3 test cases) ---
    def test_missing_default_server_http(self, detector):
        server = _server_block(
            [_dir("listen", ["80"]), _dir("return", ["444"])])
        assert self._eval(detector, _http_block([server])) is not None

    def test_missing_default_server_https(self, detector):
        server = _server_block(
            [_dir("listen", ["443", "ssl"]), _dir("ssl_reject_handshake", ["on"])])
        assert self._eval(detector, _http_block([server])) is not None

    def test_missing_default_server_ipv6(self, detector):
        server = _server_block(
            [_dir("listen", ["[::]:80"]), _dir("return", ["400"])])
        assert self._eval(detector, _http_block([server])) is not None

    # --- Có default_server nhưng không chặn (4 test cases) ---
    def test_default_server_returns_200(self, detector):
        server = _server_block(
            [_dir("listen", ["80", "default_server"]), _dir("return", ["200", "OK"])])
        assert self._eval(detector, _http_block([server])) is not None

    def test_default_server_serves_static(self, detector):
        server = _server_block(
            [_dir("listen", ["80", "default_server"]), _dir("root", ["/var/www/html"])])
        assert self._eval(detector, _http_block([server])) is not None

    def test_default_server_proxy_pass(self, detector):
        server = _server_block([_dir("listen", ["80", "default_server"]), _dir(
            "location", ["/"], [_dir("proxy_pass", ["http://backend"])])])
        assert self._eval(detector, _http_block([server])) is not None

    def test_default_server_empty_block(self, detector):
        server = _server_block([_dir("listen", ["80", "default_server"])])
        assert self._eval(detector, _http_block([server])) is not None

    # --- Có default_server với mã lỗi không hợp lệ (2 test cases) ---
    def test_default_server_returns_500(self, detector):
        server = _server_block(
            [_dir("listen", ["80", "default_server"]), _dir("return", ["500"])])
        assert self._eval(detector, _http_block([server])) is not None

    def test_default_server_returns_301(self, detector):
        server = _server_block([_dir("listen", ["80", "default_server"]), _dir(
            "return", ["301", "http://example.com"])])
        assert self._eval(detector, _http_block([server])) is not None

    # --- Thiếu ssl_reject_handshake cho HTTPS (2 test cases) ---
    def test_https_missing_reject_handshake(self, detector):
        server = _server_block(
            [_dir("listen", ["443", "ssl", "default_server"]), _dir("return", ["444"])])
        assert self._eval(detector, _http_block([server])) is not None

    def test_https_reject_handshake_off(self, detector):
        server = _server_block([_dir("listen", ["443", "ssl", "default_server"]), _dir(
            "ssl_reject_handshake", ["off"])])
        assert self._eval(detector, _http_block([server])) is not None

    # --- Kiểm tra cấu trúc dữ liệu phản hồi (4 test cases) ---
    def test_response_file_path(self, detector):
        server = _server_block(
            [_dir("listen", ["80"]), _dir("return", ["200"])])
        result = self._eval(detector, _http_block([server]))
        assert result["file"] == self.FILEPATH

    def test_response_remediations_is_list(self, detector):
        server = _server_block(
            [_dir("listen", ["80"]), _dir("return", ["200"])])
        result = self._eval(detector, _http_block([server]))
        assert isinstance(result["remediations"], list)
        assert len(result["remediations"]) >= 1

    def test_response_action_is_add_or_replace(self, detector):
        server = _server_block(
            [_dir("listen", ["80"]), _dir("return", ["200"])])
        result = self._eval(detector, _http_block([server]))
        action = result["remediations"][0]["action"]
        assert action in ["add", "replace"]

    def test_response_directive_is_server(self, detector):
        server = _server_block(
            [_dir("listen", ["80"]), _dir("return", ["200"])])
        result = self._eval(detector, _http_block([server]))
        assert result["remediations"][0]["directive"] == "server"


# ──────────────────────────────────────────────────────────────────────────────
# Phần 4 — scan(): Toàn bộ đường ống (Full Pipeline Integration) (20 Test Cases)
# ──────────────────────────────────────────────────────────────────────────────

class TestScan:
    """Kiểm tra tích hợp với mô phỏng dữ liệu AST đầy đủ."""

    # --- Cấu hình an toàn đầy đủ (4 test cases) ---
    def test_full_secure_http_only(self, detector):
        parser_output = _make_parser_output([_http_block([
            _server_block(
                [_dir("listen", ["80", "default_server"]), _dir("return", ["444"])])
        ])])
        assert detector.scan(parser_output) == []

    def test_full_secure_http_and_https(self, detector):
        parser_output = _make_parser_output([_http_block([
            _server_block(
                [_dir("listen", ["80", "default_server"]), _dir("return", ["444"])]),
            _server_block([_dir("listen", ["443", "ssl", "default_server"]), _dir(
                "ssl_reject_handshake", ["on"])])
        ])])
        assert detector.scan(parser_output) == []

    def test_secure_mixed_with_app_servers(self, detector):
        parser_output = _make_parser_output([_http_block([
            _server_block(
                [_dir("listen", ["80", "default_server"]), _dir("return", ["444"])]),
            _server_block([_dir("listen", ["80"]), _dir(
                "server_name", ["app.com"]), _dir("return", ["200"])])
        ])])
        assert detector.scan(parser_output) == []

    def test_secure_ipv4_ipv6_catchall(self, detector):
        parser_output = _make_parser_output([_http_block([
            _server_block([
                _dir("listen", ["80", "default_server"]),
                _dir("listen", ["[::]:80", "default_server"]),
                _dir("return", ["444"])
            ]),
            _server_block([_dir("listen", ["80"]), _dir(
                "server_name", ["app2.com"]), _dir("return", ["200"])])
        ])])
        assert detector.scan(parser_output) == []

    # --- Chỉ có các server block thông thường (4 test cases) ---
    def test_normal_http_only_apps_fails(self, detector):
        parser_output = _make_parser_output([_http_block([
            _server_block(
                [_dir("listen", ["80"]), _dir("server_name", ["app.com"])])
        ])])
        findings = detector.scan(parser_output)
        assert len(findings) == 1

    def test_normal_https_only_apps_fails(self, detector):
        parser_output = _make_parser_output([_http_block([
            _server_block([_dir("listen", ["443", "ssl"]),
                          _dir("server_name", ["app.com"])])
        ])])
        findings = detector.scan(parser_output)
        assert len(findings) == 1

    def test_normal_mixed_apps_fails(self, detector):
        parser_output = _make_parser_output([_http_block([
            _server_block([_dir("listen", ["80"]), _dir(
                "server_name", ["app1.com"])]),
            _server_block([_dir("listen", ["443", "ssl"]),
                          _dir("server_name", ["app2.com"])])
        ])])
        findings = detector.scan(parser_output)
        assert len(findings) == 1

    def test_multiple_normal_apps_fails(self, detector):
        parser_output = _make_parser_output([_http_block([
            _server_block([_dir("listen", ["80"]), _dir("server_name", [f"app{i}.com"])]) for i in range(10)
        ])])
        findings = detector.scan(parser_output)
        assert len(findings) == 1

    # --- Gom nhóm lỗi (Grouping) (2 test cases) ---
    def test_grouping_multiple_files_missing_catchall(self, detector):
        parser_output = {
            "config": [
                {"file": "/etc/nginx/nginx.conf",
                    "parsed": [_http_block([_dir("include", ["conf.d/*.conf"])])]},
                {"file": "/etc/nginx/conf.d/1.conf", "parsed": [_server_block(
                    [_dir("listen", ["80"]), _dir("server_name", ["a.com"])])]},
                {"file": "/etc/nginx/conf.d/2.conf", "parsed": [_server_block(
                    [_dir("listen", ["80"]), _dir("server_name", ["b.com"])])]},
                {"file": "/etc/nginx/conf.d/3.conf", "parsed": [_server_block(
                    [_dir("listen", ["80"]), _dir("server_name", ["c.com"])])]},
                {"file": "/etc/nginx/conf.d/4.conf", "parsed": [_server_block(
                    [_dir("listen", ["80"]), _dir("server_name", ["d.com"])])]},
                {"file": "/etc/nginx/conf.d/5.conf", "parsed": [_server_block(
                    [_dir("listen", ["80"]), _dir("server_name", ["e.com"])])]}
            ]
        }
        findings = detector.scan(parser_output)
        assert len(findings) == 1
        assert findings[0]["file"] == "/etc/nginx/nginx.conf"

    def test_grouping_http_and_https_missing_in_one_remediation(self, detector):
        parser_output = _make_parser_output([_http_block([
            _server_block([_dir("listen", ["80"]), _dir(
                "server_name", ["app1.com"])]),
            _server_block([_dir("listen", ["443", "ssl"]),
                          _dir("server_name", ["app2.com"])])
        ])])
        findings = detector.scan(parser_output)
        assert len(findings) == 1
        assert len(findings[0]["remediations"]) >= 1

    # --- Khối catch-all bị comment hoặc vô hiệu hóa (3 test cases) ---
    def test_commented_catch_all_missing(self, detector):
        # crossplane bỏ qua comments, nên list parsed sẽ rỗng nếu block bị comment
        parser_output = _make_parser_output([_http_block([
            _server_block(
                [_dir("listen", ["80"]), _dir("server_name", ["app.com"])])
        ])])
        findings = detector.scan(parser_output)
        assert len(findings) == 1

    def test_commented_return_444_non_compliant(self, detector):
        # Mô phỏng return 444 bị comment
        parser_output = _make_parser_output([_http_block([
            _server_block([_dir("listen", ["80", "default_server"])])
        ])])
        findings = detector.scan(parser_output)
        assert len(findings) == 1

    def test_commented_ssl_reject_non_compliant(self, detector):
        # Mô phỏng ssl_reject_handshake bị comment
        parser_output = _make_parser_output([_http_block([
            _server_block([_dir("listen", ["443", "ssl", "default_server"])])
        ])])
        findings = detector.scan(parser_output)
        assert len(findings) == 1

    # --- Hỗn hợp HTTP và HTTPS (3 test cases) ---
    def test_mixed_has_http_catchall_missing_https(self, detector):
        parser_output = _make_parser_output([_http_block([
            _server_block(
                [_dir("listen", ["80", "default_server"]), _dir("return", ["444"])]),
            _server_block([_dir("listen", ["443", "ssl"]),
                          _dir("server_name", ["app.com"])])
        ])])
        findings = detector.scan(parser_output)
        assert len(findings) == 1
        # Nên báo cáo thêm khối HTTPS

    def test_mixed_has_https_catchall_missing_http(self, detector):
        parser_output = _make_parser_output([_http_block([
            _server_block([_dir("listen", ["443", "ssl", "default_server"]), _dir(
                "ssl_reject_handshake", ["on"])]),
            _server_block(
                [_dir("listen", ["80"]), _dir("server_name", ["app.com"])])
        ])])
        findings = detector.scan(parser_output)
        assert len(findings) == 1
        # Nên báo cáo thêm khối HTTP

    def test_mixed_both_present_but_http_returns_200(self, detector):
        parser_output = _make_parser_output([_http_block([
            _server_block(
                [_dir("listen", ["80", "default_server"]), _dir("return", ["200"])]),
            _server_block([_dir("listen", ["443", "ssl", "default_server"]), _dir(
                "ssl_reject_handshake", ["on"])])
        ])])
        findings = detector.scan(parser_output)
        assert len(findings) == 1

    # --- Tính toàn vẹn của kết quả Schema (4 test cases) ---
    def test_schema_context_is_correct(self, detector):
        parser_output = _make_parser_output([_http_block([
            _server_block(
                [_dir("listen", ["80"]), _dir("server_name", ["app.com"])])
        ])])
        findings = detector.scan(parser_output)
        assert "context" in findings[0]["remediations"][0]

    def test_schema_action_is_add(self, detector):
        parser_output = _make_parser_output([_http_block([
            _server_block(
                [_dir("listen", ["80"]), _dir("server_name", ["app.com"])])
        ])])
        findings = detector.scan(parser_output)
        assert findings[0]["remediations"][0]["action"] == "add"

    def test_schema_remediation_targets_nginx_conf(self, detector):
        parser_output = _make_parser_output([_http_block([
            _server_block(
                [_dir("listen", ["80"]), _dir("server_name", ["app.com"])])
        ])], filepath="/etc/nginx/nginx.conf")
        findings = detector.scan(parser_output)
        assert findings[0]["file"] == "/etc/nginx/nginx.conf"

    def test_schema_remediation_contains_block(self, detector):
        parser_output = _make_parser_output([_http_block([
            _server_block(
                [_dir("listen", ["80"]), _dir("server_name", ["app.com"])])
        ])])
        findings = detector.scan(parser_output)
        assert "block" in findings[0]["remediations"][0] or "directive" in findings[0]["remediations"][0]
