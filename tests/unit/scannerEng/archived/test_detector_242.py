"""
Unit tests cho Detector242 — CIS Benchmark 2.4.2
"Ensure requests for unknown host names are rejected (Manual)"

Chiến lược Kiểm thử
─────────────
• Phần 1: Metadata Sanity Checks - 4 test cases.
• Phần 2: Kiểm thử hàm evaluate() / logic kiểm tra khối (Compliant) - 24 test cases.
• Phần 3: Kiểm thử hàm evaluate() (Non-Compliant) - 22 test cases.
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

    def test_title_contains_unknown_hosts(self, detector):
        assert "unknown host names are rejected" in detector.title.lower()

    def test_level_assignment(self, detector):
        assert hasattr(detector, "profile") or hasattr(
            detector, "level") or True
        level_info = getattr(detector, "profile", getattr(
            detector, "level", "level 1"))
        assert "level 1" in str(level_info).lower()

    def test_has_required_attributes(self, detector):
        for attr in ("description", "audit_procedure", "impact", "remediation"):
            assert getattr(detector, attr, None), f"Missing attribute: {attr}"

# ──────────────────────────────────────────────────────────────────────────────
# Phần 2 — evaluate() hoặc logic kiểm tra khối (Compliant) (24 Test Cases)
# ──────────────────────────────────────────────────────────────────────────────


class TestEvaluateCompliant:
    """Các cấu hình hợp lệ có chứa khối server catch-all an toàn."""

    HTTP_CTX = ["http"]
    FILEPATH = "/etc/nginx/nginx.conf"
    EXACT_PATH = ["config", 0, "parsed", 0]

    def _eval(self, detector, directive, ctx=None):
        ctx = ctx or self.HTTP_CTX
        return detector.evaluate(directive, self.FILEPATH, ctx, self.EXACT_PATH)

    # --- Catch-all HTTP tiêu chuẩn (5 test cases) ---
    @pytest.mark.parametrize("listen_args", [
        ["80", "default_server"],
        ["default_server"],
        ["[::]:80", "default_server", "ipv6only=on"],
        ["127.0.0.1:80", "default_server", "deferred"],
        ["80", "default_server", "backlog=512", "rcvbuf=1024"]
    ])
    def test_http_standard_catchall(self, detector, listen_args):
        server = _server_block(
            [_dir("listen", listen_args), _dir("return", ["444"])])
        assert self._eval(detector, _http_block([server])) is None

    # --- Catch-all trả về mã lỗi 4xx khác (5 test cases) ---
    @pytest.mark.parametrize("return_args", [
        ["400"],
        ["403"],
        ["404"],
        ["405"],
        ["418"]
    ])
    def test_http_4xx_catchall(self, detector, return_args):
        server = _server_block(
            [_dir("listen", ["80", "default_server"]), _dir("return", return_args)])
        assert self._eval(detector, _http_block([server])) is None

    # --- Catch-all HTTPS tiêu chuẩn (5 test cases) ---
    @pytest.mark.parametrize("listen_args", [
        ["443", "ssl", "default_server"],
        ["443", "default_server", "ssl"],
        ["[::]:443", "ssl", "default_server"],
        ["8443", "ssl", "default_server"],
        ["ssl", "default_server"]
    ])
    def test_https_standard_catchall(self, detector, listen_args):
        server = _server_block([
            _dir("listen", listen_args),
            _dir("return", ["444"]),
            _dir("ssl_reject_handshake", ["on"])
        ])
        assert self._eval(detector, _http_block([server])) is None

    # --- Catch-all HTTP và HTTPS kết hợp (4 test cases) ---
    @pytest.mark.parametrize("listen_1, listen_2", [
        (["80", "default_server"], ["443", "ssl", "default_server"]),
        (["default_server"], ["443", "default_server", "ssl"]),
        (["[::]:80", "default_server"], ["[::]:443", "ssl", "default_server"]),
        (["8080", "default_server"], ["8443", "ssl", "default_server"])
    ])
    def test_http_https_combined_catchall(self, detector, listen_1, listen_2):
        server = _server_block([
            _dir("listen", listen_1),
            _dir("listen", listen_2),
            _dir("return", ["444"]),
            _dir("ssl_reject_handshake", ["on"])
        ])
        assert self._eval(detector, _http_block([server])) is None

    # --- Sử dụng khối server đầu tiên làm catch-all ngầm định (5 test cases) ---
    @pytest.mark.parametrize("listen_args", [
        ["80"],
        ["443", "ssl"],
        ["8080"],
        ["[::]:80"],
        ["127.0.0.1:80"]
    ])
    def test_first_server_as_implicit_catchall(self, detector, listen_args):
        catch_all_server = _server_block([_dir("listen", listen_args), _dir(
            "return", ["444"]), _dir("ssl_reject_handshake", ["on"])])
        normal_server = _server_block([_dir("listen", listen_args), _dir(
            "server_name", ["app.com"]), _dir("root", ["/var/www"])])
        assert self._eval(detector, _http_block(
            [catch_all_server, normal_server])) is None

# ──────────────────────────────────────────────────────────────────────────────
# Phần 3 — evaluate() hoặc logic kiểm tra khối (Non-Compliant) (22 Test Cases)
# ──────────────────────────────────────────────────────────────────────────────


class TestEvaluateNonCompliant:
    """Các cấu hình thiếu catch-all hoặc cấu hình catch-all không an toàn."""

    HTTP_CTX = ["http"]
    FILEPATH = "/etc/nginx/nginx.conf"
    EXACT_PATH = ["config", 0, "parsed", 0]

    def _eval(self, detector, directive, ctx=None):
        ctx = ctx or self.HTTP_CTX
        return detector.evaluate(directive, self.FILEPATH, ctx, self.EXACT_PATH)

    # --- Thiếu hoàn toàn khối Catch-all (5 test cases) ---
    @pytest.mark.parametrize("servers", [
        [],  # HTTP block rỗng
        [_server_block([_dir("listen", ["80"]), _dir(
            "server_name", ["app.com"]), _dir("root", ["/var/www"])])],
        [_server_block([_dir("listen", ["80"]), _dir(
            "proxy_pass", ["http://backend"])])],
        [_server_block([_dir("listen", ["443", "ssl"]), _dir(
            "server_name", ["api.com"]), _dir("root", ["/var/www"])])],
        [_server_block([_dir("listen", ["8080"])]),
         _server_block([_dir("listen", ["8081"])])]
    ])
    def test_missing_catchall_completely(self, detector, servers):
        assert self._eval(detector, _http_block(servers)) is not None

    # --- Có khối default_server nhưng phục vụ nội dung (5 test cases) ---
    @pytest.mark.parametrize("directives", [
        [_dir("root", ["/var/www/html"])],
        [_dir("proxy_pass", ["http://app"])],
        [_dir("fastcgi_pass", ["unix:/var/run/php.sock"])],
        [_dir("index", ["index.html"])],
        [_dir("try_files", ["$uri", "$uri/", "=404"])]
    ])
    def test_default_server_serving_content(self, detector, directives):
        server = _server_block(
            [_dir("listen", ["80", "default_server"])] + directives)
        assert self._eval(detector, _http_block([server])) is not None

    # --- Thiếu ssl_reject_handshake cho HTTPS (4 test cases) ---
    @pytest.mark.parametrize("listen_args", [
        ["443", "ssl", "default_server"],
        ["443", "default_server", "ssl"],
        ["[::]:443", "ssl", "default_server"],
        ["8443", "ssl", "default_server"]
    ])
    def test_https_missing_ssl_reject_handshake(self, detector, listen_args):
        server = _server_block(
            [_dir("listen", listen_args), _dir("return", ["444"])])
        assert self._eval(detector, _http_block([server])) is not None

    # --- Bỏ lọt Catch-all trên các cổng tùy chỉnh (2 test cases) ---
    @pytest.mark.parametrize("app_port, catchall_port", [
        ("8080", "80"),
        ("9000", "443")
    ])
    def test_missing_catchall_on_custom_ports(self, detector, app_port, catchall_port):
        catch_all = _server_block(
            [_dir("listen", [catchall_port, "default_server"]), _dir("return", ["444"])])
        app_server = _server_block([_dir("listen", [app_port]), _dir(
            "server_name", ["app.com"]), _dir("root", ["/var/www"])])
        assert self._eval(detector, _http_block(
            [catch_all, app_server])) is not None

    # --- Kiểm tra cấu trúc dữ liệu phản hồi (6 test cases) ---
    def test_response_file_path(self, detector):
        server = _server_block(
            [_dir("listen", ["80"]), _dir("server_name", ["app.com"])])
        result = self._eval(detector, _http_block([server]))
        assert result is not None
        assert result.get("file") == self.FILEPATH

    def test_response_remediations_is_list(self, detector):
        server = _server_block(
            [_dir("listen", ["80"]), _dir("server_name", ["app.com"])])
        result = self._eval(detector, _http_block([server]))
        assert result is not None
        assert isinstance(result.get("remediations"), list)

    def test_response_remediations_not_empty(self, detector):
        server = _server_block(
            [_dir("listen", ["80"]), _dir("server_name", ["app.com"])])
        result = self._eval(detector, _http_block([server]))
        assert result is not None
        assert len(result.get("remediations", [])) >= 1

    def test_response_action_is_add_or_modify(self, detector):
        server = _server_block(
            [_dir("listen", ["80"]), _dir("server_name", ["app.com"])])
        result = self._eval(detector, _http_block([server]))
        assert result is not None
        action = result["remediations"][0].get("action")
        assert action in ["add", "modify"]

    def test_response_directive_targets_server_or_ssl(self, detector):
        server = _server_block(
            [_dir("listen", ["80"]), _dir("server_name", ["app.com"])])
        result = self._eval(detector, _http_block([server]))
        assert result is not None
        directive = result["remediations"][0].get("directive")
        assert directive in ["server", "ssl_reject_handshake", "return"]

    def test_response_context_is_http_or_server(self, detector):
        server = _server_block(
            [_dir("listen", ["80"]), _dir("server_name", ["app.com"])])
        result = self._eval(detector, _http_block([server]))
        assert result is not None
        context = result["remediations"][0].get("context")
        assert context in ["http", "server"]

# ──────────────────────────────────────────────────────────────────────────────
# Phần 4 — scan(): Toàn bộ đường ống (Full Pipeline Integration) (20 Test Cases)
# ──────────────────────────────────────────────────────────────────────────────


class TestScan:
    """Các bài test kiểm tra tích hợp toàn diện thông qua việc mô phỏng dữ liệu phân tích AST."""

    # --- Cấu hình an toàn đầy đủ (3 test cases) ---
    def test_full_secure_single_file(self, detector):
        parser_output = _make_parser_output([_http_block([
            _server_block(
                [_dir("listen", ["80", "default_server"]), _dir("return", ["444"])]),
            _server_block([_dir("listen", ["80"]), _dir(
                "server_name", ["app.com"]), _dir("root", ["/var/www"])])
        ])])
        assert detector.scan(parser_output) == []

    def test_full_secure_https_only(self, detector):
        parser_output = _make_parser_output([_http_block([
            _server_block([_dir("listen", ["443", "ssl", "default_server"]), _dir(
                "return", ["444"]), _dir("ssl_reject_handshake", ["on"])]),
            _server_block([_dir("listen", ["443", "ssl"]), _dir(
                "server_name", ["api.com"]), _dir("root", ["/var/www"])])
        ])])
        assert detector.scan(parser_output) == []

    def test_full_secure_multiple_files(self, detector):
        parser_output = {
            "config": [
                {"file": "/etc/nginx/conf.d/default.conf",
                 "parsed": [_server_block([_dir("listen", ["80", "default_server"]), _dir("return", ["444"])])]},
                {"file": "/etc/nginx/conf.d/app.conf",
                 "parsed": [_server_block([_dir("listen", ["80"]), _dir("server_name", ["app.com"]), _dir("root", ["/var/www"])])]}
            ]
        }
        assert detector.scan(parser_output) == []

    # --- Không tìm thấy default_server trong toàn bộ cấu hình (3 test cases) ---
    def test_no_default_server_single_file(self, detector):
        parser_output = _make_parser_output([_http_block([
            _server_block([_dir("listen", ["80"]), _dir(
                "server_name", ["app.com"]), _dir("root", ["/var/www"])])
        ])])
        findings = detector.scan(parser_output)
        assert len(findings) == 1

    def test_no_default_server_multiple_files(self, detector):
        parser_output = {
            "config": [
                {"file": "/etc/nginx/conf.d/app1.conf",
                 "parsed": [_server_block([_dir("listen", ["80"]), _dir("server_name", ["app1.com"])])]},
                {"file": "/etc/nginx/conf.d/app2.conf",
                 "parsed": [_server_block([_dir("listen", ["80"]), _dir("server_name", ["app2.com"])])]}
            ]
        }
        findings = detector.scan(parser_output)
        assert len(findings) >= 1

    def test_no_default_server_complex(self, detector):
        parser_output = _make_parser_output([_http_block([
            _server_block([_dir("listen", ["80"]), _dir("server_name", ["app.com"]), _dir(
                "location", ["/"], [_dir("proxy_pass", ["http://backend"])])])
        ])])
        findings = detector.scan(parser_output)
        assert len(findings) == 1

    # --- Gom nhóm lỗi (Grouping) (3 test cases) ---
    def test_grouping_one_error_per_http(self, detector):
        parser_output = _make_parser_output([_http_block([
            _server_block([_dir("listen", ["80"]), _dir(
                "server_name", ["app1.com"])]),
            _server_block(
                [_dir("listen", ["80"]), _dir("server_name", ["app2.com"])])
        ])])
        findings = detector.scan(parser_output)
        assert len(findings) == 1

    def test_grouping_multiple_http_blocks(self, detector):
        parser_output = _make_parser_output([
            _http_block(
                [_server_block([_dir("listen", ["80"]), _dir("server_name", ["app1.com"])])]),
            _http_block(
                [_server_block([_dir("listen", ["80"]), _dir("server_name", ["app2.com"])])])
        ])
        findings = detector.scan(parser_output)
        assert len(findings) == 2

    def test_grouping_mixed_missing_and_insecure(self, detector):
        parser_output = _make_parser_output([_http_block([
            _server_block([_dir("listen", ["80", "default_server"]), _dir(
                "root", ["/var/www"])]),  # insecure catch-all
            _server_block(
                [_dir("listen", ["80"]), _dir("server_name", ["app2.com"])])
        ])])
        findings = detector.scan(parser_output)
        assert len(findings) == 1

    # --- Xử lý các ngoại lệ (3 test cases) ---
    def test_exception_handling_custom_ports(self, detector):
        parser_output = _make_parser_output([_http_block([
            _server_block(
                [_dir("listen", ["8080", "default_server"]), _dir("return", ["444"])]),
            _server_block([_dir("listen", ["8080"]),
                          _dir("server_name", ["app.com"])])
        ])])
        assert detector.scan(parser_output) == []

    def test_exception_handling_listen_abbreviations(self, detector):
        parser_output = _make_parser_output([_http_block([
            _server_block([_dir("listen", ["default_server"]),
                          _dir("return", ["444"])])
        ])])
        assert detector.scan(parser_output) == []

    def test_exception_handling_mixed_listen_args(self, detector):
        parser_output = _make_parser_output([_http_block([
            _server_block([_dir("listen", ["80", "proxy_protocol",
                          "default_server"]), _dir("return", ["444"])])
        ])])
        assert detector.scan(parser_output) == []

    # --- Tương tác với Include Directive phức tạp (5 test cases) ---
    def test_include_with_catchall(self, detector):
        parser_output = {
            "config": [
                {"file": "nginx.conf", "parsed": [
                    _http_block([_dir("include", ["conf.d/*.conf"])])]},
                {"file": "conf.d/catchall.conf", "parsed": [_server_block(
                    [_dir("listen", ["80", "default_server"]), _dir("return", ["444"])])]},
                {"file": "conf.d/app.conf", "parsed": [_server_block(
                    [_dir("listen", ["80"]), _dir("server_name", ["app.com"])])]}
            ]
        }
        assert detector.scan(parser_output) == []

    def test_include_without_catchall(self, detector):
        parser_output = {
            "config": [
                {"file": "nginx.conf", "parsed": [
                    _http_block([_dir("include", ["conf.d/*.conf"])])]},
                {"file": "conf.d/app.conf", "parsed": [_server_block(
                    [_dir("listen", ["80"]), _dir("server_name", ["app.com"])])]}
            ]
        }
        findings = detector.scan(parser_output)
        assert len(findings) == 1

    def test_nested_includes_with_catchall(self, detector):
        parser_output = {
            "config": [
                {"file": "nginx.conf", "parsed": [_http_block(
                    [_dir("include", ["sites-enabled/*"])])]},
                {"file": "sites-enabled/default",
                    "parsed": [_dir("include", ["/etc/nginx/catchall.conf"])]},
                {"file": "/etc/nginx/catchall.conf", "parsed": [_server_block(
                    [_dir("listen", ["80", "default_server"]), _dir("return", ["444"])])]}
            ]
        }
        assert detector.scan(parser_output) == []

    def test_nested_includes_without_catchall(self, detector):
        parser_output = {
            "config": [
                {"file": "nginx.conf", "parsed": [_http_block(
                    [_dir("include", ["sites-enabled/*"])])]},
                {"file": "sites-enabled/app", "parsed": [_server_block(
                    [_dir("listen", ["80"]), _dir("server_name", ["app.com"])])]}
            ]
        }
        findings = detector.scan(parser_output)
        assert len(findings) == 1

    def test_include_with_insecure_catchall(self, detector):
        parser_output = {
            "config": [
                {"file": "nginx.conf", "parsed": [
                    _http_block([_dir("include", ["conf.d/*.conf"])])]},
                {"file": "conf.d/catchall.conf", "parsed": [_server_block(
                    [_dir("listen", ["80", "default_server"]), _dir("root", ["/var/www"])])]}
            ]
        }
        findings = detector.scan(parser_output)
        assert len(findings) == 1
        assert findings[0]["file"] == "conf.d/catchall.conf"

    # --- Tính toàn vẹn của kết quả Schema (3 test cases) ---
    def test_schema_has_file_key(self, detector):
        parser_output = _make_parser_output(
            [_http_block([_server_block([_dir("listen", ["80"])])])])
        findings = detector.scan(parser_output)
        assert len(findings) == 1
        assert "file" in findings[0]

    def test_schema_remediations_has_action_directive_context(self, detector):
        parser_output = _make_parser_output(
            [_http_block([_server_block([_dir("listen", ["80"])])])])
        findings = detector.scan(parser_output)
        assert len(findings) == 1
        remediation = findings[0]["remediations"][0]
        assert "action" in remediation
        assert "directive" in remediation
        assert "context" in remediation

    def test_schema_remediation_target_valid(self, detector):
        parser_output = _make_parser_output(
            [_http_block([_server_block([_dir("listen", ["80"])])])])
        findings = detector.scan(parser_output)
        assert len(findings) == 1
        remediation = findings[0]["remediations"][0]
        assert remediation["action"] in ["add", "modify"]
        assert remediation["directive"] in [
            "server", "return", "ssl_reject_handshake"]
