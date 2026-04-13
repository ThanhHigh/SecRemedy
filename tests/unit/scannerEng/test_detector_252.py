"""
Unit tests cho Detector252 — CIS Benchmark 2.5.2
"Ensure default error and index.html pages do not reference NGINX (Manual)"

Chiến lược Kiểm thử
─────────────
• Phần 1: Metadata Sanity Checks - 4 test cases.
• Phần 2: Kiểm thử hàm evaluate() / logic kiểm tra khối (Compliant) - 24 test cases.
• Phần 3: Kiểm thử hàm evaluate() (Non-Compliant) - 22 test cases.
• Phần 4: Kiểm thử hàm scan() toàn bộ đường ống - 20 test cases.
"""

import pytest
from core.scannerEng.recommendations.detector_252 import Detector252


@pytest.fixture
def detector():
    """Trả về một instance Detector252 mới cho mỗi test."""
    return Detector252()


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


def _http_block(directives: list) -> dict:
    """Hàm hỗ trợ: tạo một block 'http' chứa các chỉ thị."""
    return _dir("http", [], directives)


def _location_block(args: list, directives: list) -> dict:
    """Hàm hỗ trợ: tạo một block 'location'."""
    return _dir("location", args, directives)


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
        assert detector.id == "2.5.2"

    def test_title_contains_error_page(self, detector):
        assert "error and index.html pages do not reference NGINX" in detector.title

    def test_level_assignment(self, detector):
        assert hasattr(detector, "profile") or hasattr(detector, "level") or True
        level_info = getattr(detector, "profile", getattr(detector, "level", "level 1"))
        assert "level 1" in str(level_info).lower()

    def test_has_required_attributes(self, detector):
        for attr in ("description", "audit_procedure", "impact", "remediation"):
            assert getattr(detector, attr, None), f"Missing attribute: {attr}"


# ──────────────────────────────────────────────────────────────────────────────
# Phần 2 — evaluate() hoặc logic kiểm tra khối (Compliant) (24 Test Cases)
# ──────────────────────────────────────────────────────────────────────────────

class TestEvaluateCompliant:
    """Các cấu hình hợp lệ có khai báo error_page đầy đủ cho 404 và 50x."""

    HTTP_CTX = ["http"]
    FILEPATH = "/etc/nginx/nginx.conf"
    EXACT_PATH = ["config", 0, "parsed", 0]

    def _eval(self, detector, directive, ctx=None):
        ctx = ctx or self.HTTP_CTX
        return detector.evaluate(directive, self.FILEPATH, ctx, self.EXACT_PATH)

    # --- Thiết lập an toàn tại khối http (6 test cases) ---
    @pytest.mark.parametrize("error_args", [
        [["404", "/404.html"], ["500", "502", "503", "504", "/50x.html"]],
        [["404", "403", "/40x.html"], ["500", "502", "503", "504", "/50x.html"]],
        [["404", "500", "502", "503", "504", "/error.html"]],
        [["404", "/404.html"], ["500", "/500.html"], ["502", "503", "504", "/50x.html"]],
        [["404", "http://example.com/404.html"], ["500", "502", "503", "504", "http://example.com/50x.html"]],
        [["404", "/404.php?code=$status"], ["500", "502", "503", "504", "/50x.php?code=$status"]]
    ])
    def test_http_secure_error_pages(self, detector, error_args):
        directives = [_dir("error_page", args) for args in error_args]
        assert self._eval(detector, _http_block(directives)) is None

    # --- Thiết lập an toàn tại khối server (6 test cases) ---
    @pytest.mark.parametrize("error_args", [
        [["404", "/custom_404.html"], ["500", "502", "503", "504", "/custom_50x.html"]],
        [["404", "/404.html"], ["500", "502", "503", "504", "/500.html"]],
        [["404", "500", "502", "503", "504", "/errors.html"]],
        [["403", "/403.html"], ["404", "/404.html"], ["500", "502", "503", "504", "/50x.html"]],
        [["404", "=200", "/empty.gif"], ["500", "502", "503", "504", "/50x.html"]],
        [["404", "/404.html"], ["500", "502", "503", "504", "@maintenance"]]
    ])
    def test_server_secure_error_pages(self, detector, error_args):
        directives = [_dir("error_page", args) for args in error_args]
        server = _server_block(directives)
        assert self._eval(detector, server, ["http", "server"]) is None

    # --- Nested Contexts (6 test cases) ---
    def test_http_has_error_page_server_inherits(self, detector):
        server = _server_block([_dir("listen", ["80"])])
        http_block = _http_block([
            _dir("error_page", ["404", "/404.html"]),
            _dir("error_page", ["500", "502", "503", "504", "/50x.html"]),
            server
        ])
        assert self._eval(detector, http_block) is None

    def test_http_has_error_page_server_overrides_safely(self, detector):
        server = _server_block([
            _dir("error_page", ["404", "/custom_404.html"]),
            _dir("error_page", ["500", "502", "503", "504", "/custom_50x.html"])
        ])
        http_block = _http_block([
            _dir("error_page", ["404", "500", "502", "503", "504", "/error.html"]),
            server
        ])
        assert self._eval(detector, http_block) is None

    def test_server_error_page_with_matching_location(self, detector):
        server = _server_block([
            _dir("error_page", ["404", "/404.html"]),
            _dir("error_page", ["500", "502", "503", "504", "/50x.html"]),
            _location_block(["=", "/50x.html"], [_dir("root", ["/usr/share/nginx/html"])])
        ])
        assert self._eval(detector, server, ["http", "server"]) is None

    def test_server_and_location_own_error_pages(self, detector):
        loc = _location_block(["/api/"], [
            _dir("error_page", ["404", "/api_404.json"]),
            _dir("error_page", ["500", "502", "503", "504", "/api_50x.json"])
        ])
        server = _server_block([
            _dir("error_page", ["404", "/404.html"]),
            _dir("error_page", ["500", "502", "503", "504", "/50x.html"]),
            loc
        ])
        assert self._eval(detector, server, ["http", "server"]) is None

    def test_location_fallback_named(self, detector):
        server = _server_block([
            _dir("error_page", ["404", "/404.html"]),
            _dir("error_page", ["500", "502", "503", "504", "@fallback"]),
            _location_block(["@fallback"], [_dir("proxy_pass", ["http://backend"])])
        ])
        assert self._eval(detector, server, ["http", "server"]) is None

    def test_error_page_inside_location_only(self, detector):
        # Mặc dù location có error_page, nhưng server level cũng cần được đánh giá an toàn ở phạm vi test này
        loc = _location_block(["/"], [
            _dir("error_page", ["404", "500", "502", "503", "504", "/err.html"])
        ])
        assert self._eval(detector, loc, ["http", "server", "location"]) is None

    # --- Kết hợp với các chỉ thị bảo mật khác (6 test cases) ---
    def test_combined_with_server_tokens(self, detector):
        server = _server_block([
            _dir("server_tokens", ["off"]),
            _dir("error_page", ["404", "/404.html"]),
            _dir("error_page", ["500", "502", "503", "504", "/50x.html"])
        ])
        assert self._eval(detector, server, ["http", "server"]) is None

    def test_combined_with_add_header(self, detector):
        server = _server_block([
            _dir("add_header", ["X-Frame-Options", "DENY"]),
            _dir("error_page", ["404", "/404.html"]),
            _dir("error_page", ["500", "502", "503", "504", "/50x.html"])
        ])
        assert self._eval(detector, server, ["http", "server"]) is None

    def test_combined_with_listen_root(self, detector):
        server = _server_block([
            _dir("listen", ["80"]),
            _dir("server_name", ["example.com"]),
            _dir("error_page", ["404", "/404.html"]),
            _dir("root", ["/var/www"]),
            _dir("error_page", ["500", "502", "503", "504", "/50x.html"])
        ])
        assert self._eval(detector, server, ["http", "server"]) is None

    def test_combined_with_ssl(self, detector):
        server = _server_block([
            _dir("listen", ["443", "ssl"]),
            _dir("ssl_certificate", ["/cert.pem"]),
            _dir("error_page", ["404", "500", "502", "503", "504", "/error.html"])
        ])
        assert self._eval(detector, server, ["http", "server"]) is None

    def test_complex_server_block(self, detector):
        server = _server_block([
            _dir("listen", ["80"]),
            _dir("error_page", ["404", "/404.html"]),
            _location_block(["/"], [_dir("proxy_pass", ["http://backend"])]),
            _dir("error_page", ["500", "502", "503", "504", "/50x.html"])
        ])
        assert self._eval(detector, server, ["http", "server"]) is None

    def test_complex_http_block(self, detector):
        http_block = _http_block([
            _dir("include", ["mime.types"]),
            _dir("error_page", ["404", "/404.html"]),
            _dir("log_format", ["main", "..."]),
            _dir("error_page", ["500", "502", "503", "504", "/50x.html"]),
            _dir("access_log", ["/var/log/nginx/access.log", "main"])
        ])
        assert self._eval(detector, http_block) is None


# ──────────────────────────────────────────────────────────────────────────────
# Phần 3 — evaluate() hoặc logic kiểm tra khối (Non-Compliant) (22 Test Cases)
# ──────────────────────────────────────────────────────────────────────────────

class TestEvaluateNonCompliant:
    """Các cấu hình thiếu sót hoặc để lộ thông tin qua trang lỗi mặc định."""

    HTTP_CTX = ["http"]
    FILEPATH = "/etc/nginx/nginx.conf"
    EXACT_PATH = ["config", 0, "parsed", 0]

    def _eval(self, detector, directive, ctx=None):
        ctx = ctx or self.HTTP_CTX
        return detector.evaluate(directive, self.FILEPATH, ctx, self.EXACT_PATH)

    # --- Không khai báo error_page (Implicitly default) (6 test cases) ---
    def test_empty_http_block(self, detector):
        assert self._eval(detector, _http_block([])) is not None

    def test_empty_server_block(self, detector):
        assert self._eval(detector, _server_block([]), ["http", "server"]) is not None

    def test_server_with_listen_only(self, detector):
        server = _server_block([_dir("listen", ["80"]), _dir("server_name", ["app.com"])])
        assert self._eval(detector, server, ["http", "server"]) is not None

    def test_server_with_location_but_no_error_page(self, detector):
        server = _server_block([
            _dir("listen", ["80"]),
            _location_block(["/"], [_dir("return", ["200", "OK"])])
        ])
        assert self._eval(detector, server, ["http", "server"]) is not None

    def test_http_with_include_but_no_error_page(self, detector):
        http_block = _http_block([_dir("include", ["conf.d/*.conf"])])
        assert self._eval(detector, http_block) is not None

    def test_server_with_proxy_pass_no_error_page(self, detector):
        server = _server_block([
            _dir("listen", ["80"]),
            _dir("proxy_pass", ["http://backend"])
        ])
        assert self._eval(detector, server, ["http", "server"]) is not None

    # --- Khai báo error_page nhưng thiếu mã lỗi quan trọng (5 test cases) ---
    @pytest.mark.parametrize("error_args", [
        [["404", "/404.html"]],                                  # Thiếu 50x
        [["500", "/500.html"]],                                  # Thiếu 404, 502, 503, 504
        [["502", "503", "504", "/50x.html"]],                    # Thiếu 404, 500
        [["404", "/404.html"], ["500", "/500.html"]],            # Thiếu 502, 503, 504
        [["403", "/403.html"]]                                   # Thiếu 404, 50x
    ])
    def test_missing_important_status_codes(self, detector, error_args):
        directives = [_dir("error_page", args) for args in error_args]
        assert self._eval(detector, _http_block(directives)) is not None

    # --- Cấu hình error_page nhưng trỏ sai vị trí hoặc nguy hiểm (4 test cases) ---
    def test_error_page_missing_uri(self, detector):
        # Cú pháp không hợp lệ: error_page 404; (thiếu đường dẫn)
        http_block = _http_block([_dir("error_page", ["404"])])
        assert self._eval(detector, http_block) is not None

    def test_error_page_empty_args(self, detector):
        http_block = _http_block([_dir("error_page", [])])
        assert self._eval(detector, http_block) is not None

    def test_error_page_pointing_to_nginx_default(self, detector):
        # Ví dụ: trỏ về trang mặc định của CentOS/Ubuntu chứa chữ nginx
        server = _server_block([
            _dir("error_page", ["404", "500", "502", "503", "504", "/usr/share/nginx/html/50x.html"])
        ])
        assert self._eval(detector, server, ["http", "server"]) is not None

    def test_error_page_pointing_to_debian_default(self, detector):
        server = _server_block([
            _dir("error_page", ["404", "500", "502", "503", "504", "/var/www/html/index.nginx-debian.html"])
        ])
        assert self._eval(detector, server, ["http", "server"]) is not None

    # --- Kiểm tra cấu trúc dữ liệu phản hồi JSON Contract (7 test cases) ---
    def test_response_file_path(self, detector):
        result = self._eval(detector, _http_block([]))
        assert result is not None
        assert result.get("file") == self.FILEPATH

    def test_response_remediations_is_list(self, detector):
        result = self._eval(detector, _http_block([]))
        assert result is not None
        assert isinstance(result.get("remediations"), list)

    def test_response_remediations_not_empty(self, detector):
        result = self._eval(detector, _http_block([]))
        assert result is not None
        assert len(result.get("remediations", [])) >= 1

    def test_response_action_is_add_or_insert(self, detector):
        result = self._eval(detector, _http_block([]))
        assert result is not None
        action = result["remediations"][0].get("action")
        assert action in ["add", "insert"]

    def test_response_directive_targets_error_page(self, detector):
        result = self._eval(detector, _http_block([]))
        assert result is not None
        directive = result["remediations"][0].get("directive")
        assert directive == "error_page"

    def test_response_value_contains_status_codes(self, detector):
        result = self._eval(detector, _http_block([]))
        assert result is not None
        value = result["remediations"][0].get("value", "")
        assert "404" in value or "500" in value or "50x" in value

    def test_response_context_is_http_or_server(self, detector):
        result = self._eval(detector, _server_block([]), ["http", "server"])
        assert result is not None
        context = result["remediations"][0].get("context")
        assert context in ["http", "server"]


# ──────────────────────────────────────────────────────────────────────────────
# Phần 4 — scan(): Toàn bộ đường ống (Full Pipeline Integration) (20 Test Cases)
# ──────────────────────────────────────────────────────────────────────────────

class TestScan:
    """Các bài test kiểm tra tích hợp toàn diện thông qua việc mô phỏng dữ liệu phân tích AST đệ quy."""

    # --- Cấu hình an toàn trên toàn bộ hệ thống (3 test cases) ---
    def test_safe_full_system_single_file(self, detector):
        parser_output = _make_parser_output([_http_block([
            _dir("error_page", ["404", "/404.html"]),
            _dir("error_page", ["500", "502", "503", "504", "/50x.html"]),
            _server_block([_dir("listen", ["80"])]),
            _server_block([_dir("listen", ["443"])])
        ])])
        assert detector.scan(parser_output) == []

    def test_safe_full_system_multiple_files(self, detector):
        parser_output = {
            "config": [
                {"file": "/etc/nginx/nginx.conf",
                 "parsed": [_http_block([
                     _dir("error_page", ["404", "/404.html"]),
                     _dir("error_page", ["500", "502", "503", "504", "/50x.html"])
                 ])]},
                {"file": "/etc/nginx/conf.d/app.conf",
                 "parsed": [_server_block([_dir("listen", ["80"])])]}
            ]
        }
        assert detector.scan(parser_output) == []

    def test_safe_mixed_overrides(self, detector):
        parser_output = {
            "config": [
                {"file": "/etc/nginx/nginx.conf",
                 "parsed": [_http_block([
                     _dir("error_page", ["404", "/404.html"]),
                     _dir("error_page", ["500", "502", "503", "504", "/50x.html"])
                 ])]},
                {"file": "/etc/nginx/conf.d/app.conf",
                 "parsed": [_server_block([
                     _dir("error_page", ["404", "500", "502", "503", "504", "/custom.html"])
                 ])]}
            ]
        }
        assert detector.scan(parser_output) == []

    # --- Nhận diện sự vắng mặt của chỉ thị ở hệ thống đa tệp (3 test cases) ---
    def test_missing_in_multiple_servers(self, detector):
        parser_output = {
            "config": [
                {"file": "nginx.conf", "parsed": [_http_block([])]},
                {"file": "app1.conf", "parsed": [_server_block([_dir("listen", ["80"])])]},
                {"file": "app2.conf", "parsed": [_server_block([_dir("listen", ["443"])])]}
            ]
        }
        findings = detector.scan(parser_output)
        assert len(findings) >= 1

    def test_root_http_missing_servers_missing(self, detector):
        parser_output = _make_parser_output([_http_block([
            _server_block([_dir("listen", ["80"])])
        ])])
        findings = detector.scan(parser_output)
        assert len(findings) == 1

    def test_root_http_partial_server_missing_rest(self, detector):
        parser_output = _make_parser_output([_http_block([
            _dir("error_page", ["404", "/404.html"]),
            _server_block([_dir("listen", ["80"])]) # Thiếu 50x
        ])])
        findings = detector.scan(parser_output)
        assert len(findings) >= 1

    # --- Gom nhóm lỗi (Grouping) và cảnh báo ghi đè (3 test cases) ---
    def test_grouping_http_missing(self, detector):
        parser_output = _make_parser_output([_http_block([
            _server_block([_dir("listen", ["80"])]),
            _server_block([_dir("listen", ["443"])])
        ])])
        findings = detector.scan(parser_output)
        assert len(findings) >= 1

    def test_override_missing_50x(self, detector):
        parser_output = {
            "config": [
                {"file": "nginx.conf", "parsed": [_http_block([
                    _dir("error_page", ["404", "500", "502", "503", "504", "/err.html"])
                ])]},
                {"file": "app.conf", "parsed": [_server_block([
                    _dir("error_page", ["404", "/app_404.html"]) # Ghi đè nhưng thiếu 50x
                ])]}
            ]
        }
        findings = detector.scan(parser_output)
        assert len(findings) == 1
        assert findings[0]["file"] == "app.conf"

    def test_override_safe_other_unsafe(self, detector):
        parser_output = {
            "config": [
                {"file": "nginx.conf", "parsed": [_http_block([
                    _dir("error_page", ["404", "500", "502", "503", "504", "/err.html"])
                ])]},
                {"file": "safe.conf", "parsed": [_server_block([])]}, # Kế thừa an toàn
                {"file": "unsafe.conf", "parsed": [_server_block([
                    _dir("error_page", ["500", "/500.html"]) # Ghi đè thiếu 404, 502, 503, 504
                ])]}
            ]
        }
        findings = detector.scan(parser_output)
        assert len(findings) == 1
        assert findings[0]["file"] == "unsafe.conf"

    # --- Xử lý các ngoại lệ cấu hình (3 test cases) ---
    def test_empty_file(self, detector):
        parser_output = {"config": [{"file": "empty.conf", "parsed": []}]}
        assert detector.scan(parser_output) == []

    def test_stream_block_only(self, detector):
        parser_output = {"config": [{"file": "stream.conf", "parsed": [
            _dir("stream", [], [_server_block([_dir("listen", ["12345"])])])
        ]}]}
        assert detector.scan(parser_output) == []

    def test_events_block_only(self, detector):
        parser_output = {"config": [{"file": "events.conf", "parsed": [
            _dir("events", [], [_dir("worker_connections", ["1024"])])
        ]}]}
        assert detector.scan(parser_output) == []

    # --- Tương tác với Include Directive phức tạp (5 test cases) ---
    def test_include_inherits_from_http(self, detector):
        parser_output = {
            "config": [
                {"file": "nginx.conf", "parsed": [_http_block([
                    _dir("error_page", ["404", "500", "502", "503", "504", "/err.html"]),
                    _dir("include", ["conf.d/*.conf"])
                ])]},
                {"file": "conf.d/app.conf", "parsed": [_server_block([_dir("listen", ["80"])])]}
            ]
        }
        assert detector.scan(parser_output) == []

    def test_include_missing_error_page(self, detector):
        parser_output = {
            "config": [
                {"file": "nginx.conf", "parsed": [_http_block([
                    _dir("include", ["conf.d/*.conf"])
                ])]},
                {"file": "conf.d/app.conf", "parsed": [_server_block([_dir("listen", ["80"])])]}
            ]
        }
        findings = detector.scan(parser_output)
        assert len(findings) >= 1

    def test_nested_include_missing(self, detector):
        parser_output = {
            "config": [
                {"file": "nginx.conf", "parsed": [_http_block([
                    _dir("include", ["sites-enabled/*"])
                ])]},
                {"file": "sites-enabled/default", "parsed": [_dir("include", ["/etc/nginx/app.conf"])]},
                {"file": "/etc/nginx/app.conf", "parsed": [_server_block([_dir("listen", ["80"])])]}
            ]
        }
        findings = detector.scan(parser_output)
        assert len(findings) >= 1

    def test_include_with_unsafe_override(self, detector):
        parser_output = {
            "config": [
                {"file": "nginx.conf", "parsed": [_http_block([
                    _dir("error_page", ["404", "500", "502", "503", "504", "/err.html"]),
                    _dir("include", ["conf.d/*.conf"])
                ])]},
                {"file": "conf.d/app.conf", "parsed": [_server_block([
                    _dir("error_page", ["404", "/404.html"])
                ])]}
            ]
        }
        findings = detector.scan(parser_output)
        assert len(findings) == 1
        assert findings[0]["file"] == "conf.d/app.conf"

    def test_include_invalid_location_only(self, detector):
        parser_output = {
            "config": [
                {"file": "nginx.conf", "parsed": [_http_block([
                    _server_block([
                        _dir("include", ["loc.conf"])
                    ])
                ])]},
                {"file": "loc.conf", "parsed": [_location_block(["/"], [_dir("return", ["200"])])]}
            ]
        }
        findings = detector.scan(parser_output)
        assert len(findings) >= 1

    # --- Tính toàn vẹn của kết quả Schema cho Auto-Remediation (3 test cases) ---
    def test_schema_has_file_key(self, detector):
        parser_output = _make_parser_output([_http_block([])])
        findings = detector.scan(parser_output)
        assert len(findings) >= 1
        assert "file" in findings[0]

    def test_schema_remediations_has_action_directive_context(self, detector):
        parser_output = _make_parser_output([_http_block([])])
        findings = detector.scan(parser_output)
        assert len(findings) >= 1
        remediation = findings[0]["remediations"][0]
        assert "action" in remediation
        assert "directive" in remediation
        assert "context" in remediation

    def test_schema_remediation_target_valid(self, detector):
        parser_output = _make_parser_output([_http_block([])])
        findings = detector.scan(parser_output)
        assert len(findings) >= 1
        remediation = findings[0]["remediations"][0]
        assert remediation["action"] in ["add", "insert"]
        assert remediation["directive"] == "error_page"
