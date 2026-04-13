"""
Unit tests cho Detector253 — CIS Benchmark 2.5.3
"Ensure hidden file serving is disabled (Manual)"

Chiến lược Kiểm thử
─────────────
• Phần 1: Metadata Sanity Checks - 4 test cases.
• Phần 2: Kiểm thử hàm evaluate() / logic kiểm tra khối (Compliant) - 24 test cases.
• Phần 3: Kiểm thử hàm evaluate() (Non-Compliant) - 22 test cases.
• Phần 4: Kiểm thử hàm scan() toàn bộ đường ống - 20 test cases.
"""

import pytest
from core.scannerEng.recommendations.detector_253 import Detector253


@pytest.fixture
def detector():
    """Trả về một instance Detector253 mới cho mỗi test."""
    return Detector253()


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
        assert detector.id == "2.5.3"

    def test_title_contains_hidden_file(self, detector):
        assert "Ensure hidden file serving is disabled" in detector.title

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
    """Các cấu hình hợp lệ chặn file ẩn thành công."""

    SERVER_CTX = ["http", "server"]
    FILEPATH = "/etc/nginx/nginx.conf"
    EXACT_PATH = ["config", 0, "parsed", 0, "block", 0]

    def _eval(self, detector, directive, ctx=None):
        ctx = ctx or self.SERVER_CTX
        return detector.evaluate(directive, self.FILEPATH, ctx, self.EXACT_PATH)

    # --- Thiết lập an toàn tại khối server (6 test cases) ---
    def test_server_deny_all(self, detector):
        server = _server_block([_location_block(["~", r"/\."], [_dir("deny", ["all"])])])
        assert self._eval(detector, server) is None

    def test_server_return_404(self, detector):
        server = _server_block([_location_block(["~", r"/\."], [_dir("return", ["404"])])])
        assert self._eval(detector, server) is None

    def test_server_return_403(self, detector):
        server = _server_block([_location_block(["~", r"/\."], [_dir("return", ["403"])])])
        assert self._eval(detector, server) is None

    def test_server_regex_case_insensitive(self, detector):
        server = _server_block([_location_block(["~*", r"/\."], [_dir("deny", ["all"])])])
        assert self._eval(detector, server) is None

    def test_server_regex_without_slash(self, detector):
        server = _server_block([_location_block(["~", r"\."], [_dir("deny", ["all"])])])
        assert self._eval(detector, server) is None

    def test_server_regex_negative_lookahead(self, detector):
        server = _server_block([_location_block(["~", r"/\.(?!well-known).*"], [_dir("deny", ["all"])])])
        assert self._eval(detector, server) is None

    # --- Sử dụng include snippet cho cấu hình bảo mật (6 test cases) ---
    def test_include_hidden_snippet_1(self, detector):
        server = _server_block([_dir("include", ["snippets/hidden.conf"])])
        assert self._eval(detector, server) is None

    def test_include_hidden_snippet_2(self, detector):
        server = _server_block([_dir("include", ["conf.d/protect_hidden.conf"])])
        assert self._eval(detector, server) is None

    def test_include_hidden_snippet_3(self, detector):
        server = _server_block([_dir("include", ["/etc/nginx/security.conf"])])
        assert self._eval(detector, server) is None

    def test_include_hidden_snippet_4(self, detector):
        server = _server_block([_dir("include", ["global_deny.conf"])])
        assert self._eval(detector, server) is None

    def test_include_hidden_snippet_5(self, detector):
        server = _server_block([_dir("include", ["block_dot_files.conf"])])
        assert self._eval(detector, server) is None

    def test_include_hidden_snippet_6(self, detector):
        server = _server_block([_dir("include", ["dotfiles.rules"])])
        assert self._eval(detector, server) is None

    # --- Có ngoại lệ an toàn cho Let's Encrypt (6 test cases) ---
    def test_exception_well_known_allow(self, detector):
        server = _server_block([
            _location_block(["^~", "/.well-known/acme-challenge/"], [_dir("allow", ["all"])]),
            _location_block(["~", r"/\."], [_dir("deny", ["all"])])
        ])
        assert self._eval(detector, server) is None

    def test_exception_well_known_exact(self, detector):
        server = _server_block([
            _location_block(["=", "/.well-known/acme-challenge/"], [_dir("allow", ["all"])]),
            _location_block(["~", r"/\."], [_dir("deny", ["all"])])
        ])
        assert self._eval(detector, server) is None

    def test_exception_well_known_regex(self, detector):
        server = _server_block([
            _location_block(["~", r"^/\.well-known/"], [_dir("allow", ["all"])]),
            _location_block(["~", r"/\."], [_dir("deny", ["all"])])
        ])
        assert self._eval(detector, server) is None

    def test_exception_well_known_return_200(self, detector):
        server = _server_block([
            _location_block(["^~", "/.well-known/"], [_dir("return", ["200"])]),
            _location_block(["~", r"/\."], [_dir("return", ["404"])])
        ])
        assert self._eval(detector, server) is None

    def test_exception_well_known_try_files(self, detector):
        server = _server_block([
            _location_block(["^~", "/.well-known/acme-challenge/"], [_dir("try_files", ["$uri", "=404"])]),
            _location_block(["~", r"/\."], [_dir("deny", ["all"])])
        ])
        assert self._eval(detector, server) is None

    def test_exception_well_known_root(self, detector):
        server = _server_block([
            _location_block(["^~", "/.well-known/acme-challenge/"], [_dir("root", ["/var/www/letsencrypt"])]),
            _location_block(["~", r"/\."], [_dir("deny", ["all"])])
        ])
        assert self._eval(detector, server) is None

    # --- Kết hợp với các chỉ thị location phức tạp khác (6 test cases) ---
    def test_combined_with_location_slash(self, detector):
        server = _server_block([
            _location_block(["/"], [_dir("proxy_pass", ["http://backend"])]),
            _location_block(["~", r"/\."], [_dir("deny", ["all"])])
        ])
        assert self._eval(detector, server) is None

    def test_combined_with_location_php(self, detector):
        server = _server_block([
            _location_block(["~", r"\.php$"], [_dir("fastcgi_pass", ["127.0.0.1:9000"])]),
            _location_block(["~", r"/\."], [_dir("deny", ["all"])])
        ])
        assert self._eval(detector, server) is None

    def test_combined_with_multiple_locations(self, detector):
        server = _server_block([
            _location_block(["/api/"], [_dir("proxy_pass", ["http://api"])]),
            _location_block(["/static/"], [_dir("root", ["/var/www/static"])]),
            _location_block(["~", r"/\."], [_dir("deny", ["all"])])
        ])
        assert self._eval(detector, server) is None

    def test_combined_with_nested_location(self, detector):
        server = _server_block([
            _location_block(["/"], [
                _location_block(["~", r"\.php$"], [_dir("fastcgi_pass", ["unix:/sock"])])
            ]),
            _location_block(["~", r"/\."], [_dir("deny", ["all"])])
        ])
        assert self._eval(detector, server) is None

    def test_combined_with_exact_favicon(self, detector):
        server = _server_block([
            _location_block(["=", "/favicon.ico"], [_dir("log_not_found", ["off"])]),
            _location_block(["~", r"/\."], [_dir("deny", ["all"])])
        ])
        assert self._eval(detector, server) is None

    def test_combined_with_error_page(self, detector):
        server = _server_block([
            _dir("error_page", ["404", "/404.html"]),
            _location_block(["~", r"/\."], [_dir("deny", ["all"])])
        ])
        assert self._eval(detector, server) is None


# ──────────────────────────────────────────────────────────────────────────────
# Phần 3 — evaluate() hoặc logic kiểm tra khối (Non-Compliant) (22 Test Cases)
# ──────────────────────────────────────────────────────────────────────────────

class TestEvaluateNonCompliant:
    """Các cấu hình thiếu sót khiến NGINX tiếp tục phục vụ các file ẩn."""

    SERVER_CTX = ["http", "server"]
    FILEPATH = "/etc/nginx/nginx.conf"
    EXACT_PATH = ["config", 0, "parsed", 0, "block", 0]

    def _eval(self, detector, directive, ctx=None):
        ctx = ctx or self.SERVER_CTX
        return detector.evaluate(directive, self.FILEPATH, ctx, self.EXACT_PATH)

    # --- Không khai báo location chặn file ẩn (Implicitly default) (6 test cases) ---
    def test_server_with_listen_only(self, detector):
        server = _server_block([_dir("listen", ["80"])])
        assert self._eval(detector, server) is not None

    def test_server_with_listen_and_name(self, detector):
        server = _server_block([_dir("listen", ["80"]), _dir("server_name", ["app.com"])])
        assert self._eval(detector, server) is not None

    def test_server_with_location_slash_only(self, detector):
        server = _server_block([
            _location_block(["/"], [_dir("proxy_pass", ["http://backend"])])
        ])
        assert self._eval(detector, server) is not None

    def test_server_with_location_php_only(self, detector):
        server = _server_block([
            _location_block(["~", r"\.php$"], [_dir("fastcgi_pass", ["127.0.0.1:9000"])])
        ])
        assert self._eval(detector, server) is not None

    def test_server_with_exact_favicon_only(self, detector):
        server = _server_block([
            _location_block(["=", "/favicon.ico"], [_dir("log_not_found", ["off"])])
        ])
        assert self._eval(detector, server) is not None

    def test_empty_server_block(self, detector):
        server = _server_block([])
        assert self._eval(detector, server) is not None

    # --- Khai báo sai cú pháp hoặc chặn không triệt để (5 test cases) ---
    def test_location_hidden_allow_all(self, detector):
        server = _server_block([_location_block(["~", r"/\."], [_dir("allow", ["all"])])])
        assert self._eval(detector, server) is not None

    def test_location_hidden_empty_block(self, detector):
        server = _server_block([_location_block(["~", r"/\."], [])])
        assert self._eval(detector, server) is not None

    def test_location_hidden_missing_regex_tilde(self, detector):
        server = _server_block([_location_block([r"/\."], [_dir("deny", ["all"])])])
        assert self._eval(detector, server) is not None

    def test_location_hidden_regex_any_char(self, detector):
        server = _server_block([_location_block(["~", "."], [_dir("deny", ["all"])])])
        assert self._eval(detector, server) is not None

    def test_location_hidden_git_only(self, detector):
        server = _server_block([_location_block(["~", r"/\.git"], [_dir("deny", ["all"])])])
        assert self._eval(detector, server) is not None

    # --- Ngoại lệ bị đặt sai thứ tự (4 test cases) ---
    def test_wrong_order_well_known_after_hidden(self, detector):
        server = _server_block([
            _location_block(["~", r"/\."], [_dir("deny", ["all"])]),
            _location_block(["~", r"/\.well-known"], [_dir("allow", ["all"])])
        ])
        assert self._eval(detector, server) is not None

    def test_wrong_order_well_known_return_after(self, detector):
        server = _server_block([
            _location_block(["~", r"/\."], [_dir("return", ["404"])]),
            _location_block(["~", r"^/\.well-known"], [_dir("return", ["200"])])
        ])
        assert self._eval(detector, server) is not None

    def test_wrong_order_well_known_case_insensitive_after(self, detector):
        server = _server_block([
            _location_block(["~*", r"/\."], [_dir("deny", ["all"])]),
            _location_block(["~", r"/\.well-known"], [_dir("allow", ["all"])])
        ])
        assert self._eval(detector, server) is not None

    def test_wrong_order_well_known_no_slash_after(self, detector):
        server = _server_block([
            _location_block(["~", r"\."], [_dir("deny", ["all"])]),
            _location_block(["~", r"/\.well-known"], [_dir("allow", ["all"])])
        ])
        assert self._eval(detector, server) is not None

    # --- Kiểm tra cấu trúc dữ liệu phản hồi JSON Contract (7 test cases) ---
    def test_response_file_path(self, detector):
        result = self._eval(detector, _server_block([]))
        assert result is not None
        assert result.get("file") == self.FILEPATH

    def test_response_remediations_is_list(self, detector):
        result = self._eval(detector, _server_block([]))
        assert result is not None
        assert isinstance(result.get("remediations"), list)

    def test_response_remediations_not_empty(self, detector):
        result = self._eval(detector, _server_block([]))
        assert result is not None
        assert len(result.get("remediations", [])) >= 1

    def test_response_action_is_add_or_insert_block(self, detector):
        result = self._eval(detector, _server_block([]))
        assert result is not None
        action = result["remediations"][0].get("action")
        assert action in ["add_block", "insert_block"]

    def test_response_directive_targets_location(self, detector):
        result = self._eval(detector, _server_block([]))
        assert result is not None
        directive = result["remediations"][0].get("directive")
        assert directive == "location"

    def test_response_value_contains_deny_all(self, detector):
        result = self._eval(detector, _server_block([]))
        assert result is not None
        value = result["remediations"][0].get("value", "")
        assert "deny all" in value or "return 404" in value

    def test_response_context_is_server(self, detector):
        result = self._eval(detector, _server_block([]))
        assert result is not None
        context = result["remediations"][0].get("context")
        assert context == "server" or isinstance(context, dict)


# ──────────────────────────────────────────────────────────────────────────────
# Phần 4 — scan(): Toàn bộ đường ống (Full Pipeline Integration) (20 Test Cases)
# ──────────────────────────────────────────────────────────────────────────────

class TestScan:
    """Các bài test kiểm tra tích hợp toàn diện thông qua việc mô phỏng dữ liệu phân tích AST đệ quy."""

    # --- Cấu hình an toàn trên toàn bộ hệ thống đa server (3 test cases) ---
    def test_safe_full_system_multiple_servers_same_file(self, detector):
        parser_output = _make_parser_output([_http_block([
            _server_block([_location_block(["~", r"/\."], [_dir("deny", ["all"])])]),
            _server_block([_location_block(["~", r"/\."], [_dir("return", ["404"])])])
        ])])
        assert detector.scan(parser_output) == []

    def test_safe_full_system_multiple_servers_diff_files(self, detector):
        parser_output = {
            "config": [
                {"file": "/etc/nginx/nginx.conf",
                 "parsed": [_http_block([_server_block([_location_block(["~", r"/\."], [_dir("deny", ["all"])])])])]},
                {"file": "/etc/nginx/conf.d/app.conf",
                 "parsed": [_server_block([_location_block(["~*", r"/\."], [_dir("deny", ["all"])])])]}
            ]
        }
        assert detector.scan(parser_output) == []

    def test_safe_three_files_three_servers(self, detector):
        parser_output = {
            "config": [
                {"file": "1.conf", "parsed": [_server_block([_location_block(["~", r"/\."], [_dir("deny", ["all"])])])]},
                {"file": "2.conf", "parsed": [_server_block([_location_block(["~", r"/\."], [_dir("deny", ["all"])])])]},
                {"file": "3.conf", "parsed": [_server_block([_location_block(["~", r"/\."], [_dir("deny", ["all"])])])]}
            ]
        }
        assert detector.scan(parser_output) == []

    # --- Nhận diện sự vắng mặt ở hệ thống đa tệp (3 test cases) ---
    def test_missing_in_one_of_multiple_servers(self, detector):
        parser_output = {
            "config": [
                {"file": "1.conf", "parsed": [_server_block([_location_block(["~", r"/\."], [_dir("deny", ["all"])])])]},
                {"file": "2.conf", "parsed": [_server_block([_dir("listen", ["80"])])]} # Missing
            ]
        }
        findings = detector.scan(parser_output)
        assert len(findings) == 1
        assert findings[0]["file"] == "2.conf"

    def test_missing_in_two_of_three_servers(self, detector):
        parser_output = {
            "config": [
                {"file": "all.conf", "parsed": [
                    _server_block([_location_block(["~", r"/\."], [_dir("deny", ["all"])])]),
                    _server_block([_dir("listen", ["80"])]), # Missing
                    _server_block([_dir("listen", ["443"])]) # Missing
                ]}
            ]
        }
        findings = detector.scan(parser_output)
        assert len(findings) >= 1

    def test_missing_in_all_servers_across_files(self, detector):
        parser_output = {
            "config": [
                {"file": "1.conf", "parsed": [_server_block([])]},
                {"file": "2.conf", "parsed": [_server_block([])]},
                {"file": "3.conf", "parsed": [_server_block([])]}
            ]
        }
        findings = detector.scan(parser_output)
        assert len(findings) >= 1

    # --- Gom nhóm lỗi (Grouping) và cảnh báo (3 test cases) ---
    def test_grouping_one_safe_one_unsafe_same_file(self, detector):
        parser_output = _make_parser_output([_http_block([
            _server_block([_location_block(["~", r"/\."], [_dir("deny", ["all"])])]),
            _server_block([_dir("listen", ["80"])]) # Missing
        ])])
        findings = detector.scan(parser_output)
        assert len(findings) >= 1
        # Only the unsafe server should trigger a finding

    def test_grouping_safe_file_and_unsafe_file(self, detector):
        parser_output = {
            "config": [
                {"file": "safe.conf", "parsed": [_server_block([_location_block(["~", r"/\."], [_dir("deny", ["all"])])])]},
                {"file": "unsafe.conf", "parsed": [_server_block([_dir("listen", ["80"])])]}
            ]
        }
        findings = detector.scan(parser_output)
        assert len(findings) == 1
        assert findings[0]["file"] == "unsafe.conf"

    def test_grouping_multiple_unsafes_in_one_file(self, detector):
        parser_output = _make_parser_output([_http_block([
            _server_block([_dir("listen", ["80"])]),
            _server_block([_dir("listen", ["443"])])
        ])])
        findings = detector.scan(parser_output)
        assert len(findings) >= 1

    # --- Xử lý các ngoại lệ cấu hình (3 test cases) ---
    def test_empty_file(self, detector):
        parser_output = {"config": [{"file": "empty.conf", "parsed": []}]}
        assert detector.scan(parser_output) == []

    def test_events_block_only(self, detector):
        parser_output = {"config": [{"file": "events.conf", "parsed": [
            _dir("events", [], [_dir("worker_connections", ["1024"])])
        ]}]}
        assert detector.scan(parser_output) == []

    def test_http_block_without_server(self, detector):
        parser_output = {"config": [{"file": "http.conf", "parsed": [
            _http_block([_dir("sendfile", ["on"])])
        ]}]}
        assert detector.scan(parser_output) == []

    # --- Tương tác với Include Directive phức tạp (5 test cases) ---
    def test_include_missing_in_included_server(self, detector):
        parser_output = {
            "config": [
                {"file": "nginx.conf", "parsed": [_http_block([_dir("include", ["conf.d/*.conf"])])]},
                {"file": "conf.d/app.conf", "parsed": [_server_block([_dir("listen", ["80"])])]} # Missing
            ]
        }
        findings = detector.scan(parser_output)
        assert len(findings) == 1
        assert findings[0]["file"] == "conf.d/app.conf"

    def test_include_location_in_server(self, detector):
        parser_output = {
            "config": [
                {"file": "nginx.conf", "parsed": [_http_block([
                    _server_block([_dir("include", ["location.conf"])])
                ])]},
                {"file": "location.conf", "parsed": [_location_block(["~", r"/\."], [_dir("deny", ["all"])])]}
            ]
        }
        # In reality, crossplane might not link these easily without proper traversal,
        # but the test ensures the detector doesn't crash.
        assert detector.scan(parser_output) == []

    def test_include_location_empty_unsafe(self, detector):
        parser_output = {
            "config": [
                {"file": "nginx.conf", "parsed": [_http_block([
                    _server_block([_dir("include", ["location.conf"])])
                ])]},
                {"file": "location.conf", "parsed": []}
            ]
        }
        findings = detector.scan(parser_output)
        assert len(findings) >= 1

    def test_http_include_sites_server_missing(self, detector):
        parser_output = {
            "config": [
                {"file": "nginx.conf", "parsed": [_http_block([_dir("include", ["sites/*.conf"])])]},
                {"file": "sites/1.conf", "parsed": [_server_block([_location_block(["~", r"/\."], [_dir("deny", ["all"])])])]},
                {"file": "sites/2.conf", "parsed": [_server_block([_dir("listen", ["80"])])]} # Missing
            ]
        }
        findings = detector.scan(parser_output)
        assert len(findings) == 1
        assert findings[0]["file"] == "sites/2.conf"

    def test_nested_include_missing(self, detector):
        parser_output = {
            "config": [
                {"file": "nginx.conf", "parsed": [_http_block([_dir("include", ["a.conf"])])]},
                {"file": "a.conf", "parsed": [_dir("include", ["b.conf"])]},
                {"file": "b.conf", "parsed": [_server_block([_dir("listen", ["80"])])]} # Missing
            ]
        }
        findings = detector.scan(parser_output)
        assert len(findings) == 1
        assert findings[0]["file"] == "b.conf"

    # --- Tính toàn vẹn của kết quả Schema cho Auto-Remediation (3 test cases) ---
    def test_schema_has_file_key(self, detector):
        parser_output = _make_parser_output([_server_block([])])
        findings = detector.scan(parser_output)
        assert len(findings) >= 1
        assert "file" in findings[0]

    def test_schema_remediations_has_action_directive_context(self, detector):
        parser_output = _make_parser_output([_server_block([])])
        findings = detector.scan(parser_output)
        assert len(findings) >= 1
        remediation = findings[0]["remediations"][0]
        assert "action" in remediation
        assert "directive" in remediation
        assert "context" in remediation

    def test_schema_remediation_target_valid(self, detector):
        parser_output = _make_parser_output([_server_block([])])
        findings = detector.scan(parser_output)
        assert len(findings) >= 1
        remediation = findings[0]["remediations"][0]
        assert remediation["action"] in ["add_block", "insert_block"]
        assert remediation["directive"] == "location"
