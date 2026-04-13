"""
Unit tests cho Detector252 — CIS Benchmark 2.5.2
"Đảm bảo các trang báo lỗi mặc định (ví dụ: 404, 50x) và trang index.html mặc định không tham chiếu đến NGINX (Manual)"

Chiến lược Kiểm thử
─────────────
• Phần 1: Metadata Sanity Checks - 4 test cases.
• Phần 2: Kiểm thử hàm evaluate() / logic kiểm tra khối (Compliant) - 24 test cases.
• Phần 3: Kiểm thử hàm evaluate() (Non-Compliant) - 20 test cases.
• Phần 4: Kiểm thử hàm scan() toàn bộ đường ống - 15 test cases.
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


def _location_block(path: str, directives: list) -> dict:
    """Hàm hỗ trợ: tạo một block 'location' giả lập."""
    return _dir("location", [path], directives)


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
        assert detector.id == "2.5.2"

    def test_title_contains_error_and_index(self, detector):
        assert "error and index.html pages" in detector.title.lower()

    def test_level_assignment(self, detector):
        assert hasattr(detector, "profile") or hasattr(detector, "level")
        level_info = getattr(detector, "profile", getattr(detector, "level", ""))
        assert "level 1" in str(level_info).lower()

    def test_has_required_attributes(self, detector):
        for attr in ("description", "audit_procedure", "impact", "remediation"):
            assert getattr(detector, attr, None), f"Missing attribute: {attr}"


# ──────────────────────────────────────────────────────────────────────────────
# Phần 2 — evaluate() hoặc logic kiểm tra khối (Compliant) (24 Test Cases)
# ──────────────────────────────────────────────────────────────────────────────

class TestEvaluateCompliant:
    """Các cấu hình hợp lệ có chứa chỉ thị error_page đầy đủ cho 4xx và 5xx."""

    HTTP_CTX = ["http"]
    FILEPATH = "/etc/nginx/nginx.conf"
    EXACT_PATH = ["config", 0, "parsed", 0]

    def _eval(self, detector, directive, ctx=None):
        ctx = ctx or self.HTTP_CTX
        return detector.evaluate(directive, self.FILEPATH, ctx, self.EXACT_PATH)

    # --- Lỗi phổ biến 4xx (5 test cases) ---
    def test_error_page_404(self, detector):
        server = _server_block([_dir("error_page", ["404", "/404.html"]), _dir("error_page", ["500", "502", "503", "504", "/50x.html"])])
        assert self._eval(detector, _http_block([server])) is None

    def test_error_page_403(self, detector):
        server = _server_block([_dir("error_page", ["403", "/403.html"]), _dir("error_page", ["500", "502", "503", "504", "/50x.html"])])
        assert self._eval(detector, _http_block([server])) is None

    def test_error_page_400_401_403_404(self, detector):
        server = _server_block([_dir("error_page", ["400", "401", "403", "404", "/4xx.html"]), _dir("error_page", ["500", "502", "503", "504", "/50x.html"])])
        assert self._eval(detector, _http_block([server])) is None

    def test_error_page_404_http_block(self, detector):
        http = _http_block([_dir("error_page", ["404", "/404.html"]), _dir("error_page", ["500", "502", "503", "504", "/50x.html"]), _server_block([])])
        assert self._eval(detector, http) is None

    def test_error_page_4xx_multiple_lines(self, detector):
        server = _server_block([
            _dir("error_page", ["403", "/403.html"]),
            _dir("error_page", ["404", "/404.html"]),
            _dir("error_page", ["500", "502", "503", "504", "/50x.html"])
        ])
        assert self._eval(detector, _http_block([server])) is None

    # --- Lỗi hệ thống 5xx (5 test cases) ---
    def test_error_page_500_502_503_504(self, detector):
        server = _server_block([_dir("error_page", ["500", "502", "503", "504", "/50x.html"]), _dir("error_page", ["404", "404.html"])])
        assert self._eval(detector, _http_block([server])) is None

    def test_error_page_500(self, detector):
        server = _server_block([_dir("error_page", ["500", "502", "503", "504", "/500.html"]), _dir("error_page", ["404", "404.html"])])
        assert self._eval(detector, _http_block([server])) is None

    def test_error_page_50x_http_block(self, detector):
        http = _http_block([_dir("error_page", ["500", "502", "503", "504", "/50x.html"]), _dir("error_page", ["404", "404.html"]), _server_block([])])
        assert self._eval(detector, http) is None

    def test_error_page_5xx_multiple_lines(self, detector):
        server = _server_block([
            _dir("error_page", ["500", "502", "503", "504", "/50x.html"]),
            _dir("error_page", ["502", "503", "504", "/50x.html"]),
            _dir("error_page", ["404", "/404.html"])
        ])
        assert self._eval(detector, _http_block([server])) is None

    def test_error_page_all_4xx_5xx(self, detector):
        server = _server_block([
            _dir("error_page", ["404", "/404.html"]),
            _dir("error_page", ["500", "502", "503", "504", "/50x.html"])
        ])
        assert self._eval(detector, _http_block([server])) is None

    # --- Khai báo error_page kèm thay đổi mã phản hồi (4 test cases) ---
    def test_error_page_404_equals_200(self, detector):
        server = _server_block([_dir("error_page", ["404", "=200", "/empty.gif"]), _dir("error_page", ["500", "502", "503", "504", "/50x.html"])])
        assert self._eval(detector, _http_block([server])) is None

    def test_error_page_404_equals_empty(self, detector):
        server = _server_block([_dir("error_page", ["404", "=", "/404.php"]), _dir("error_page", ["500", "502", "503", "504", "/50x.html"])])
        assert self._eval(detector, _http_block([server])) is None

    def test_error_page_500_equals_200(self, detector):
        server = _server_block([_dir("error_page", ["500", "502", "503", "504", "=200", "/custom_50x.html"]), _dir("error_page", ["404", "404.html"])])
        assert self._eval(detector, _http_block([server])) is None

    def test_error_page_403_equals_404(self, detector):
        server = _server_block([_dir("error_page", ["403", "=404", "/404.html"]), _dir("error_page", ["500", "502", "503", "504", "/50x.html"])])
        assert self._eval(detector, _http_block([server])) is None

    # --- Cấu hình kết hợp nhiều cấp độ (5 test cases) ---
    def test_error_page_http_and_server(self, detector):
        http = _http_block([
            _dir("error_page", ["500", "502", "503", "504", "/50x.html"]),
            _server_block([_dir("error_page", ["404", "/404.html"])])
        ])
        assert self._eval(detector, http) is None

    def test_error_page_server_and_location(self, detector):
        server = _server_block([
            _dir("error_page", ["404", "/404.html"]),
            _location_block("/api/", [_dir("error_page", ["500", "502", "503", "504", "/api_error.html"])])
        ])
        assert self._eval(detector, _http_block([server])) is None

    def test_error_page_http_server_location(self, detector):
        http = _http_block([
            _dir("error_page", ["500", "502", "503", "504", "/50x.html"]),
            _server_block([
                _dir("error_page", ["404", "/404.html"]),
                _location_block("/admin", [_dir("error_page", ["403", "/403.html"])])
            ])
        ])
        assert self._eval(detector, http) is None

    def test_error_page_override_in_server(self, detector):
        http = _http_block([
            _dir("error_page", ["404", "/global_404.html"]), _dir("error_page", ["500", "502", "503", "504", "/50x.html"]),
            _server_block([_dir("error_page", ["404", "/custom_404.html"])])
        ])
        assert self._eval(detector, http) is None

    def test_error_page_override_in_location(self, detector):
        server = _server_block([
            _dir("error_page", ["500", "502", "503", "504", "/50x.html"]), _dir("error_page", ["404", "/404.html"]),
            _location_block("/upload", [_dir("error_page", ["500", "/upload_error.html"])])
        ])
        assert self._eval(detector, _http_block([server])) is None

    # --- Vị trí file tùy chỉnh khác nhau (5 test cases) ---
    def test_error_page_custom_path_1(self, detector):
        server = _server_block([_dir("error_page", ["404", "/custom_errors/404.html"]), _dir("error_page", ["500", "502", "503", "504", "/50x.html"])])
        assert self._eval(detector, _http_block([server])) is None

    def test_error_page_custom_path_2(self, detector):
        server = _server_block([_dir("error_page", ["50x", "/usr/share/nginx/html/custom_50x.html"]), _dir("error_page", ["404", "404.html"])])
        assert self._eval(detector, _http_block([server])) is None

    def test_error_page_custom_named_location(self, detector):
        server = _server_block([
            _dir("error_page", ["404", "@fallback"]), _dir("error_page", ["500", "502", "503", "504", "/50x.html"]),
            _location_block("@fallback", [_dir("return", ["404", "Not Found"])])
        ])
        assert self._eval(detector, _http_block([server])) is None

    def test_error_page_absolute_url(self, detector):
        server = _server_block([_dir("error_page", ["500", "502", "503", "504", "http://example.com/error.html"]), _dir("error_page", ["404", "404.html"])])
        assert self._eval(detector, _http_block([server])) is None

    def test_error_page_included_file(self, detector):
        parser_output = {
            "config": [
                {"file": "/etc/nginx/nginx.conf",
                 "parsed": [_http_block([_dir("include", ["conf.d/*.conf"])])]},
                {"file": "/etc/nginx/conf.d/errors.conf",
                 "parsed": [_server_block([_dir("error_page", ["404", "/404.html"]), _dir("error_page", ["500", "502", "503", "504", "/50x.html"])])]}
            ]
        }
        assert detector.scan(parser_output) == []


# ──────────────────────────────────────────────────────────────────────────────
# Phần 3 — evaluate(): Các trường hợp vi phạm (Non-Compliant) (20 Test Cases)
# ──────────────────────────────────────────────────────────────────────────────

class TestEvaluateNonCompliant:
    """Các cấu hình thiếu error_page hoặc định nghĩa không đầy đủ."""

    HTTP_CTX = ["http"]
    FILEPATH = "/etc/nginx/nginx.conf"
    EXACT_PATH = ["config", 0, "parsed", 0]

    def _eval(self, detector, directive, ctx=None):
        ctx = ctx or self.HTTP_CTX
        return detector.evaluate(directive, self.FILEPATH, ctx, self.EXACT_PATH)

    # --- Thiếu error_page hoàn toàn (5 test cases) ---
    def test_missing_error_page_completely_1(self, detector):
        server = _server_block([_dir("listen", ["80"])])
        assert self._eval(detector, _http_block([server])) is not None

    def test_missing_error_page_completely_2(self, detector):
        server = _server_block([_dir("server_name", ["example.com"])])
        assert self._eval(detector, _http_block([server])) is not None

    def test_missing_error_page_empty_server(self, detector):
        server = _server_block([_dir("root", ["/var/www/html"])])
        assert self._eval(detector, _http_block([server])) is not None

    def test_missing_error_page_http_block_empty(self, detector):
        http = _http_block([_server_block([_dir("root", ["/var/www/html"])])])
        assert self._eval(detector, http) is not None

    def test_missing_error_page_multiple_servers(self, detector):
        http = _http_block([
            _server_block([_dir("listen", ["80"])]),
            _server_block([_dir("listen", ["443"])])
        ])
        assert self._eval(detector, http) is not None

    # --- Chỉ khai báo một phần lỗi (5 test cases) ---
    def test_partial_error_page_only_404(self, detector):
        server = _server_block([_dir("error_page", ["404", "/404.html"])])
        result = self._eval(detector, _http_block([server]))
        assert result is not None

    def test_partial_error_page_only_500(self, detector):
        server = _server_block([_dir("error_page", ["500", "502", "503", "504", "/50x.html"])])
        assert self._eval(detector, _http_block([server])) is not None

    def test_partial_error_page_missing_502_503_504(self, detector):
        server = _server_block([_dir("error_page", ["404", "/404.html"]), _dir("error_page", ["500", "/50x.html"])])
        assert self._eval(detector, _http_block([server])) is not None

    def test_partial_error_page_only_50x(self, detector):
        server = _server_block([_dir("error_page", ["500", "502", "503", "504", "/50x.html"])])
        assert self._eval(detector, _http_block([server])) is not None

    def test_partial_error_page_http_level(self, detector):
        http = _http_block([
            _dir("error_page", ["404", "/404.html"]),
            _server_block([_dir("listen", ["80"])])
        ])
        assert self._eval(detector, http) is not None

    # --- Lỗi cú pháp hoặc thiếu URL đích (4 test cases) ---
    def test_invalid_error_page_no_url(self, detector):
        server = _server_block([_dir("error_page", ["404"])])
        assert self._eval(detector, _http_block([server])) is not None

    def test_invalid_error_page_missing_code_and_url(self, detector):
        server = _server_block([_dir("error_page", [])])
        assert self._eval(detector, _http_block([server])) is not None

    def test_invalid_error_page_50x_no_url(self, detector):
        server = _server_block([_dir("error_page", ["500", "502", "503", "504"])])
        assert self._eval(detector, _http_block([server])) is not None

    def test_invalid_error_page_equals_no_url(self, detector):
        server = _server_block([_dir("error_page", ["404", "="])])
        assert self._eval(detector, _http_block([server])) is not None

    # --- Kiểm tra cấu trúc dữ liệu phản hồi (6 test cases) ---
    def test_response_file_path(self, detector):
        server = _server_block([_dir("listen", ["80"])])
        result = self._eval(detector, _http_block([server]))
        assert result["file"] == self.FILEPATH

    def test_response_remediations_is_list(self, detector):
        server = _server_block([_dir("listen", ["80"])])
        result = self._eval(detector, _http_block([server]))
        assert isinstance(result["remediations"], list)

    def test_response_remediations_not_empty(self, detector):
        server = _server_block([_dir("listen", ["80"])])
        result = self._eval(detector, _http_block([server]))
        assert len(result["remediations"]) >= 1

    def test_response_action_is_add(self, detector):
        server = _server_block([_dir("listen", ["80"])])
        result = self._eval(detector, _http_block([server]))
        action = result["remediations"][0]["action"]
        assert action == "add"

    def test_response_directive_is_error_page(self, detector):
        server = _server_block([_dir("listen", ["80"])])
        result = self._eval(detector, _http_block([server]))
        assert result["remediations"][0]["directive"] == "error_page"

    def test_response_context_is_valid(self, detector):
        server = _server_block([_dir("listen", ["80"])])
        result = self._eval(detector, _http_block([server]))
        assert result["remediations"][0]["context"] in ["server", "http"]


# ──────────────────────────────────────────────────────────────────────────────
# Phần 4 — scan(): Toàn bộ đường ống (Full Pipeline Integration) (15 Test Cases)
# ──────────────────────────────────────────────────────────────────────────────

class TestScan:
    """Các bài test kiểm tra tích hợp toàn diện thông qua việc mô phỏng dữ liệu phân tích AST."""

    # --- Cấu hình an toàn đầy đủ (3 test cases) ---
    def test_full_secure_all_error_pages_in_http(self, detector):
        parser_output = _make_parser_output([_http_block([
            _dir("error_page", ["404", "/404.html"]),
            _dir("error_page", ["500", "502", "503", "504", "/50x.html"]),
            _server_block([_dir("listen", ["80"])]),
            _server_block([_dir("listen", ["443"])])
        ])])
        assert detector.scan(parser_output) == []

    def test_full_secure_all_error_pages_in_server(self, detector):
        parser_output = _make_parser_output([_http_block([
            _server_block([
                _dir("error_page", ["404", "/404.html"]),
                _dir("error_page", ["500", "502", "503", "504", "/50x.html"]),
                _dir("listen", ["80"])
            ])
        ])])
        assert detector.scan(parser_output) == []

    def test_full_secure_mixed_inheritance(self, detector):
        parser_output = _make_parser_output([_http_block([
            _dir("error_page", ["500", "502", "503", "504", "/50x.html"]),
            _server_block([
                _dir("error_page", ["404", "/404.html"]),
                _dir("listen", ["80"])
            ]),
            _server_block([
                _dir("error_page", ["404", "/custom_404.html"]),
                _dir("listen", ["443"])
            ])
        ])])
        assert detector.scan(parser_output) == []

    # --- Nhiều file cấu hình vi phạm (3 test cases) ---
    def test_multiple_files_missing_error_page(self, detector):
        parser_output = {
            "config": [
                {"file": "/etc/nginx/conf.d/api.conf",
                 "parsed": [_server_block([_dir("listen", ["80"])])]},
                {"file": "/etc/nginx/conf.d/admin.conf",
                 "parsed": [_server_block([_dir("listen", ["443"])])]}
            ]
        }
        findings = detector.scan(parser_output)
        assert len(findings) == 2
        files = [f["file"] for f in findings]
        assert "/etc/nginx/conf.d/api.conf" in files
        assert "/etc/nginx/conf.d/admin.conf" in files

    def test_multiple_files_one_valid_one_invalid(self, detector):
        parser_output = {
            "config": [
                {"file": "/etc/nginx/conf.d/valid.conf",
                 "parsed": [_server_block([
                     _dir("error_page", ["404", "/404.html"]),
                     _dir("error_page", ["500", "502", "503", "504", "/50x.html"])
                 ])]},
                {"file": "/etc/nginx/conf.d/invalid.conf",
                 "parsed": [_server_block([_dir("listen", ["80"])])]}
            ]
        }
        findings = detector.scan(parser_output)
        assert len(findings) == 1
        assert findings[0]["file"] == "/etc/nginx/conf.d/invalid.conf"

    def test_multiple_files_partial_missing(self, detector):
        parser_output = {
            "config": [
                {"file": "/etc/nginx/conf.d/partial1.conf",
                 "parsed": [_server_block([_dir("error_page", ["404", "/404.html"])])]},
                {"file": "/etc/nginx/conf.d/partial2.conf",
                 "parsed": [_server_block([_dir("error_page", ["500", "502", "503", "504", "/50x.html"])])]}
            ]
        }
        findings = detector.scan(parser_output)
        assert len(findings) == 2

    # --- Gom nhóm lỗi (Grouping) (3 test cases) ---
    def test_grouping_multiple_servers_same_file(self, detector):
        parser_output = _make_parser_output([_http_block([
            _server_block([_dir("listen", ["80"])]),
            _server_block([_dir("listen", ["8080"])])
        ])])
        findings = detector.scan(parser_output)
        assert len(findings) == 1
        assert len(findings[0]["remediations"]) >= 2

    def test_grouping_http_level_and_server_level(self, detector):
        parser_output = _make_parser_output([_http_block([
            _server_block([_dir("listen", ["80"])])
        ])])
        findings = detector.scan(parser_output)
        assert len(findings) == 1
        assert len(findings[0]["remediations"]) >= 1

    def test_grouping_three_servers_missing_error_page(self, detector):
        parser_output = _make_parser_output([_http_block([
            _server_block([_dir("listen", ["81"])]),
            _server_block([_dir("listen", ["82"])]),
            _server_block([_dir("listen", ["83"])])
        ])])
        findings = detector.scan(parser_output)
        assert len(findings) == 1
        assert len(findings[0]["remediations"]) >= 3

    # --- Xử lý khối server rỗng hoặc redirect (3 test cases) ---
    def test_ignore_redirect_only_server(self, detector):
        parser_output = _make_parser_output([_http_block([
            _server_block([
                _dir("listen", ["80"]),
                _dir("server_name", ["example.com"]),
                _dir("return", ["301", "https://$host$request_uri"])
            ])
        ])])
        assert detector.scan(parser_output) == []

    def test_ignore_empty_server(self, detector):
        parser_output = _make_parser_output([_http_block([
            _server_block([])
        ])])
        assert detector.scan(parser_output) == []

    def test_do_not_ignore_normal_server(self, detector):
        parser_output = _make_parser_output([_http_block([
            _server_block([
                _dir("listen", ["80"]),
                _dir("root", ["/var/www/html"])
            ])
        ])])
        assert len(detector.scan(parser_output)) == 1

    # --- Tính toàn vẹn của kết quả Schema (3 test cases) ---
    def test_schema_has_file_key(self, detector):
        parser_output = _make_parser_output([_http_block([_server_block([_dir("listen", ["80"])])])])
        findings = detector.scan(parser_output)
        assert "file" in findings[0]

    def test_schema_remediations_has_action_directive_context(self, detector):
        parser_output = _make_parser_output([_http_block([_server_block([_dir("listen", ["80"])])])])
        findings = detector.scan(parser_output)
        remediation = findings[0]["remediations"][0]
        assert "action" in remediation
        assert "directive" in remediation
        assert "context" in remediation

    def test_schema_remediation_target_add_error_page(self, detector):
        parser_output = _make_parser_output([_http_block([_server_block([_dir("listen", ["80"])])])])
        findings = detector.scan(parser_output)
        remediation = findings[0]["remediations"][0]
        assert remediation["action"] == "add"
        assert remediation["directive"] == "error_page"
