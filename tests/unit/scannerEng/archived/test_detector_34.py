"""
Unit tests cho Detector34 — CIS Benchmark 3.4
"Ensure proxies pass source IP information (Manual)"

Chiến lược Kiểm thử
─────────────
• Phần 1: Metadata Sanity Checks - 4 test cases.
• Phần 2: Kiểm thử hàm evaluate() / logic kiểm tra khối (Compliant) - 24 test cases.
• Phần 3: Kiểm thử hàm evaluate() (Non-Compliant) - 22 test cases.
• Phần 4: Kiểm thử hàm scan() toàn bộ đường ống - 20 test cases.
"""

import pytest
from core.scannerEng.recommendations.archived.detector_34 import Detector34


@pytest.fixture
def detector():
    """Trả về một instance Detector34 mới cho mỗi test."""
    return Detector34()


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
        assert detector.id == "3.4"

    def test_title_contains_proxies_ip(self, detector):
        assert "proxies pass source IP information" in detector.title

    def test_level_assignment(self, detector):
        assert hasattr(detector, "profile") or hasattr(
            detector, "level") or True
        level_info = getattr(detector, "profile", getattr(
            detector, "level", "level 1"))
        assert "level 1" in str(level_info).lower()
        assert "proxy" in str(level_info).lower(
        ) or "loadbalancer" in str(level_info).lower()

    def test_has_required_attributes(self, detector):
        for attr in ("description", "audit_procedure", "impact", "remediation"):
            assert getattr(detector, attr, None), f"Missing attribute: {attr}"


# ──────────────────────────────────────────────────────────────────────────────
# Phần 2 — evaluate() hoặc logic kiểm tra khối (Compliant) (24 Test Cases)
# ──────────────────────────────────────────────────────────────────────────────

class TestEvaluateCompliant:
    """Các cấu hình hợp lệ có khai báo truyền IP đầy đủ cho X-Forwarded-For và X-Real-IP."""

    HTTP_CTX = ["http"]
    FILEPATH = "/etc/nginx/nginx.conf"
    EXACT_PATH = ["config", 0, "parsed", 0]

    def _eval(self, detector, directive, ctx=None):
        ctx = ctx or self.HTTP_CTX
        return detector.evaluate(directive, self.FILEPATH, ctx, self.EXACT_PATH)

    # --- Thiết lập an toàn tại khối location (6 test cases) ---
    def test_location_safe_basic(self, detector):
        loc = _location_block(["/"], [
            _dir("proxy_pass", ["http://backend"]),
            _dir("proxy_set_header", [
                 "X-Forwarded-For", "$proxy_add_x_forwarded_for"]),
            _dir("proxy_set_header", ["X-Real-IP", "$remote_addr"])
        ])
        assert self._eval(
            detector, loc, ["http", "server", "location"]) is None

    def test_location_safe_with_redirect(self, detector):
        loc = _location_block(["/api"], [
            _dir("proxy_pass", ["http://api_backend"]),
            _dir("proxy_redirect", ["off"]),
            _dir("proxy_set_header", [
                 "X-Forwarded-For", "$proxy_add_x_forwarded_for"]),
            _dir("proxy_set_header", ["X-Real-IP", "$remote_addr"])
        ])
        assert self._eval(
            detector, loc, ["http", "server", "location"]) is None

    def test_location_safe_different_value(self, detector):
        loc = _location_block(["/test"], [
            _dir("proxy_pass", ["http://test_backend"]),
            _dir("proxy_set_header", [
                 "X-Forwarded-For", "$http_x_forwarded_for"]),
            _dir("proxy_set_header", ["X-Real-IP", "$remote_addr"])
        ])
        assert self._eval(
            detector, loc, ["http", "server", "location"]) is None

    def test_location_safe_uppercase_names(self, detector):
        loc = _location_block(["/upper"], [
            _dir("proxy_pass", ["http://backend"]),
            _dir("proxy_set_header", [
                 "X-FORWARDED-FOR", "$proxy_add_x_forwarded_for"]),
            _dir("proxy_set_header", ["X-REAL-IP", "$remote_addr"])
        ])
        assert self._eval(
            detector, loc, ["http", "server", "location"]) is None

    def test_location_safe_lowercase_names(self, detector):
        loc = _location_block(["/lower"], [
            _dir("proxy_pass", ["http://backend"]),
            _dir("proxy_set_header", [
                 "x-forwarded-for", "$proxy_add_x_forwarded_for"]),
            _dir("proxy_set_header", ["x-real-ip", "$remote_addr"])
        ])
        assert self._eval(
            detector, loc, ["http", "server", "location"]) is None

    def test_location_safe_large_config(self, detector):
        loc = _location_block(["/large"], [
            _dir("proxy_pass", ["http://backend"]),
            _dir("proxy_connect_timeout", ["60s"]),
            _dir("proxy_send_timeout", ["60s"]),
            _dir("proxy_read_timeout", ["60s"]),
            _dir("proxy_set_header", [
                 "X-Forwarded-For", "$proxy_add_x_forwarded_for"]),
            _dir("proxy_set_header", ["X-Real-IP", "$remote_addr"])
        ])
        assert self._eval(
            detector, loc, ["http", "server", "location"]) is None

    # --- Thiết lập an toàn tại khối server hoặc http (6 test cases) ---
    def test_safe_inherited_from_http(self, detector):
        http_block = _http_block([
            _dir("proxy_set_header", [
                 "X-Forwarded-For", "$proxy_add_x_forwarded_for"]),
            _dir("proxy_set_header", ["X-Real-IP", "$remote_addr"]),
            _server_block([
                _location_block(
                    ["/"], [_dir("proxy_pass", ["http://backend"])])
            ])
        ])
        assert self._eval(detector, http_block) is None

    def test_safe_inherited_from_server(self, detector):
        server = _server_block([
            _dir("proxy_set_header", [
                 "X-Forwarded-For", "$proxy_add_x_forwarded_for"]),
            _dir("proxy_set_header", ["X-Real-IP", "$remote_addr"]),
            _location_block(["/"], [_dir("proxy_pass", ["http://backend"])])
        ])
        assert self._eval(detector, server, ["http", "server"]) is None

    def test_safe_http_multiple_locations(self, detector):
        http_block = _http_block([
            _dir("proxy_set_header", [
                 "X-Forwarded-For", "$proxy_add_x_forwarded_for"]),
            _dir("proxy_set_header", ["X-Real-IP", "$remote_addr"]),
            _server_block([
                _location_block(
                    ["/a"], [_dir("proxy_pass", ["http://backend_a"])]),
                _location_block(
                    ["/b"], [_dir("proxy_pass", ["http://backend_b"])])
            ])
        ])
        assert self._eval(detector, http_block) is None

    def test_safe_server_multiple_locations(self, detector):
        server = _server_block([
            _dir("proxy_set_header", [
                 "X-Forwarded-For", "$proxy_add_x_forwarded_for"]),
            _dir("proxy_set_header", ["X-Real-IP", "$remote_addr"]),
            _location_block(["/1"], [_dir("proxy_pass", ["http://1"])]),
            _location_block(["/2"], [_dir("proxy_pass", ["http://2"])])
        ])
        assert self._eval(detector, server, ["http", "server"]) is None

    def test_safe_http_server_no_override(self, detector):
        http_block = _http_block([
            _dir("proxy_set_header", [
                 "X-Forwarded-For", "$proxy_add_x_forwarded_for"]),
            _dir("proxy_set_header", ["X-Real-IP", "$remote_addr"]),
            _server_block([
                _dir("listen", ["80"]),
                _location_block(
                    ["/"], [_dir("proxy_pass", ["http://backend"])])
            ])
        ])
        assert self._eval(detector, http_block) is None

    def test_safe_server_nested_locations(self, detector):
        server = _server_block([
            _dir("proxy_set_header", [
                 "X-Forwarded-For", "$proxy_add_x_forwarded_for"]),
            _dir("proxy_set_header", ["X-Real-IP", "$remote_addr"]),
            _location_block(["/parent"], [
                _location_block(["/parent/child"],
                                [_dir("proxy_pass", ["http://backend"])])
            ])
        ])
        assert self._eval(detector, server, ["http", "server"]) is None

    # --- Kiểm tra lồng ghép đệ quy và cấu hình location tương ứng (Nested Contexts) (6 test cases) ---
    def test_nested_http_server_redeclares(self, detector):
        http_block = _http_block([
            _dir("proxy_set_header", [
                 "X-Forwarded-For", "$proxy_add_x_forwarded_for"]),
            _dir("proxy_set_header", ["X-Real-IP", "$remote_addr"]),
            _server_block([
                _dir("proxy_set_header", ["Host", "$host"]),
                # Vì Host ghi đè proxy_set_header, phải khai báo lại IP headers để an toàn
                _dir("proxy_set_header", [
                     "X-Forwarded-For", "$proxy_add_x_forwarded_for"]),
                _dir("proxy_set_header", ["X-Real-IP", "$remote_addr"]),
                _location_block(
                    ["/"], [_dir("proxy_pass", ["http://backend"])])
            ])
        ])
        assert self._eval(detector, http_block) is None

    def test_nested_location_outer_headers(self, detector):
        loc = _location_block(["/outer"], [
            _dir("proxy_set_header", [
                 "X-Forwarded-For", "$proxy_add_x_forwarded_for"]),
            _dir("proxy_set_header", ["X-Real-IP", "$remote_addr"]),
            _location_block(["/outer/inner"], [
                _dir("proxy_pass", ["http://backend"])
            ])
        ])
        assert self._eval(
            detector, loc, ["http", "server", "location"]) is None

    def test_nested_location_inner_headers(self, detector):
        loc = _location_block(["/outer"], [
            _location_block(["/outer/inner"], [
                _dir("proxy_pass", ["http://backend"]),
                _dir("proxy_set_header", [
                     "X-Forwarded-For", "$proxy_add_x_forwarded_for"]),
                _dir("proxy_set_header", ["X-Real-IP", "$remote_addr"])
            ])
        ])
        assert self._eval(
            detector, loc, ["http", "server", "location"]) is None

    def test_nested_location_outer_proxy_inner_headers(self, detector):
        server = _server_block([
            _dir("proxy_set_header", [
                 "X-Forwarded-For", "$proxy_add_x_forwarded_for"]),
            _dir("proxy_set_header", ["X-Real-IP", "$remote_addr"]),
            _location_block(["/outer"], [
                _dir("proxy_pass", ["http://backend1"]),
                _location_block(["/outer/inner"], [
                    _dir("proxy_set_header", ["X-Custom", "Value"]),
                    # Phải khai báo lại vì ghi đè proxy_set_header
                    _dir("proxy_set_header", [
                         "X-Forwarded-For", "$proxy_add_x_forwarded_for"]),
                    _dir("proxy_set_header", ["X-Real-IP", "$remote_addr"]),
                    _dir("proxy_pass", ["http://backend2"])
                ])
            ])
        ])
        assert self._eval(detector, server, ["http", "server"]) is None

    def test_nested_if_block(self, detector):
        loc = _location_block(["/"], [
            _dir("proxy_set_header", [
                 "X-Forwarded-For", "$proxy_add_x_forwarded_for"]),
            _dir("proxy_set_header", ["X-Real-IP", "$remote_addr"]),
            _dir("if", ["($request_method = POST)"], [
                _dir("proxy_pass", ["http://backend"])
            ])
        ])
        assert self._eval(
            detector, loc, ["http", "server", "location"]) is None

    def test_nested_limit_except(self, detector):
        loc = _location_block(["/api"], [
            _dir("proxy_set_header", [
                 "X-Forwarded-For", "$proxy_add_x_forwarded_for"]),
            _dir("proxy_set_header", ["X-Real-IP", "$remote_addr"]),
            _dir("limit_except", ["GET"], [
                _dir("proxy_pass", ["http://backend"])
            ])
        ])
        assert self._eval(
            detector, loc, ["http", "server", "location"]) is None

    # --- Kết hợp với các chỉ thị bảo mật khác (6 test cases) ---
    def test_combined_with_proxy_hide_header(self, detector):
        loc = _location_block(["/"], [
            _dir("proxy_pass", ["http://backend"]),
            _dir("proxy_hide_header", ["X-Powered-By"]),
            _dir("proxy_set_header", [
                 "X-Forwarded-For", "$proxy_add_x_forwarded_for"]),
            _dir("proxy_set_header", ["X-Real-IP", "$remote_addr"])
        ])
        assert self._eval(
            detector, loc, ["http", "server", "location"]) is None

    def test_combined_with_proxy_set_header_host(self, detector):
        loc = _location_block(["/"], [
            _dir("proxy_pass", ["http://backend"]),
            _dir("proxy_set_header", ["Host", "$host"]),
            _dir("proxy_set_header", [
                 "X-Forwarded-For", "$proxy_add_x_forwarded_for"]),
            _dir("proxy_set_header", ["X-Real-IP", "$remote_addr"])
        ])
        assert self._eval(
            detector, loc, ["http", "server", "location"]) is None

    def test_combined_with_add_header(self, detector):
        loc = _location_block(["/"], [
            _dir("proxy_pass", ["http://backend"]),
            _dir("add_header", ["X-Frame-Options", "SAMEORIGIN"]),
            _dir("proxy_set_header", [
                 "X-Forwarded-For", "$proxy_add_x_forwarded_for"]),
            _dir("proxy_set_header", ["X-Real-IP", "$remote_addr"])
        ])
        assert self._eval(
            detector, loc, ["http", "server", "location"]) is None

    def test_combined_with_proxy_ssl_verify(self, detector):
        loc = _location_block(["/"], [
            _dir("proxy_pass", ["https://backend"]),
            _dir("proxy_ssl_verify", ["on"]),
            _dir("proxy_set_header", [
                 "X-Forwarded-For", "$proxy_add_x_forwarded_for"]),
            _dir("proxy_set_header", ["X-Real-IP", "$remote_addr"])
        ])
        assert self._eval(
            detector, loc, ["http", "server", "location"]) is None

    def test_combined_with_proxy_buffering(self, detector):
        loc = _location_block(["/"], [
            _dir("proxy_pass", ["http://backend"]),
            _dir("proxy_buffering", ["off"]),
            _dir("proxy_set_header", [
                 "X-Forwarded-For", "$proxy_add_x_forwarded_for"]),
            _dir("proxy_set_header", ["X-Real-IP", "$remote_addr"])
        ])
        assert self._eval(
            detector, loc, ["http", "server", "location"]) is None

    def test_combined_with_rewrite(self, detector):
        loc = _location_block(["/old"], [
            _dir("rewrite", ["^/old(.*)$", "/new$1", "break"]),
            _dir("proxy_pass", ["http://backend"]),
            _dir("proxy_set_header", [
                 "X-Forwarded-For", "$proxy_add_x_forwarded_for"]),
            _dir("proxy_set_header", ["X-Real-IP", "$remote_addr"])
        ])
        assert self._eval(
            detector, loc, ["http", "server", "location"]) is None


# ──────────────────────────────────────────────────────────────────────────────
# Phần 3 — evaluate() hoặc logic kiểm tra khối (Non-Compliant) (22 Test Cases)
# ──────────────────────────────────────────────────────────────────────────────

class TestEvaluateNonCompliant:
    """Các cấu hình thiếu hoặc sai cấu hình truyền IP thật, kích hoạt cảnh báo vi phạm."""

    HTTP_CTX = ["http"]
    FILEPATH = "/etc/nginx/nginx.conf"
    EXACT_PATH = ["config", 0, "parsed", 0]

    def _eval(self, detector, directive, ctx=None):
        ctx = ctx or self.HTTP_CTX
        return detector.evaluate(directive, self.FILEPATH, ctx, self.EXACT_PATH)

    # --- Không khai báo proxy_set_header cần thiết (Implicitly default) (6 test cases) ---
    def test_location_proxy_no_headers(self, detector):
        loc = _location_block(["/"], [_dir("proxy_pass", ["http://backend"])])
        assert self._eval(
            detector, loc, ["http", "server", "location"]) is not None

    def test_location_proxy_only_host(self, detector):
        loc = _location_block(["/"], [
            _dir("proxy_pass", ["http://backend"]),
            _dir("proxy_set_header", ["Host", "$host"])
        ])
        assert self._eval(
            detector, loc, ["http", "server", "location"]) is not None

    def test_server_proxy_no_headers(self, detector):
        server = _server_block([
            _dir("listen", ["80"]),
            _dir("proxy_pass", ["http://backend"])
        ])
        assert self._eval(detector, server, ["http", "server"]) is not None

    def test_multiple_locations_no_headers(self, detector):
        server = _server_block([
            _location_block(["/1"], [_dir("proxy_pass", ["http://backend1"])]),
            _location_block(["/2"], [_dir("proxy_pass", ["http://backend2"])])
        ])
        assert self._eval(detector, server, ["http", "server"]) is not None

    def test_http_proxy_no_headers(self, detector):
        # Dù proxy_pass hiếm khi ở http, nếu có thì vẫn bắt lỗi
        http_block = _http_block([_dir("proxy_pass", ["http://backend"])])
        assert self._eval(detector, http_block) is not None

    def test_nested_location_no_headers(self, detector):
        loc = _location_block(["/outer"], [
            _location_block(["/outer/inner"],
                            [_dir("proxy_pass", ["http://backend"])])
        ])
        assert self._eval(
            detector, loc, ["http", "server", "location"]) is not None

    # --- Khai báo thiếu một trong các header quan trọng (5 test cases) ---
    def test_missing_x_forwarded_for(self, detector):
        loc = _location_block(["/"], [
            _dir("proxy_pass", ["http://backend"]),
            _dir("proxy_set_header", ["X-Real-IP", "$remote_addr"])
        ])
        assert self._eval(
            detector, loc, ["http", "server", "location"]) is not None

    def test_missing_x_real_ip(self, detector):
        loc = _location_block(["/"], [
            _dir("proxy_pass", ["http://backend"]),
            _dir("proxy_set_header", [
                 "X-Forwarded-For", "$proxy_add_x_forwarded_for"])
        ])
        assert self._eval(
            detector, loc, ["http", "server", "location"]) is not None

    def test_override_loses_x_real_ip(self, detector):
        server = _server_block([
            _dir("proxy_set_header", ["X-Real-IP", "$remote_addr"]),
            _location_block(["/"], [
                _dir("proxy_pass", ["http://backend"]),
                _dir("proxy_set_header", ["Host", "$host"]),
                _dir("proxy_set_header", [
                     "X-Forwarded-For", "$proxy_add_x_forwarded_for"])
                # Bị mất X-Real-IP do ghi đè
            ])
        ])
        assert self._eval(detector, server, ["http", "server"]) is not None

    def test_override_loses_x_forwarded_for(self, detector):
        http_block = _http_block([
            _dir("proxy_set_header", [
                 "X-Forwarded-For", "$proxy_add_x_forwarded_for"]),
            _server_block([
                _dir("proxy_set_header", ["X-Real-IP", "$remote_addr"]),
                _location_block(
                    ["/"], [_dir("proxy_pass", ["http://backend"])])
                # Mất X-Forwarded-For do khối server có proxy_set_header
            ])
        ])
        assert self._eval(detector, http_block) is not None

    def test_http_has_x_real_ip_missing_x_forwarded_for(self, detector):
        http_block = _http_block([
            _dir("proxy_set_header", ["X-Real-IP", "$remote_addr"]),
            _server_block([
                _location_block(
                    ["/"], [_dir("proxy_pass", ["http://backend"])])
            ])
        ])
        assert self._eval(detector, http_block) is not None

    # --- Cấu hình proxy_set_header sai giá trị (4 test cases) ---
    def test_x_real_ip_static_string(self, detector):
        loc = _location_block(["/"], [
            _dir("proxy_pass", ["http://backend"]),
            _dir("proxy_set_header", [
                 "X-Forwarded-For", "$proxy_add_x_forwarded_for"]),
            _dir("proxy_set_header", ["X-Real-IP", "1.1.1.1"])
        ])
        assert self._eval(
            detector, loc, ["http", "server", "location"]) is not None

    def test_x_forwarded_for_static_string(self, detector):
        loc = _location_block(["/"], [
            _dir("proxy_pass", ["http://backend"]),
            _dir("proxy_set_header", ["X-Forwarded-For", "192.168.1.1"]),
            _dir("proxy_set_header", ["X-Real-IP", "$remote_addr"])
        ])
        assert self._eval(
            detector, loc, ["http", "server", "location"]) is not None

    def test_x_real_ip_empty_value(self, detector):
        loc = _location_block(["/"], [
            _dir("proxy_pass", ["http://backend"]),
            _dir("proxy_set_header", [
                 "X-Forwarded-For", "$proxy_add_x_forwarded_for"]),
            _dir("proxy_set_header", ["X-Real-IP", ""])
        ])
        assert self._eval(
            detector, loc, ["http", "server", "location"]) is not None

    def test_x_forwarded_for_empty_value(self, detector):
        loc = _location_block(["/"], [
            _dir("proxy_pass", ["http://backend"]),
            _dir("proxy_set_header", ["X-Forwarded-For", ""]),
            _dir("proxy_set_header", ["X-Real-IP", "$remote_addr"])
        ])
        assert self._eval(
            detector, loc, ["http", "server", "location"]) is not None

    # --- Kiểm tra cấu trúc dữ liệu phản hồi JSON Contract (7 test cases) ---
    def test_response_file_path(self, detector):
        loc = _location_block(["/"], [_dir("proxy_pass", ["http://backend"])])
        result = self._eval(detector, loc, ["http", "server", "location"])
        assert result is not None
        assert result.get("file") == self.FILEPATH

    def test_response_remediations_is_list(self, detector):
        loc = _location_block(["/"], [_dir("proxy_pass", ["http://backend"])])
        result = self._eval(detector, loc, ["http", "server", "location"])
        assert result is not None
        assert isinstance(result.get("remediations"), list)

    def test_response_action_is_add_or_insert(self, detector):
        loc = _location_block(["/"], [_dir("proxy_pass", ["http://backend"])])
        result = self._eval(detector, loc, ["http", "server", "location"])
        assert result is not None
        action = result["remediations"][0].get("action")
        assert action in ["add", "insert"]

    def test_response_directive_targets_proxy_set_header(self, detector):
        loc = _location_block(["/"], [_dir("proxy_pass", ["http://backend"])])
        result = self._eval(detector, loc, ["http", "server", "location"])
        assert result is not None
        directive = result["remediations"][0].get("directive")
        assert directive == "proxy_set_header"

    def test_response_value_contains_headers(self, detector):
        loc = _location_block(["/"], [_dir("proxy_pass", ["http://backend"])])
        result = self._eval(detector, loc, ["http", "server", "location"])
        assert result is not None
        values = [r.get("value", "") for r in result["remediations"]]
        assert any("X-Forwarded-For" in v for v in values)
        assert any("X-Real-IP" in v for v in values)

    def test_response_context_is_valid(self, detector):
        loc = _location_block(["/"], [_dir("proxy_pass", ["http://backend"])])
        result = self._eval(detector, loc, ["http", "server", "location"])
        assert result is not None
        context = result["remediations"][0].get("context")
        # Tuỳ implement, context có thể là dict
        assert context is not None

    def test_response_has_two_remediations_if_both_missing(self, detector):
        loc = _location_block(["/"], [_dir("proxy_pass", ["http://backend"])])
        result = self._eval(detector, loc, ["http", "server", "location"])
        assert result is not None
        # Cần thêm 2 header -> có 2 remediations
        assert len(result.get("remediations", [])) >= 2


# ──────────────────────────────────────────────────────────────────────────────
# Phần 4 — scan(): Toàn bộ đường ống (Full Pipeline Integration) (20 Test Cases)
# ──────────────────────────────────────────────────────────────────────────────

class TestScan:
    """Các bài test kiểm tra tích hợp toàn diện thông qua việc mô phỏng dữ liệu phân tích AST đệ quy."""

    # --- Cấu hình an toàn trên toàn bộ hệ thống (3 test cases) ---
    def test_safe_full_system_single_file(self, detector):
        parser_output = _make_parser_output([_http_block([
            _server_block([
                _dir("proxy_set_header", [
                     "X-Forwarded-For", "$proxy_add_x_forwarded_for"]),
                _dir("proxy_set_header", ["X-Real-IP", "$remote_addr"]),
                _location_block(
                    ["/"], [_dir("proxy_pass", ["http://backend"])])
            ])
        ])])
        assert detector.scan(parser_output) == []

    def test_safe_full_system_multiple_files(self, detector):
        parser_output = {
            "config": [
                {"file": "/etc/nginx/nginx.conf",
                 "parsed": [_http_block([
                     _dir("proxy_set_header", [
                          "X-Forwarded-For", "$proxy_add_x_forwarded_for"]),
                     _dir("proxy_set_header", ["X-Real-IP", "$remote_addr"])
                 ])]},
                {"file": "/etc/nginx/conf.d/app.conf",
                 "parsed": [_server_block([
                     _location_block(
                         ["/"], [_dir("proxy_pass", ["http://backend"])])
                 ])]}
            ]
        }
        assert detector.scan(parser_output) == []

    def test_safe_mixed_overrides(self, detector):
        parser_output = {
            "config": [
                {"file": "/etc/nginx/nginx.conf",
                 "parsed": [_http_block([
                     _dir("proxy_set_header", [
                          "X-Forwarded-For", "$proxy_add_x_forwarded_for"]),
                     _dir("proxy_set_header", ["X-Real-IP", "$remote_addr"])
                 ])]},
                {"file": "/etc/nginx/conf.d/app.conf",
                 "parsed": [_server_block([
                     _dir("proxy_set_header", ["Host", "$host"]),
                     _dir("proxy_set_header", [
                          "X-Forwarded-For", "$proxy_add_x_forwarded_for"]),
                     _dir("proxy_set_header", ["X-Real-IP", "$remote_addr"]),
                     _location_block(
                         ["/"], [_dir("proxy_pass", ["http://backend"])])
                 ])]}
            ]
        }
        assert detector.scan(parser_output) == []

    # --- Nhận diện sự vắng mặt của chỉ thị ở hệ thống đa tệp (3 test cases) ---
    def test_missing_in_one_file_among_many(self, detector):
        parser_output = {
            "config": [
                {"file": "nginx.conf", "parsed": [_http_block([])]},
                {"file": "app1.conf", "parsed": [_server_block([
                    _dir("proxy_set_header", [
                         "X-Forwarded-For", "$proxy_add_x_forwarded_for"]),
                    _dir("proxy_set_header", ["X-Real-IP", "$remote_addr"]),
                    _location_block(["/"], [_dir("proxy_pass", ["http://1"])])
                ])]},
                {"file": "app2.conf", "parsed": [_server_block([
                    _location_block(
                        ["/"], [_dir("proxy_pass", ["http://2"])])  # Missing
                ])]}
            ]
        }
        findings = detector.scan(parser_output)
        assert len(findings) >= 1
        assert any(f["file"] == "app2.conf" for f in findings)

    def test_missing_in_multiple_files(self, detector):
        parser_output = {
            "config": [
                {"file": "app1.conf", "parsed": [_server_block([
                    _location_block(["/"], [_dir("proxy_pass", ["http://1"])])
                ])]},
                {"file": "app2.conf", "parsed": [_server_block([
                    _location_block(["/"], [_dir("proxy_pass", ["http://2"])])
                ])]}
            ]
        }
        findings = detector.scan(parser_output)
        assert len(findings) >= 2

    def test_partial_missing_across_files(self, detector):
        parser_output = {
            "config": [
                {"file": "nginx.conf", "parsed": [_http_block([
                    # Thiếu X-Forwarded-For
                    _dir("proxy_set_header", ["X-Real-IP", "$remote_addr"])
                ])]},
                {"file": "app.conf", "parsed": [_server_block([
                    _location_block(["/"], [_dir("proxy_pass", ["http://1"])])
                ])]}
            ]
        }
        findings = detector.scan(parser_output)
        assert len(findings) >= 1

    # --- Gom nhóm lỗi (Grouping) và cảnh báo ghi đè (3 test cases) ---
    def test_grouping_http_missing_when_server_has_proxy(self, detector):
        parser_output = _make_parser_output([_http_block([
            _server_block([
                _location_block(["/1"], [_dir("proxy_pass", ["http://1"])]),
                _location_block(["/2"], [_dir("proxy_pass", ["http://2"])])
            ])
        ])])
        findings = detector.scan(parser_output)
        assert len(findings) >= 1

    def test_override_in_location_removes_headers(self, detector):
        parser_output = {
            "config": [
                {"file": "app.conf", "parsed": [_server_block([
                    _dir("proxy_set_header", [
                         "X-Forwarded-For", "$proxy_add_x_forwarded_for"]),
                    _dir("proxy_set_header", ["X-Real-IP", "$remote_addr"]),
                    _location_block(
                        ["/safe"], [_dir("proxy_pass", ["http://safe"])]),
                    _location_block(["/unsafe"], [
                        _dir("proxy_pass", ["http://unsafe"]),
                        # Xoá mất IP headers
                        _dir("proxy_set_header", ["Host", "$host"])
                    ])
                ])]}
            ]
        }
        findings = detector.scan(parser_output)
        assert len(findings) >= 1

    def test_safe_and_unsafe_in_same_server(self, detector):
        parser_output = _make_parser_output([_server_block([
            _location_block(["/safe"], [
                _dir("proxy_pass", ["http://safe"]),
                _dir("proxy_set_header", [
                     "X-Forwarded-For", "$proxy_add_x_forwarded_for"]),
                _dir("proxy_set_header", ["X-Real-IP", "$remote_addr"])
            ]),
            _location_block(
                ["/unsafe"], [_dir("proxy_pass", ["http://unsafe"])])
        ])])
        findings = detector.scan(parser_output)
        assert len(findings) >= 1

    # --- Xử lý các ngoại lệ cấu hình (3 test cases) ---
    def test_empty_file_no_error(self, detector):
        parser_output = {"config": [{"file": "empty.conf", "parsed": []}]}
        assert detector.scan(parser_output) == []

    def test_no_proxy_pass_anywhere(self, detector):
        parser_output = {"config": [{"file": "app.conf", "parsed": [_server_block([
            _location_block(["/"], [_dir("return", ["200", "OK"])])
        ])]}]}
        assert detector.scan(parser_output) == []

    def test_other_protocols_stream_events(self, detector):
        parser_output = {"config": [{"file": "stream.conf", "parsed": [
            _dir("stream", [], [_server_block([_dir("listen", ["12345"])])]),
            _dir("events", [], [_dir("worker_connections", ["1024"])])
        ]}]}
        assert detector.scan(parser_output) == []

    # --- Tương tác với Include Directive phức tạp (5 test cases) ---
    def test_included_file_inherits(self, detector):
        parser_output = {
            "config": [
                {"file": "nginx.conf", "parsed": [_http_block([
                    _dir("proxy_set_header", [
                         "X-Forwarded-For", "$proxy_add_x_forwarded_for"]),
                    _dir("proxy_set_header", ["X-Real-IP", "$remote_addr"]),
                    _dir("include", ["conf.d/*.conf"])
                ])]},
                {"file": "conf.d/app.conf", "parsed": [_server_block([
                    _location_block(
                        ["/"], [_dir("proxy_pass", ["http://backend"])])
                ])]}
            ]
        }
        assert detector.scan(parser_output) == []

    def test_included_file_missing_headers(self, detector):
        parser_output = {
            "config": [
                {"file": "nginx.conf", "parsed": [_http_block([
                    _dir("include", ["conf.d/*.conf"])
                ])]},
                {"file": "conf.d/app.conf", "parsed": [_server_block([
                    _location_block(
                        ["/"], [_dir("proxy_pass", ["http://backend"])])
                ])]}
            ]
        }
        findings = detector.scan(parser_output)
        assert len(findings) >= 1

    def test_nested_include_missing_headers(self, detector):
        parser_output = {
            "config": [
                {"file": "nginx.conf", "parsed": [_http_block([
                    _dir("include", ["sites/*"])
                ])]},
                {"file": "sites/default",
                    "parsed": [_dir("include", ["/etc/nginx/app.conf"])]},
                {"file": "/etc/nginx/app.conf", "parsed": [_server_block([
                    _location_block(
                        ["/"], [_dir("proxy_pass", ["http://backend"])])
                ])]}
            ]
        }
        findings = detector.scan(parser_output)
        assert len(findings) >= 1

    def test_include_with_unsafe_override_in_child(self, detector):
        parser_output = {
            "config": [
                {"file": "nginx.conf", "parsed": [_http_block([
                    _dir("proxy_set_header", [
                         "X-Forwarded-For", "$proxy_add_x_forwarded_for"]),
                    _dir("proxy_set_header", ["X-Real-IP", "$remote_addr"]),
                    _dir("include", ["conf.d/*.conf"])
                ])]},
                {"file": "conf.d/app.conf", "parsed": [_server_block([
                    _dir("proxy_set_header", ["Host", "$host"]),  # Mất kế thừa
                    _location_block(
                        ["/"], [_dir("proxy_pass", ["http://backend"])])
                ])]}
            ]
        }
        findings = detector.scan(parser_output)
        assert len(findings) >= 1

    def test_include_inside_location_missing(self, detector):
        parser_output = {
            "config": [
                {"file": "nginx.conf", "parsed": [_http_block([
                    _server_block([
                        _location_block(["/"], [
                            _dir("include", ["proxy_params"])
                        ])
                    ])
                ])]},
                {"file": "proxy_params", "parsed": [
                    _dir("proxy_pass", ["http://backend"])
                    # Thiếu headers
                ]}
            ]
        }
        findings = detector.scan(parser_output)
        assert len(findings) >= 1

    # --- Tính toàn vẹn của kết quả Schema cho Auto-Remediation (3 test cases) ---
    def test_schema_has_file_key(self, detector):
        parser_output = _make_parser_output([_http_block([
            _server_block(
                [_location_block(["/"], [_dir("proxy_pass", ["http://backend"])])])
        ])])
        findings = detector.scan(parser_output)
        assert len(findings) >= 1
        assert "file" in findings[0]

    def test_schema_remediations_has_action_directive_context(self, detector):
        parser_output = _make_parser_output([_http_block([
            _server_block(
                [_location_block(["/"], [_dir("proxy_pass", ["http://backend"])])])
        ])])
        findings = detector.scan(parser_output)
        assert len(findings) >= 1
        remediation = findings[0]["remediations"][0]
        assert "action" in remediation
        assert "directive" in remediation
        assert "context" in remediation

    def test_schema_remediation_target_proxy_set_header(self, detector):
        parser_output = _make_parser_output([_http_block([
            _server_block(
                [_location_block(["/"], [_dir("proxy_pass", ["http://backend"])])])
        ])])
        findings = detector.scan(parser_output)
        assert len(findings) >= 1
        remediation = findings[0]["remediations"][0]
        assert remediation["action"] in ["add", "insert"]
        assert remediation["directive"] == "proxy_set_header"
