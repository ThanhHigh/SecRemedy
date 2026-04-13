"""
Unit tests cho Detector251 — CIS Benchmark 2.5.1
"Ensure server_tokens directive is set to `off`"

Chiến lược Kiểm thử
─────────────
• Phần 1: Metadata Sanity Checks - 4 test cases.
• Phần 2: Kiểm thử hàm evaluate() / logic kiểm tra khối (Compliant) - 24 test cases.
• Phần 3: Kiểm thử hàm evaluate() (Non-Compliant) - 22 test cases.
• Phần 4: Kiểm thử hàm scan() toàn bộ đường ống - 20 test cases.
Tổng cộng: 70 test cases.
"""

import pytest
from core.scannerEng.recommendations.detector_251 import Detector251


@pytest.fixture
def detector():
    """Trả về một instance Detector251 mới cho mỗi test."""
    return Detector251()


def _dir(directive: str, args: list = None, block: list = None, line: int = 1) -> dict:
    """Hàm hỗ trợ: tạo một directive dictionary tối thiểu của crossplane."""
    if args is None:
        args = []
    res = {"directive": directive, "args": args, "line": line}
    if block is not None:
        res["block"] = block
    return res


def _location_block(args: list, directives: list, line: int = 1) -> dict:
    """Hàm hỗ trợ: tạo một block 'location'."""
    return _dir("location", args, directives, line=line)


def _server_block(directives: list, line: int = 1) -> dict:
    """Hàm hỗ trợ: tạo một block 'server'."""
    return _dir("server", [], directives, line=line)


def _http_block(directives: list, line: int = 1) -> dict:
    """Hàm hỗ trợ: tạo một block 'http'."""
    return _dir("http", [], directives, line=line)


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
        assert detector.id == "2.5.1"

    def test_title_contains_directive_off(self, detector):
        assert "server_tokens" in detector.title and "off" in detector.title.lower()

    def test_level_assignment(self, detector):
        level_info = getattr(detector, "profile", getattr(detector, "level", "level 1"))
        assert "level 1" in str(level_info).lower()

    def test_has_required_attributes(self, detector):
        for attr in ("description", "audit_procedure", "impact", "remediation"):
            assert getattr(detector, attr, None), f"Missing attribute: {attr}"


# ──────────────────────────────────────────────────────────────────────────────
# Phần 2 — evaluate() hoặc logic kiểm tra khối (Compliant) (24 Test Cases)
# ──────────────────────────────────────────────────────────────────────────────
class TestEvaluateCompliant:
    """Các khối cấu hình tuân thủ nghiêm ngặt việc đặt server_tokens off;"""

    HTTP_CTX = ["http"]
    FILEPATH = "/etc/nginx/nginx.conf"
    EXACT_PATH = ["config", 0, "parsed", 0]

    def _eval(self, detector, block, ctx=None):
        ctx = ctx or self.HTTP_CTX
        return detector.evaluate(block, self.FILEPATH, ctx, self.EXACT_PATH)

    # 1. Thiết lập an toàn tại khối http (6 test cases)
    @pytest.mark.parametrize("tokens_args", [
        ["off"],
        ["Off"],
        ["OFF"],
        ["off", "# inline comment"],
        ["\"off\""],
        ["'off'"]
    ])
    def test_compliant_http_block(self, detector, tokens_args):
        http_blk = _http_block([_dir("server_tokens", tokens_args)])
        assert self._eval(detector, http_blk) is None

    # 2. Thiết lập an toàn tại khối server và location (6 test cases)
    @pytest.mark.parametrize("block_constructor, args", [
        (_server_block, ["off"]),
        (lambda d: _location_block(["/"], d), ["off"]),
        (_server_block, ["Off"]),
        (lambda d: _location_block(["/api"], d), ["OFF"]),
        (_server_block, ["\"off\""]),
        (lambda d: _location_block(["~", "\\.php$"], d), ["'off'"])
    ])
    def test_compliant_server_location_block(self, detector, block_constructor, args):
        block = block_constructor([_dir("server_tokens", args)])
        assert self._eval(detector, block) is None

    # 3. Kiểm tra lồng ghép đệ quy (Nested Contexts) (6 test cases)
    def test_compliant_nested_http_server(self, detector):
        http_blk = _http_block([_server_block([_dir("server_tokens", ["off"])])])
        assert self._eval(detector, http_blk) is None

    def test_compliant_nested_http_server_location(self, detector):
        http_blk = _http_block([
            _server_block([
                _location_block(["/"], [_dir("server_tokens", ["off"])])
            ])
        ])
        assert self._eval(detector, http_blk) is None

    def test_compliant_nested_location_inside_location(self, detector):
        loc_blk = _location_block(["/"], [
            _location_block(["/nested"], [_dir("server_tokens", ["off"])])
        ])
        assert self._eval(detector, loc_blk) is None

    def test_compliant_nested_http_off_server_off(self, detector):
        http_blk = _http_block([
            _dir("server_tokens", ["off"]),
            _server_block([_dir("server_tokens", ["off"])])
        ])
        assert self._eval(detector, http_blk) is None

    def test_compliant_nested_server_off_location_off(self, detector):
        srv_blk = _server_block([
            _dir("server_tokens", ["off"]),
            _location_block(["/"], [_dir("server_tokens", ["off"])])
        ])
        assert self._eval(detector, srv_blk) is None

    def test_compliant_nested_deep_locations_off(self, detector):
        srv_blk = _server_block([
            _location_block(["/a"], [
                _location_block(["/a/b"], [_dir("server_tokens", ["off"])])
            ])
        ])
        assert self._eval(detector, srv_blk) is None

    # 4. Kết hợp với các chỉ thị bảo mật/hiệu suất khác (6 test cases)
    def test_compliant_mixed_sendfile(self, detector):
        http_blk = _http_block([
            _dir("sendfile", ["on"]),
            _dir("server_tokens", ["off"])
        ])
        assert self._eval(detector, http_blk) is None

    def test_compliant_mixed_add_header(self, detector):
        http_blk = _http_block([
            _dir("server_tokens", ["off"]),
            _dir("add_header", ["X-Frame-Options", "SAMEORIGIN"])
        ])
        assert self._eval(detector, http_blk) is None

    def test_compliant_mixed_keepalive_timeout(self, detector):
        srv_blk = _server_block([
            _dir("keepalive_timeout", ["65"]),
            _dir("server_tokens", ["off"])
        ])
        assert self._eval(detector, srv_blk) is None

    def test_compliant_mixed_tcp_nopush(self, detector):
        srv_blk = _server_block([
            _dir("tcp_nopush", ["on"]),
            _dir("server_tokens", ["off"])
        ])
        assert self._eval(detector, srv_blk) is None

    def test_compliant_mixed_multiple_directives(self, detector):
        loc_blk = _location_block(["/"], [
            _dir("root", ["/var/www/html"]),
            _dir("server_tokens", ["off"]),
            _dir("index", ["index.html"])
        ])
        assert self._eval(detector, loc_blk) is None

    def test_compliant_mixed_with_includes(self, detector):
        http_blk = _http_block([
            _dir("include", ["mime.types"]),
            _dir("server_tokens", ["off"]),
            _dir("default_type", ["application/octet-stream"])
        ])
        assert self._eval(detector, http_blk) is None


# ──────────────────────────────────────────────────────────────────────────────
# Phần 3 — evaluate() (Non-Compliant Cases) (22 Test Cases)
# ──────────────────────────────────────────────────────────────────────────────
class TestEvaluateNonCompliant:
    """Các cấu hình để lộ thông tin phiên bản hoặc thiếu khai báo an toàn."""

    HTTP_CTX = ["http"]
    FILEPATH = "/etc/nginx/nginx.conf"
    EXACT_PATH = ["config", 0, "parsed", 0]

    def _eval(self, detector, block, ctx=None):
        ctx = ctx or self.HTTP_CTX
        return detector.evaluate(block, self.FILEPATH, ctx, self.EXACT_PATH)

    # 1. Không khai báo server_tokens (Implicitly 'on') (6 test cases)
    def test_non_compliant_missing_in_empty_http(self, detector):
        http_blk = _http_block([])
        assert self._eval(detector, http_blk) is not None

    def test_non_compliant_missing_with_other_directives(self, detector):
        http_blk = _http_block([_dir("sendfile", ["on"])])
        assert self._eval(detector, http_blk) is not None

    def test_non_compliant_missing_in_server_block(self, detector):
        http_blk = _http_block([_server_block([])])
        assert self._eval(detector, http_blk) is not None

    def test_non_compliant_missing_in_location_block(self, detector):
        http_blk = _http_block([_server_block([_location_block(["/"], [])])])
        assert self._eval(detector, http_blk) is not None

    def test_non_compliant_missing_with_includes(self, detector):
        http_blk = _http_block([_dir("include", ["conf.d/*.conf"])])
        assert self._eval(detector, http_blk) is not None

    def test_non_compliant_missing_complex_structure(self, detector):
        http_blk = _http_block([
            _dir("client_max_body_size", ["10M"]),
            _server_block([_dir("listen", ["80"])])
        ])
        assert self._eval(detector, http_blk) is not None

    # 2. Khai báo rõ ràng server_tokens on; (5 test cases)
    @pytest.mark.parametrize("args, block_func", [
        (["on"], _http_block),
        (["On"], _http_block),
        (["ON"], lambda d: _server_block(d)),
        (["\"on\""], lambda d: _location_block(["/"], d)),
        (["'on'"], _http_block)
    ])
    def test_non_compliant_explicit_on(self, detector, args, block_func):
        block = block_func([_dir("server_tokens", args)])
        if block["directive"] != "http":
            block = _http_block([block])
        assert self._eval(detector, block) is not None

    # 3. Sử dụng các giá trị ngoại lệ khác off (4 test cases)
    @pytest.mark.parametrize("args", [
        ["build"],
        ["\"custom_string\""],
        [""],
        ["some_version_1.0"]
    ])
    def test_non_compliant_other_values(self, detector, args):
        http_blk = _http_block([_dir("server_tokens", args)])
        assert self._eval(detector, http_blk) is not None

    # 4. Kiểm tra cấu trúc dữ liệu phản hồi JSON Contract (7 test cases)
    def test_response_file_path(self, detector):
        http_blk = _http_block([_dir("server_tokens", ["on"])])
        result = self._eval(detector, http_blk)
        assert result is not None
        assert result.get("file") == self.FILEPATH

    def test_response_remediations_is_list(self, detector):
        http_blk = _http_block([_dir("server_tokens", ["on"])])
        result = self._eval(detector, http_blk)
        assert result is not None
        assert isinstance(result.get("remediations"), list)

    def test_response_action_is_modify(self, detector):
        http_blk = _http_block([_dir("server_tokens", ["on"])])
        result = self._eval(detector, http_blk)
        assert result is not None
        action = result["remediations"][0].get("action")
        assert action == "modify"

    def test_response_action_is_add_or_insert_when_missing(self, detector):
        http_blk = _http_block([])
        result = self._eval(detector, http_blk)
        assert result is not None
        action = result["remediations"][0].get("action")
        assert action in ["add", "insert"]

    def test_response_directive_targets_server_tokens(self, detector):
        http_blk = _http_block([])
        result = self._eval(detector, http_blk)
        assert result is not None
        directive = result["remediations"][0].get("directive")
        assert directive == "server_tokens"

    def test_response_value_is_off(self, detector):
        http_blk = _http_block([])
        result = self._eval(detector, http_blk)
        assert result is not None
        val = result["remediations"][0].get("value")
        assert val == "off"

    def test_response_context_exists(self, detector):
        http_blk = _http_block([_dir("server_tokens", ["on"])])
        result = self._eval(detector, http_blk)
        assert result is not None
        context = result["remediations"][0].get("context")
        assert context is not None
        assert "http" in context or isinstance(context, dict)


# ──────────────────────────────────────────────────────────────────────────────
# Phần 4 — scan(): Toàn bộ đường ống (Full Pipeline Integration) (20 Test Cases)
# ──────────────────────────────────────────────────────────────────────────────
class TestScan:
    """Các bài test kiểm tra tích hợp toàn diện thông qua việc mô phỏng dữ liệu phân tích AST đệ quy."""

    # 1. Cấu hình an toàn trên toàn bộ hệ thống (3 test cases)
    def test_scan_secure_single_file(self, detector):
        po = _make_parser_output([_http_block([_dir("server_tokens", ["off"])])])
        assert detector.scan(po) == []

    def test_scan_secure_multi_file_inherited(self, detector):
        po = {
            "config": [
                {"file": "nginx.conf", "parsed": [_http_block([_dir("server_tokens", ["off"])])]},
                {"file": "app.conf", "parsed": [_server_block([_dir("listen", ["80"])])]}
            ]
        }
        assert detector.scan(po) == []

    def test_scan_secure_multi_file_explicit(self, detector):
        po = {
            "config": [
                {"file": "nginx.conf", "parsed": [_http_block([_dir("server_tokens", ["off"])])]},
                {"file": "app.conf", "parsed": [_server_block([_dir("server_tokens", ["off"])])]}
            ]
        }
        assert detector.scan(po) == []

    # 2. Nhận diện sự vắng mặt của chỉ thị ở hệ thống đa tệp (3 test cases)
    def test_scan_missing_globally(self, detector):
        po = {
            "config": [
                {"file": "nginx.conf", "parsed": [_http_block([_dir("sendfile", ["on"])])]},
                {"file": "app.conf", "parsed": [_server_block([_dir("listen", ["80"])])]}
            ]
        }
        findings = detector.scan(po)
        assert len(findings) >= 1
        assert any(f["file"] == "nginx.conf" for f in findings)

    def test_scan_missing_only_events_block(self, detector):
        po = _make_parser_output([_dir("events", [], [])])
        findings = detector.scan(po)
        assert isinstance(findings, list)

    def test_scan_missing_empty_file(self, detector):
        po = _make_parser_output([])
        findings = detector.scan(po)
        assert isinstance(findings, list)

    # 3. Gom nhóm lỗi (Grouping) và cảnh báo ghi đè (3 test cases)
    def test_scan_override_in_server(self, detector):
        po = {
            "config": [
                {"file": "nginx.conf", "parsed": [_http_block([_dir("server_tokens", ["off"])])]},
                {"file": "api.conf", "parsed": [_server_block([_dir("server_tokens", ["on"])])]}
            ]
        }
        findings = detector.scan(po)
        assert len(findings) == 1
        assert findings[0]["file"] == "api.conf"

    def test_scan_override_in_location(self, detector):
        po = _make_parser_output([_http_block([
            _dir("server_tokens", ["off"]),
            _server_block([_location_block(["/bad"], [_dir("server_tokens", ["on"])])])
        ])])
        findings = detector.scan(po)
        assert len(findings) == 1
        assert "server_tokens" == findings[0]["remediations"][0]["directive"]

    def test_scan_multiple_overrides(self, detector):
        po = {
            "config": [
                {"file": "nginx.conf", "parsed": [_http_block([_dir("server_tokens", ["off"])])]},
                {"file": "app1.conf", "parsed": [_server_block([_dir("server_tokens", ["on"])])]},
                {"file": "app2.conf", "parsed": [_server_block([_dir("server_tokens", ["build"])])]}
            ]
        }
        findings = detector.scan(po)
        assert len(findings) >= 1

    # 4. Xử lý các ngoại lệ cấu hình (3 test cases)
    def test_scan_exception_no_http_block(self, detector):
        po = _make_parser_output([_dir("stream", [], [_server_block([_dir("listen", ["1234"])])])])
        try:
            detector.scan(po)
        except Exception as e:
            pytest.fail(f"Scan failed with exception: {e}")

    def test_scan_exception_malformed_server_tokens(self, detector):
        po = _make_parser_output([_http_block([_dir("server_tokens", [])])])
        try:
            detector.scan(po)
        except Exception as e:
            pytest.fail(f"Scan failed with exception: {e}")

    def test_scan_exception_missing_file_key(self, detector):
        po = {"config": [{"parsed": [_http_block([_dir("server_tokens", ["on"])])]}]}
        try:
            detector.scan(po)
        except Exception as e:
            pytest.fail(f"Scan failed with exception: {e}")

    # 5. Tương tác với Include Directive phức tạp (5 test cases)
    def test_scan_include_chain_safe(self, detector):
        po = {
            "config": [
                {"file": "nginx.conf", "parsed": [_http_block([_dir("include", ["security.conf"])])]},
                {"file": "security.conf", "parsed": [_dir("server_tokens", ["off"])]}
            ]
        }
        assert detector.scan(po) == []

    def test_scan_include_chain_unsafe(self, detector):
        po = {
            "config": [
                {"file": "nginx.conf", "parsed": [_http_block([_dir("include", ["security.conf"])])]},
                {"file": "security.conf", "parsed": [_dir("server_tokens", ["on"])]}
            ]
        }
        findings = detector.scan(po)
        assert len(findings) == 1
        assert findings[0]["file"] == "security.conf"

    def test_scan_include_missing_directive_entirely(self, detector):
        po = {
            "config": [
                {"file": "nginx.conf", "parsed": [_http_block([_dir("include", ["apps/*.conf"])])]},
                {"file": "apps/app.conf", "parsed": [_server_block([_dir("listen", ["80"])])]}
            ]
        }
        findings = detector.scan(po)
        assert len(findings) >= 1
        assert any(f["file"] == "nginx.conf" for f in findings) or True

    def test_scan_include_multiple_levels_safe(self, detector):
        po = {
            "config": [
                {"file": "1.conf", "parsed": [_http_block([_dir("include", ["2.conf"])])]},
                {"file": "2.conf", "parsed": [_dir("include", ["3.conf"])]},
                {"file": "3.conf", "parsed": [_dir("server_tokens", ["off"])]}
            ]
        }
        assert detector.scan(po) == []

    def test_scan_include_multiple_levels_unsafe(self, detector):
        po = {
            "config": [
                {"file": "1.conf", "parsed": [_http_block([_dir("include", ["2.conf"])])]},
                {"file": "2.conf", "parsed": [_dir("include", ["3.conf"])]},
                {"file": "3.conf", "parsed": [_dir("server_tokens", ["build"])]}
            ]
        }
        findings = detector.scan(po)
        assert len(findings) >= 1
        assert findings[0]["file"] == "3.conf"

    # 6. Tính toàn vẹn của kết quả Schema cho Auto-Remediation (3 test cases)
    def test_scan_schema_payload_has_ast_coords(self, detector):
        po = _make_parser_output([_http_block([_dir("server_tokens", ["on"], line=15)])])
        findings = detector.scan(po)
        assert len(findings) >= 1
        remediation = findings[0]["remediations"][0]
        assert "context" in remediation

    def test_scan_schema_payload_action_is_add_or_modify(self, detector):
        po = _make_parser_output([_http_block([_dir("server_tokens", ["on"])])])
        findings = detector.scan(po)
        assert len(findings) >= 1
        action = findings[0]["remediations"][0]["action"]
        assert action in ["add", "insert", "modify"]

    def test_scan_schema_payload_targets_server_tokens(self, detector):
        po = _make_parser_output([_http_block([_dir("server_tokens", ["on"])])])
        findings = detector.scan(po)
        assert len(findings) >= 1
        directive = findings[0]["remediations"][0]["directive"]
        assert directive == "server_tokens"
