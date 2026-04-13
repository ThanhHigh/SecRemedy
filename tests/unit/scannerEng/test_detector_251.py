"""
Unit tests cho Detector251 — CIS Benchmark 2.5.1
"Đảm bảo chỉ thị server_tokens được cấu hình là off để ẩn thông tin phiên bản NGINX"

Chiến lược Kiểm thử
─────────────
• Phần 1: Metadata Sanity Checks - 4 test cases.
• Phần 2: Kiểm thử hàm evaluate() / logic kiểm tra khối (Compliant) - 5 test cases
• Phần 3: Kiểm thử hàm evaluate() (Non-Compliant) - 12 test cases
• Phần 4: Kiểm thử hàm scan() toàn bộ đường ống - 8 test cases
"""

import pytest
from core.scannerEng.recommendations.detector_251 import Detector251


@pytest.fixture
def detector():
    """Trả về một instance Detector251 mới cho mỗi test."""
    return Detector251()


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
    """Hàm hỗ trợ: tạo một block 'http' chứa các directive."""
    return _dir("http", [], directives)


def _location_block(args: list, directives: list) -> dict:
    """Hàm hỗ trợ: tạo một block 'location' giả lập."""
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
# Phần 1 — Kiểm tra tính đúng đắn của Metadata (4 test cases)
# ──────────────────────────────────────────────────────────────────────────────

class TestMetadata:
    def test_id(self, detector):
        assert detector.id == "2.5.1"

    def test_title_contains_server_tokens(self, detector):
        assert "server_tokens" in detector.title.lower()

    def test_level_assignment(self, detector):
        assert hasattr(detector, "profile") or hasattr(detector, "level")
        level_info = getattr(detector, "profile",
                             getattr(detector, "level", ""))
        assert "level 1" in str(level_info).lower()

    def test_has_required_attributes(self, detector):
        for attr in ("description", "audit_procedure", "impact", "remediation"):
            assert getattr(detector, attr, None), f"Missing attribute: {attr}"


# ──────────────────────────────────────────────────────────────────────────────
# Phần 2 — evaluate() hoặc logic kiểm tra: Compliant (5 test cases)
# ──────────────────────────────────────────────────────────────────────────────

class TestEvaluateCompliant:
    """Các cấu hình hợp lệ khi server_tokens được đặt thành off."""

    HTTP_CTX = ["http"]
    FILEPATH = "/etc/nginx/nginx.conf"
    EXACT_PATH = ["config", 0, "parsed", 0]

    def _eval(self, detector, config_block):
        parser_output = _make_parser_output([config_block])
        return detector.scan(parser_output)

    # --- Cấu hình chuẩn trong khối http (1 test case) ---
    def test_http_off_standard(self, detector):
        assert self._eval(detector, _http_block(
            [_dir("server_tokens", ["off"])])) == []

    # --- Cấu hình trong khối server và location (2 test cases) ---
    def test_server_off(self, detector):
        http = _http_block([_server_block([_dir("server_tokens", ["off"])])])
        # Nếu server_tokens off được đặt ở cấp server và không có server nào khác,
        # phụ thuộc vào logic cụ thể của TDD, test này có thể expect pass hoặc expect empty.
        # Ở đây ta giả định là nếu cấu hình an toàn thì mảng lỗi rỗng.
        assert self._eval(detector, http) == []

    def test_location_off(self, detector):
        http = _http_block(
            [_server_block([_location_block(["/"], [_dir("server_tokens", ["off"])])])])
        assert self._eval(detector, http) == []

    # --- Các giá trị kế thừa hợp lệ (2 test cases) ---
    def test_inherit_server_1(self, detector):
        http = _http_block([_dir("server_tokens", ["off"]), _server_block([])])
        assert self._eval(detector, http) == []

    def test_inherit_server_2(self, detector):
        http = _http_block([_dir("server_tokens", ["off"]),
                           _server_block([_location_block(["/"], [])])])
        assert self._eval(detector, http) == []


# ──────────────────────────────────────────────────────────────────────────────
# Phần 3 — evaluate(): Các trường hợp vi phạm (Non-Compliant) (12 test cases)
# ──────────────────────────────────────────────────────────────────────────────

class TestEvaluateNonCompliant:
    FILEPATH = "/etc/nginx/nginx.conf"

    def _scan(self, detector, config_block):
        parser_output = _make_parser_output([config_block])
        return detector.scan(parser_output)

    # --- Không khai báo server_tokens (2 test cases) ---
    def test_missing_http(self, detector):
        http = _http_block([])
        assert len(self._scan(detector, http)) > 0

    def test_missing_completely(self, detector):
        parser_output = _make_parser_output([])
        assert len(detector.scan(parser_output)) > 0

    # --- Cấu hình server_tokens on (3 test cases) ---
    def test_on_in_http(self, detector):
        http = _http_block([_dir("server_tokens", ["on"])])
        assert len(self._scan(detector, http)) > 0

    def test_on_in_server(self, detector):
        http = _http_block([_server_block([_dir("server_tokens", ["on"])])])
        assert len(self._scan(detector, http)) > 0

    def test_on_in_location(self, detector):
        http = _http_block(
            [_server_block([_location_block(["/"], [_dir("server_tokens", ["on"])])])])
        assert len(self._scan(detector, http)) > 0

    # --- Sử dụng giá trị không phải off (2 test cases) ---
    def test_value_build(self, detector):
        http = _http_block([_dir("server_tokens", ["build"])])
        assert len(self._scan(detector, http)) > 0

    def test_value_empty(self, detector):
        http = _http_block([_dir("server_tokens", [""])])
        assert len(self._scan(detector, http)) > 0

    # --- Ghi đè cấu hình không an toàn (1 test case) ---
    def test_off_in_http_on_in_server(self, detector):
        http = _http_block([_dir("server_tokens", ["off"]),
                           _server_block([_dir("server_tokens", ["on"])])])
        assert len(self._scan(detector, http)) > 0

    # --- Kiểm tra cấu trúc dữ liệu phản hồi (4 test cases) ---
    def test_response_file_path(self, detector):
        http = _http_block([_dir("server_tokens", ["on"])])
        result = self._scan(detector, http)
        assert result[0]["file"] == self.FILEPATH

    def test_response_remediations_is_list(self, detector):
        http = _http_block([_dir("server_tokens", ["on"])])
        result = self._scan(detector, http)
        assert isinstance(result[0]["remediations"], list)
        assert len(result[0]["remediations"]) >= 1

    def test_response_action_is_add_or_replace(self, detector):
        http = _http_block([_dir("server_tokens", ["on"])])
        result = self._scan(detector, http)
        action = result[0]["remediations"][0]["action"]
        assert action in ["replace", "add"]

    def test_response_directive_is_server_tokens(self, detector):
        http = _http_block([_dir("server_tokens", ["on"])])
        result = self._scan(detector, http)
        assert result[0]["remediations"][0]["directive"] == "server_tokens"


# ──────────────────────────────────────────────────────────────────────────────
# Phần 4 — scan(): Toàn bộ đường ống (Full Pipeline Integration) (8 test cases)
# ──────────────────────────────────────────────────────────────────────────────

class TestScan:
    # --- Cấu hình an toàn đầy đủ (1 test case) ---
    def test_full_secure_1(self, detector):
        parser_output = _make_parser_output(
            [_http_block([_dir("server_tokens", ["off"])])])
        assert detector.scan(parser_output) == []

    # --- Nhiều file cấu hình có lỗi (2 test cases) ---
    def test_multiple_files_with_violations(self, detector):
        parser_output = {
            "config": [
                {"file": "/etc/nginx/nginx.conf",
                    "parsed": [_http_block([_dir("include", ["conf.d/*.conf"])])]},
                {"file": "/etc/nginx/conf.d/api.conf",
                    "parsed": [_server_block([_dir("server_tokens", ["on"])])]}
            ]
        }
        findings = detector.scan(parser_output)
        assert len(findings) > 0

    def test_valid_in_root_invalid_in_included(self, detector):
        parser_output = {
            "config": [
                {"file": "/etc/nginx/nginx.conf", "parsed": [_http_block(
                    [_dir("server_tokens", ["off"]), _dir("include", ["conf.d/*.conf"])])]},
                {"file": "/etc/nginx/conf.d/invalid.conf",
                    "parsed": [_server_block([_dir("server_tokens", ["on"])])]}
            ]
        }
        findings = detector.scan(parser_output)
        assert len(findings) > 0
        assert findings[0]["file"] == "/etc/nginx/conf.d/invalid.conf"

    # --- Ưu tiên cấu hình khối http (1 test cases) ---
    def test_add_to_http_block(self, detector):
        parser_output = _make_parser_output([_http_block([])])
        findings = detector.scan(parser_output)
        assert findings[0]["remediations"][0]["action"] == "add"

    # --- Chỉ thị bị comment (1 test case) ---
    def test_commented_directive_treated_as_missing(self, detector):
        parser_output = _make_parser_output(
            [_http_block([])])  # Crossplane ignores comments
        findings = detector.scan(parser_output)
        assert len(findings) > 0

    # --- Tính toàn vẹn của kết quả Schema (3 test cases) ---
    def test_schema_file_key(self, detector):
        parser_output = _make_parser_output([_http_block([])])
        findings = detector.scan(parser_output)
        assert "file" in findings[0]

    def test_schema_remediations_array(self, detector):
        parser_output = _make_parser_output([_http_block([])])
        findings = detector.scan(parser_output)
        remediation = findings[0]["remediations"][0]
        assert "action" in remediation
        assert "directive" in remediation
        assert "context" in remediation

    def test_schema_auto_remediation(self, detector):
        parser_output = _make_parser_output([_http_block([])])
        findings = detector.scan(parser_output)
        remediation = findings[0]["remediations"][0]
        assert remediation["action"] in ["add", "replace"]
        assert remediation["directive"] == "server_tokens"
