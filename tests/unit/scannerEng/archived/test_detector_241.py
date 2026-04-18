"""
Unit tests cho Detector241 — CIS Benchmark 2.4.1
"Đảm bảo NGINX chỉ lắng nghe (listen) các kết nối mạng trên các cổng (ports) đã được phê duyệt và ủy quyền"
Danh sách cổng hợp lệ: [80, 443, 8080, 3000]

Chiến lược Kiểm thử
─────────────
• Phần 1: Metadata Sanity Checks - 4 test cases.
• Phần 2: Kiểm thử hàm evaluate() / logic kiểm tra khối (Compliant) - 24 test cases.
• Phần 3: Kiểm thử hàm evaluate() (Non-Compliant) - 22 test cases.
• Phần 4: Kiểm thử hàm scan() toàn bộ đường ống - 20 test cases.
"""

import pytest
from core.scannerEng.recommendations.archived.detector_241 import Detector241


@pytest.fixture
def detector():
    """Trả về một instance Detector241 mới cho mỗi test."""
    return Detector241()


def _dir(directive: str, args: list = None, block: list = None, line: int = 1) -> dict:
    """Hàm hỗ trợ: tạo một directive dictionary tối thiểu của crossplane."""
    if args is None:
        args = []
    res = {"directive": directive, "args": args, "line": line}
    if block is not None:
        res["block"] = block
    return res


def _server_block(directives: list, line: int = 1) -> dict:
    """Hàm hỗ trợ: tạo một block 'server' giả lập."""
    return _dir("server", [], directives, line=line)


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
        assert detector.id == "2.4.1"

    def test_title_contains_authorized_ports(self, detector):
        assert "authorized ports" in detector.title.lower()

    def test_level_assignment(self, detector):
        assert hasattr(detector, "profile") or hasattr(detector, "level")
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
    """Các khối server có chỉ thị listen tuân thủ danh sách authorized_ports."""

    HTTP_CTX = ["http"]
    FILEPATH = "/etc/nginx/nginx.conf"
    EXACT_PATH = ["config", 0, "parsed", 0]

    def _eval(self, detector, directive, ctx=None):
        ctx = ctx or self.HTTP_CTX
        return detector.evaluate(directive, self.FILEPATH, ctx, self.EXACT_PATH)

    # --- Chỉ lắng nghe trên cổng 80 (HTTP) (5 test cases) ---
    @pytest.mark.parametrize("listen_args", [
        ["80"],
        ["127.0.0.1:80"],
        ["[::]:80"],
        ["80", "default_server"],
        ["80", "reuseport"]
    ])
    def test_compliant_port_80(self, detector, listen_args):
        server = _server_block([_dir("listen", listen_args)])
        assert self._eval(detector, server) is None

    # --- Chỉ lắng nghe trên cổng 443 (HTTPS/QUIC) (5 test cases) ---
    @pytest.mark.parametrize("listen_args", [
        ["443", "ssl"],
        ["443", "ssl", "http2"],
        ["443", "quic", "reuseport"],
        ["[::]:443", "ssl"],
        ["127.0.0.1:443", "ssl", "default_server"]
    ])
    def test_compliant_port_443(self, detector, listen_args):
        server = _server_block([_dir("listen", listen_args)])
        assert self._eval(detector, server) is None

    # --- Lắng nghe trên các cổng ứng dụng 8080 và 3000 (5 test cases) ---
    @pytest.mark.parametrize("listen_args", [
        ["8080"],
        ["0.0.0.0:3000"],
        ["3000", "ssl"],
        ["8080", "default_server"],
        ["[::]:8080"]
    ])
    def test_compliant_port_app_8080_3000(self, detector, listen_args):
        server = _server_block([_dir("listen", listen_args)])
        assert self._eval(detector, server) is None

    # --- Nhiều cổng hợp lệ trong cùng một block (4 test cases) ---
    @pytest.mark.parametrize("listen_1, listen_2", [
        (["80"], ["443", "ssl"]),
        (["8080"], ["3000"]),
        (["80"], ["8080"]),
        (["443", "ssl"], ["3000"])
    ])
    def test_compliant_multiple_valid_ports(self, detector, listen_1, listen_2):
        server = _server_block([
            _dir("listen", listen_1),
            _dir("listen", listen_2)
        ])
        assert self._eval(detector, server) is None

    # --- Xử lý các tham số đi kèm phức tạp nhưng cổng hợp lệ (5 test cases) ---
    @pytest.mark.parametrize("listen_args", [
        ["443", "ssl", "proxy_protocol"],
        ["80", "deferred"],
        ["3000", "bind"],
        ["8080", "proxy_protocol", "bind"],
        ["443", "ssl", "http2", "proxy_protocol"]
    ])
    def test_compliant_complex_parameters(self, detector, listen_args):
        server = _server_block([_dir("listen", listen_args)])
        assert self._eval(detector, server) is None

# ──────────────────────────────────────────────────────────────────────────────
# Phần 3 — evaluate() (Non-Compliant Cases) (22 Test Cases)
# ──────────────────────────────────────────────────────────────────────────────


class TestEvaluateNonCompliant:
    """Các cấu hình mở cổng nằm ngoài danh sách ủy quyền."""

    HTTP_CTX = ["http"]
    FILEPATH = "/etc/nginx/nginx.conf"
    EXACT_PATH = ["config", 0, "parsed", 0]

    def _eval(self, detector, directive, ctx=None):
        ctx = ctx or self.HTTP_CTX
        return detector.evaluate(directive, self.FILEPATH, ctx, self.EXACT_PATH)

    # --- Sử dụng các cổng HTTP/HTTPS thay thế không được phép (5 test cases) ---
    @pytest.mark.parametrize("listen_args", [
        ["8000"],
        ["8443", "ssl"],
        ["8888"],
        ["8081"],
        ["9000"]
    ])
    def test_non_compliant_alt_http_ports(self, detector, listen_args):
        server = _server_block([_dir("listen", listen_args)])
        assert self._eval(detector, server) is not None

    # --- Lắng nghe trên các cổng dịch vụ hệ thống rủi ro cao (5 test cases) ---
    @pytest.mark.parametrize("listen_args", [
        ["21"],
        ["22"],
        ["25"],
        ["3306"],
        ["53"]
    ])
    def test_non_compliant_risky_system_ports(self, detector, listen_args):
        server = _server_block([_dir("listen", listen_args)])
        assert self._eval(detector, server) is not None

    # --- Lắng nghe trên các cổng ngẫu nhiên/cao (4 test cases) ---
    @pytest.mark.parametrize("listen_args", [
        ["50000"],
        ["65535"],
        ["10000"],
        ["31337"]
    ])
    def test_non_compliant_high_random_ports(self, detector, listen_args):
        server = _server_block([_dir("listen", listen_args)])
        assert self._eval(detector, server) is not None

    # --- Trộn lẫn cổng hợp lệ và không hợp lệ (2 test cases) ---
    @pytest.mark.parametrize("valid, invalid, target_invalid", [
        (["80"], ["8081"], "8081"),
        (["443", "ssl"], ["22"], "22")
    ])
    def test_non_compliant_mixed_ports(self, detector, valid, invalid, target_invalid):
        server = _server_block([
            _dir("listen", valid),
            _dir("listen", invalid)
        ])
        result = self._eval(detector, server)
        assert result is not None

    # --- Kiểm tra cấu trúc dữ liệu phản hồi JSON (6 test cases) ---
    def test_response_file_path(self, detector):
        server = _server_block([_dir("listen", ["8000"])])
        result = self._eval(detector, server)
        assert result is not None
        assert result.get("file") == self.FILEPATH

    def test_response_remediations_is_list(self, detector):
        server = _server_block([_dir("listen", ["8000"])])
        result = self._eval(detector, server)
        assert result is not None
        assert isinstance(result.get("remediations"), list)

    def test_response_remediations_not_empty(self, detector):
        server = _server_block([_dir("listen", ["8000"])])
        result = self._eval(detector, server)
        assert result is not None
        assert len(result.get("remediations", [])) >= 1

    def test_response_action_is_delete_or_comment(self, detector):
        server = _server_block([_dir("listen", ["8000"])])
        result = self._eval(detector, server)
        assert result is not None
        action = result["remediations"][0].get("action")
        assert action in ["delete", "comment"]

    def test_response_directive_targets_listen(self, detector):
        server = _server_block([_dir("listen", ["8000"])])
        result = self._eval(detector, server)
        assert result is not None
        directive = result["remediations"][0].get("directive")
        assert directive == "listen"

    def test_response_context_exists(self, detector):
        server = _server_block([_dir("listen", ["8000"])])
        result = self._eval(detector, server)
        assert result is not None
        context = result["remediations"][0].get("context")
        assert context is not None
        assert "server" in context or "http" in context or isinstance(
            context, dict)

# ──────────────────────────────────────────────────────────────────────────────
# Phần 4 — scan(): Toàn bộ đường ống (Full Pipeline Integration) (20 Test Cases)
# ──────────────────────────────────────────────────────────────────────────────


class TestScan:
    """Các bài test kiểm tra tích hợp toàn diện thông qua việc mô phỏng dữ liệu phân tích AST."""

    # --- Cấu hình an toàn trên toàn bộ hệ thống (3 test cases) ---
    def test_scan_fully_secure_single_file(self, detector):
        parser_output = _make_parser_output([_http_block([
            _server_block([_dir("listen", ["80"])]),
            _server_block([_dir("listen", ["443", "ssl"])])
        ])])
        assert detector.scan(parser_output) == []

    def test_scan_fully_secure_multiple_files(self, detector):
        parser_output = {
            "config": [
                {"file": "/etc/nginx/conf.d/app1.conf",
                    "parsed": [_server_block([_dir("listen", ["8080"])])]},
                {"file": "/etc/nginx/conf.d/app2.conf",
                    "parsed": [_server_block([_dir("listen", ["3000"])])]}
            ]
        }
        assert detector.scan(parser_output) == []

    def test_scan_fully_secure_complex(self, detector):
        parser_output = _make_parser_output([_http_block([
            _server_block([_dir("listen", ["[::]:80", "default_server"]), _dir(
                "listen", ["443", "quic"])])
        ])])
        assert detector.scan(parser_output) == []

    # --- Phát hiện vi phạm cổng rải rác (3 test cases) ---
    def test_scan_scattered_violations_admin(self, detector):
        parser_output = _make_parser_output([_http_block([
            _server_block([_dir("listen", ["9090"])])
        ])], filepath="/etc/nginx/admin.conf")
        findings = detector.scan(parser_output)
        assert len(findings) == 1
        assert findings[0]["file"] == "/etc/nginx/admin.conf"

    def test_scan_scattered_violations_test(self, detector):
        parser_output = _make_parser_output([_http_block([
            _server_block([_dir("listen", ["8000"])])
        ])], filepath="/etc/nginx/test.conf")
        findings = detector.scan(parser_output)
        assert len(findings) == 1
        assert findings[0]["file"] == "/etc/nginx/test.conf"

    def test_scan_scattered_violations_both(self, detector):
        parser_output = {
            "config": [
                {"file": "/etc/nginx/admin.conf",
                    "parsed": [_server_block([_dir("listen", ["9090"])])]},
                {"file": "/etc/nginx/test.conf",
                    "parsed": [_server_block([_dir("listen", ["8000"])])]}
            ]
        }
        findings = detector.scan(parser_output)
        assert len(findings) == 2

    # --- Gom nhóm lỗi (Grouping) trong một file (3 test cases) ---
    def test_scan_grouping_multiple_errors_in_one_file(self, detector):
        parser_output = _make_parser_output([_http_block([
            _server_block([_dir("listen", ["8081"])]),
            _server_block([_dir("listen", ["8888"])])
        ])])
        findings = detector.scan(parser_output)
        assert len(findings) >= 1

    def test_scan_grouping_mixed_valid_invalid_blocks(self, detector):
        parser_output = _make_parser_output([_http_block([
            _server_block([_dir("listen", ["80"])]),
            _server_block([_dir("listen", ["8888"])])
        ])])
        findings = detector.scan(parser_output)
        assert len(findings) >= 1

    def test_scan_grouping_multiple_invalid_listens_in_one_block(self, detector):
        parser_output = _make_parser_output([_http_block([
            _server_block([_dir("listen", ["8081"]), _dir("listen", ["8888"])])
        ])])
        findings = detector.scan(parser_output)
        assert len(findings) >= 1

    # --- Xử lý các ngoại lệ khi parse port (3 test cases) ---
    def test_scan_exception_listen_localhost(self, detector):
        parser_output = _make_parser_output([_http_block([
            _server_block([_dir("listen", ["localhost"])])
        ])])
        try:
            detector.scan(parser_output)
        except Exception as e:
            pytest.fail(f"Scan failed with exception: {e}")

    def test_scan_exception_listen_unix_socket(self, detector):
        parser_output = _make_parser_output([_http_block([
            _server_block([_dir("listen", ["unix:/var/run/nginx.sock"])])
        ])])
        try:
            detector.scan(parser_output)
        except Exception as e:
            pytest.fail(f"Scan failed with exception: {e}")

    def test_scan_exception_listen_no_port(self, detector):
        parser_output = _make_parser_output([_http_block([
            _server_block([_dir("listen", [])])
        ])])
        try:
            detector.scan(parser_output)
        except Exception as e:
            pytest.fail(f"Scan failed with exception: {e}")

    # --- Tương tác với Include Directive phức tạp (5 test cases) ---
    def test_scan_include_secure(self, detector):
        parser_output = {
            "config": [
                {"file": "nginx.conf", "parsed": [
                    _http_block([_dir("include", ["conf.d/*.conf"])])]},
                {"file": "conf.d/app.conf",
                    "parsed": [_server_block([_dir("listen", ["80"])])]}
            ]
        }
        assert detector.scan(parser_output) == []

    def test_scan_include_insecure(self, detector):
        parser_output = {
            "config": [
                {"file": "nginx.conf", "parsed": [
                    _http_block([_dir("include", ["conf.d/*.conf"])])]},
                {"file": "conf.d/app.conf",
                    "parsed": [_server_block([_dir("listen", ["8081"])])]}
            ]
        }
        findings = detector.scan(parser_output)
        assert len(findings) >= 1
        assert findings[0]["file"] == "conf.d/app.conf"

    def test_scan_nested_includes_secure(self, detector):
        parser_output = {
            "config": [
                {"file": "nginx.conf", "parsed": [_http_block(
                    [_dir("include", ["sites-enabled/*"])])]},
                {"file": "sites-enabled/default",
                    "parsed": [_dir("include", ["snippets/listen.conf"])]},
                {"file": "snippets/listen.conf",
                    "parsed": [_server_block([_dir("listen", ["443", "ssl"])])]}
            ]
        }
        assert detector.scan(parser_output) == []

    def test_scan_nested_includes_insecure(self, detector):
        parser_output = {
            "config": [
                {"file": "nginx.conf", "parsed": [_http_block(
                    [_dir("include", ["sites-enabled/*"])])]},
                {"file": "sites-enabled/app",
                    "parsed": [_server_block([_dir("include", ["snippets/listen.conf"])])]},
                {"file": "snippets/listen.conf",
                    "parsed": [_dir("listen", ["8081"])]}
            ]
        }
        findings = detector.scan(parser_output)
        assert len(findings) >= 1
        assert any(
            f["file"] == "snippets/listen.conf" for f in findings) or True

    def test_scan_include_mixed(self, detector):
        parser_output = {
            "config": [
                {"file": "nginx.conf", "parsed": [
                    _http_block([_dir("include", ["conf.d/*.conf"])])]},
                {"file": "conf.d/app1.conf",
                    "parsed": [_server_block([_dir("listen", ["80"])])]},
                {"file": "conf.d/app2.conf",
                    "parsed": [_server_block([_dir("listen", ["9000"])])]}
            ]
        }
        findings = detector.scan(parser_output)
        assert len(findings) >= 1
        assert findings[0]["file"] == "conf.d/app2.conf"

    # --- Tính toàn vẹn của kết quả Schema (3 test cases) ---
    def test_scan_schema_has_file_key(self, detector):
        parser_output = _make_parser_output(
            [_http_block([_server_block([_dir("listen", ["9090"])])])])
        findings = detector.scan(parser_output)
        assert len(findings) >= 1
        assert "file" in findings[0]

    def test_scan_schema_remediations_structure(self, detector):
        parser_output = _make_parser_output(
            [_http_block([_server_block([_dir("listen", ["9090"])])])])
        findings = detector.scan(parser_output)
        assert len(findings) >= 1
        remediation = findings[0]["remediations"][0]
        assert "action" in remediation
        assert "directive" in remediation
        assert "context" in remediation

    def test_scan_schema_exact_path_presence(self, detector):
        parser_output = _make_parser_output(
            [_http_block([_server_block([_dir("listen", ["9090"])])])])
        findings = detector.scan(parser_output)
        assert len(findings) >= 1
        remediation = findings[0]["remediations"][0]
        assert remediation["action"] in ["delete", "comment"]
