"""
Unit tests cho Detector241 — CIS Benchmark 2.4.1
"Đảm bảo NGINX chỉ lắng nghe (listen) các kết nối mạng trên các cổng (ports) đã được phê duyệt và ủy quyền"
Danh sách cổng hợp lệ: [80, 443, 8080, 3000]

Chiến lược Kiểm thử
─────────────
• Phần 1: Metadata Sanity Checks - 4 test cases.
• Phần 2: Kiểm thử hàm evaluate() / logic kiểm tra khối Listen (Compliant) - 24 test cases.
• Phần 3: Kiểm thử hàm evaluate() (Non-Compliant) - 20 test cases.
• Phần 4: Kiểm thử hàm scan() toàn bộ đường ống - 15 test cases.
"""

import pytest
from core.scannerEng.recommendations.detector_241 import Detector241


@pytest.fixture
def detector():
    """Trả về một instance Detector241 mới cho mỗi test."""
    return Detector241()


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
        assert detector.id == "2.4.1"

    def test_title_contains_authorized_ports(self, detector):
        assert "authorized ports" in detector.title.lower()

    def test_level_assignment(self, detector):
        # Thông thường được khai báo trong profile hoặc tags
        assert hasattr(detector, "profile") or hasattr(detector, "level")
        level_info = getattr(detector, "profile",
                             getattr(detector, "level", ""))
        assert "level 1" in str(level_info).lower()

    def test_has_required_attributes(self, detector):
        for attr in ("description", "audit_procedure", "impact", "remediation"):
            assert getattr(detector, attr, None), f"Missing attribute: {attr}"


# ──────────────────────────────────────────────────────────────────────────────
# Phần 2 — evaluate() hoặc logic kiểm tra khối Listen: Compliant (24 Test Cases)
# ──────────────────────────────────────────────────────────────────────────────

class TestEvaluateCompliant:
    """Các cấu hình hợp lệ chỉ chứa các cổng nằm trong danh sách được phép [80, 443, 8080, 3000]."""

    HTTP_CTX = ["http"]
    FILEPATH = "/etc/nginx/nginx.conf"
    EXACT_PATH = ["config", 0, "parsed", 0]

    def _eval(self, detector, directive, ctx=None):
        ctx = ctx or self.HTTP_CTX
        return detector.evaluate(directive, self.FILEPATH, ctx, self.EXACT_PATH)

    # --- Cổng chuẩn HTTP (80) và HTTPS (443) (5 test cases) ---
    def test_port_80(self, detector):
        server = _server_block([_dir("listen", ["80"])])
        assert self._eval(detector, _http_block([server])) is None

    def test_port_443_ssl(self, detector):
        server = _server_block([_dir("listen", ["443", "ssl"])])
        assert self._eval(detector, _http_block([server])) is None

    def test_port_80_ipv6(self, detector):
        server = _server_block([_dir("listen", ["[::]:80"])])
        assert self._eval(detector, _http_block([server])) is None

    def test_port_443_ssl_ipv4_local(self, detector):
        server = _server_block([_dir("listen", ["127.0.0.1:443", "ssl"])])
        assert self._eval(detector, _http_block([server])) is None

    def test_port_80_default_server(self, detector):
        server = _server_block([_dir("listen", ["80", "default_server"])])
        assert self._eval(detector, _http_block([server])) is None

    # --- Cổng bổ sung được ủy quyền (8080, 3000) (4 test cases) ---
    def test_port_8080(self, detector):
        server = _server_block([_dir("listen", ["8080"])])
        assert self._eval(detector, _http_block([server])) is None

    def test_port_3000(self, detector):
        server = _server_block([_dir("listen", ["3000"])])
        assert self._eval(detector, _http_block([server])) is None

    def test_port_8080_ipv6(self, detector):
        server = _server_block([_dir("listen", ["[::]:8080"])])
        assert self._eval(detector, _http_block([server])) is None

    def test_port_3000_ipv4_local(self, detector):
        server = _server_block([_dir("listen", ["127.0.0.1:3000"])])
        assert self._eval(detector, _http_block([server])) is None

    # --- Hỗ trợ HTTP/2 và HTTP/3 (QUIC) (5 test cases) ---
    def test_port_443_quic_reuseport(self, detector):
        server = _server_block([_dir("listen", ["443", "quic", "reuseport"])])
        assert self._eval(detector, _http_block([server])) is None

    def test_port_8080_quic(self, detector):
        server = _server_block([_dir("listen", ["8080", "quic"])])
        assert self._eval(detector, _http_block([server])) is None

    def test_port_443_http2(self, detector):
        server = _server_block([_dir("listen", ["443", "http2"])])
        assert self._eval(detector, _http_block([server])) is None

    def test_port_3000_quic(self, detector):
        server = _server_block([_dir("listen", ["3000", "quic"])])
        assert self._eval(detector, _http_block([server])) is None

    def test_port_443_quic_ipv6(self, detector):
        server = _server_block([_dir("listen", ["[::]:443", "quic"])])
        assert self._eval(detector, _http_block([server])) is None

    # --- Cấu hình kết hợp nhiều cổng hợp lệ (4 test cases) ---
    def test_mixed_80_and_443(self, detector):
        server = _server_block(
            [_dir("listen", ["80"]), _dir("listen", ["443", "ssl"])])
        assert self._eval(detector, _http_block([server])) is None

    def test_mixed_8080_and_3000(self, detector):
        server = _server_block(
            [_dir("listen", ["8080"]), _dir("listen", ["3000"])])
        assert self._eval(detector, _http_block([server])) is None

    def test_mixed_all_authorized(self, detector):
        server = _server_block([
            _dir("listen", ["80"]),
            _dir("listen", ["443", "ssl"]),
            _dir("listen", ["8080"]),
            _dir("listen", ["3000"])
        ])
        assert self._eval(detector, _http_block([server])) is None

    def test_mixed_ipv4_and_ipv6_authorized(self, detector):
        server = _server_block([
            _dir("listen", ["80"]),
            _dir("listen", ["[::]:80"])
        ])
        assert self._eval(detector, _http_block([server])) is None

    # --- Nhiều tham số trong listen hợp lệ (4 test cases) ---
    def test_listen_3000_deferred(self, detector):
        server = _server_block([_dir("listen", ["3000", "deferred"])])
        assert self._eval(detector, _http_block([server])) is None

    def test_listen_8080_ipv6only(self, detector):
        server = _server_block([_dir("listen", ["[::]:8080", "ipv6only=on"])])
        assert self._eval(detector, _http_block([server])) is None

    def test_listen_443_backlog(self, detector):
        server = _server_block([_dir("listen", ["443", "ssl", "backlog=512"])])
        assert self._eval(detector, _http_block([server])) is None

    def test_listen_80_proxy_protocol(self, detector):
        server = _server_block([_dir("listen", ["80", "proxy_protocol"])])
        assert self._eval(detector, _http_block([server])) is None

    # --- Các cổng hợp lệ nằm ở file cấu hình khác (2 test cases) ---
    def test_valid_ports_in_included_http_file(self, detector):
        parser_output = {
            "config": [
                {"file": "/etc/nginx/nginx.conf",
                    "parsed": [_http_block([_dir("include", ["conf.d/*.conf"])])]},
                {"file": "/etc/nginx/conf.d/app.conf",
                    "parsed": [_server_block([_dir("listen", ["3000"])])]}
            ]
        }
        assert detector.scan(parser_output) == []

    def test_valid_ports_in_included_https_file(self, detector):
        parser_output = {
            "config": [
                {"file": "/etc/nginx/nginx.conf",
                    "parsed": [_http_block([_dir("include", ["conf.d/*.conf"])])]},
                {"file": "/etc/nginx/conf.d/ssl.conf",
                    "parsed": [_server_block([_dir("listen", ["443", "ssl"])])]}
            ]
        }
        assert detector.scan(parser_output) == []


# ──────────────────────────────────────────────────────────────────────────────
# Phần 3 — evaluate(): Các trường hợp vi phạm (Non-Compliant) (20 Test Cases)
# ──────────────────────────────────────────────────────────────────────────────

class TestEvaluateNonCompliant:
    """Các cấu hình chứa cổng không nằm trong danh sách [80, 443, 8080, 3000]."""

    HTTP_CTX = ["http"]
    FILEPATH = "/etc/nginx/nginx.conf"
    EXACT_PATH = ["config", 0, "parsed", 0]

    def _eval(self, detector, directive, ctx=None):
        ctx = ctx or self.HTTP_CTX
        return detector.evaluate(directive, self.FILEPATH, ctx, self.EXACT_PATH)

    # --- Lắng nghe trên cổng không được phép (5 test cases) ---
    def test_invalid_port_81(self, detector):
        server = _server_block([_dir("listen", ["81"])])
        assert self._eval(detector, _http_block([server])) is not None

    def test_invalid_port_8443_ssl(self, detector):
        server = _server_block([_dir("listen", ["8443", "ssl"])])
        assert self._eval(detector, _http_block([server])) is not None

    def test_invalid_port_9000(self, detector):
        server = _server_block([_dir("listen", ["9000"])])
        assert self._eval(detector, _http_block([server])) is not None

    def test_invalid_port_444(self, detector):
        server = _server_block([_dir("listen", ["444"])])
        assert self._eval(detector, _http_block([server])) is not None

    def test_invalid_port_5000(self, detector):
        server = _server_block([_dir("listen", ["5000"])])
        assert self._eval(detector, _http_block([server])) is not None

    # --- Cổng không được phép kèm theo IP (5 test cases) ---
    def test_invalid_port_with_ipv4_0000(self, detector):
        server = _server_block([_dir("listen", ["0.0.0.0:8081"])])
        assert self._eval(detector, _http_block([server])) is not None

    def test_invalid_port_with_ipv4_local(self, detector):
        server = _server_block([_dir("listen", ["192.168.1.100:9090"])])
        assert self._eval(detector, _http_block([server])) is not None

    def test_invalid_port_with_ipv6_loopback(self, detector):
        server = _server_block([_dir("listen", ["[::1]:8888"])])
        assert self._eval(detector, _http_block([server])) is not None

    def test_invalid_port_with_ipv4_private(self, detector):
        server = _server_block([_dir("listen", ["10.0.0.5:22"])])
        assert self._eval(detector, _http_block([server])) is not None

    def test_invalid_port_with_ipv4_loopback(self, detector):
        server = _server_block([_dir("listen", ["127.0.0.1:27017"])])
        assert self._eval(detector, _http_block([server])) is not None

    # --- Trộn lẫn cổng hợp lệ và không hợp lệ (4 test cases) ---
    def test_mixed_80_and_8081(self, detector):
        server = _server_block(
            [_dir("listen", ["80"]), _dir("listen", ["8081"])])
        result = self._eval(detector, _http_block([server]))
        assert result is not None
        assert len(result["remediations"]) >= 1

    def test_mixed_3000_and_4000(self, detector):
        server = _server_block(
            [_dir("listen", ["3000"]), _dir("listen", ["4000"])])
        result = self._eval(detector, _http_block([server]))
        assert result is not None
        assert len(result["remediations"]) >= 1

    def test_mixed_443_and_8443(self, detector):
        server = _server_block(
            [_dir("listen", ["443", "ssl"]), _dir("listen", ["8443", "ssl"])])
        result = self._eval(detector, _http_block([server]))
        assert result is not None

    def test_mixed_ipv6_80_and_81(self, detector):
        server = _server_block(
            [_dir("listen", ["[::]:80"]), _dir("listen", ["[::]:81"])])
        result = self._eval(detector, _http_block([server]))
        assert result is not None

    # --- Giao thức UDP trên cổng không cho phép (2 test cases) ---
    def test_invalid_port_8443_quic(self, detector):
        server = _server_block([_dir("listen", ["8443", "quic"])])
        assert self._eval(detector, _http_block([server])) is not None

    def test_invalid_port_9000_udp(self, detector):
        server = _server_block([_dir("listen", ["9000", "udp"])])
        assert self._eval(detector, _http_block([server])) is not None

    # --- Kiểm tra cấu trúc dữ liệu phản hồi (4 test cases) ---
    def test_response_file_path(self, detector):
        server = _server_block([_dir("listen", ["81"])])
        result = self._eval(detector, _http_block([server]))
        assert result["file"] == self.FILEPATH

    def test_response_remediations_is_list(self, detector):
        server = _server_block([_dir("listen", ["81"])])
        result = self._eval(detector, _http_block([server]))
        assert isinstance(result["remediations"], list)
        assert len(result["remediations"]) >= 1

    def test_response_action_is_delete_or_replace(self, detector):
        server = _server_block([_dir("listen", ["81"])])
        result = self._eval(detector, _http_block([server]))
        action = result["remediations"][0]["action"]
        assert action in ["delete", "replace"]

    def test_response_directive_is_listen(self, detector):
        server = _server_block([_dir("listen", ["81"])])
        result = self._eval(detector, _http_block([server]))
        assert result["remediations"][0]["directive"] == "listen"


# ──────────────────────────────────────────────────────────────────────────────
# Phần 4 — scan(): Toàn bộ đường ống (Full Pipeline Integration) (15 Test Cases)
# ──────────────────────────────────────────────────────────────────────────────

class TestScan:
    """Các bài test kiểm tra tích hợp toàn diện thông qua việc mô phỏng dữ liệu phân tích AST."""

    # --- Cấu hình an toàn đầy đủ (3 test cases) ---
    def test_full_secure_80_443(self, detector):
        parser_output = _make_parser_output([_http_block([
            _server_block([_dir("listen", ["80"])]),
            _server_block([_dir("listen", ["443", "ssl"])])
        ])])
        assert detector.scan(parser_output) == []

    def test_full_secure_8080_3000(self, detector):
        parser_output = _make_parser_output([_http_block([
            _server_block([_dir("listen", ["8080"])]),
            _server_block([_dir("listen", ["3000"])])
        ])])
        assert detector.scan(parser_output) == []

    def test_full_secure_all_valid_distributed(self, detector):
        parser_output = _make_parser_output([_http_block([
            _server_block([_dir("listen", ["80"]), _dir("listen", ["8080"])]),
            _server_block([_dir("listen", ["443", "ssl"]),
                          _dir("listen", ["3000"])])
        ])])
        assert detector.scan(parser_output) == []

    # --- Nhiều file cấu hình có cổng vi phạm (3 test cases) ---
    def test_multiple_files_with_violations(self, detector):
        parser_output = {
            "config": [
                {"file": "/etc/nginx/conf.d/admin.conf",
                    "parsed": [_server_block([_dir("listen", ["9090"])])]},
                {"file": "/etc/nginx/conf.d/api.conf",
                    "parsed": [_server_block([_dir("listen", ["8443", "ssl"])])]}
            ]
        }
        findings = detector.scan(parser_output)
        assert len(findings) == 2
        files = [f["file"] for f in findings]
        assert "/etc/nginx/conf.d/admin.conf" in files
        assert "/etc/nginx/conf.d/api.conf" in files

    def test_multiple_files_app1_app2(self, detector):
        parser_output = {
            "config": [
                {"file": "/etc/nginx/conf.d/app.conf",
                    "parsed": [_server_block([_dir("listen", ["81"])])]},
                {"file": "/etc/nginx/conf.d/app2.conf",
                    "parsed": [_server_block([_dir("listen", ["82"])])]}
            ]
        }
        findings = detector.scan(parser_output)
        assert len(findings) == 2

    def test_valid_in_one_invalid_in_another(self, detector):
        parser_output = {
            "config": [
                {"file": "/etc/nginx/conf.d/valid.conf",
                    "parsed": [_server_block([_dir("listen", ["80"])])]},
                {"file": "/etc/nginx/conf.d/invalid.conf",
                    "parsed": [_server_block([_dir("listen", ["8081"])])]}
            ]
        }
        findings = detector.scan(parser_output)
        assert len(findings) == 1
        assert findings[0]["file"] == "/etc/nginx/conf.d/invalid.conf"

    # --- Gom nhóm lỗi (Grouping) (3 test cases) ---
    def test_grouping_multiple_invalid_in_same_file(self, detector):
        parser_output = _make_parser_output([_http_block([
            _server_block([_dir("listen", ["8081"]), _dir("listen", ["8082"])])
        ])])
        findings = detector.scan(parser_output)
        assert len(findings) == 1
        assert len(findings[0]["remediations"]) == 2

    def test_grouping_three_invalid_ports(self, detector):
        parser_output = _make_parser_output([_http_block([
            _server_block([_dir("listen", ["81"]), _dir(
                "listen", ["82"]), _dir("listen", ["83"])])
        ])])
        findings = detector.scan(parser_output)
        assert len(findings) == 1
        assert len(findings[0]["remediations"]) == 3

    def test_grouping_invalid_across_multiple_servers(self, detector):
        parser_output = _make_parser_output([_http_block([
            _server_block([_dir("listen", ["81"])]),
            _server_block([_dir("listen", ["82"])])
        ])])
        findings = detector.scan(parser_output)
        assert len(findings) == 1
        assert len(findings[0]["remediations"]) == 2

    # --- Cổng không hợp lệ bị comment (3 test cases) ---
    def test_commented_invalid_port_ignored(self, detector):
        # Crossplane ignores comments, so parsed list for commented directive is empty
        parser_output = _make_parser_output([_http_block([
            _server_block([])  # Simulating commented out listen
        ])])
        assert detector.scan(parser_output) == []

    def test_commented_invalid_with_active_valid(self, detector):
        parser_output = _make_parser_output([_http_block([
            # Simulating `# listen 81;` and active `listen 80;`
            _server_block([_dir("listen", ["80"])])
        ])])
        assert detector.scan(parser_output) == []

    def test_commented_invalid_with_active_invalid(self, detector):
        parser_output = _make_parser_output([_http_block([
            # Active invalid, commented invalid not shown
            _server_block([_dir("listen", ["9000"])])
        ])])
        findings = detector.scan(parser_output)
        assert len(findings) == 1

    # --- Tính toàn vẹn của kết quả Schema (3 test cases) ---
    def test_schema_file_key_exists(self, detector):
        parser_output = _make_parser_output([_http_block([
            _server_block([_dir("listen", ["81"])])
        ])])
        findings = detector.scan(parser_output)
        assert "file" in findings[0]

    def test_schema_remediations_array_exists_with_required_keys(self, detector):
        parser_output = _make_parser_output([_http_block([
            _server_block([_dir("listen", ["81"])])
        ])])
        findings = detector.scan(parser_output)
        remediation = findings[0]["remediations"][0]
        assert "action" in remediation
        assert "directive" in remediation
        assert "context" in remediation

    def test_schema_can_be_used_for_auto_remediation(self, detector):
        parser_output = _make_parser_output([_http_block([
            _server_block([_dir("listen", ["81"])])
        ])])
        findings = detector.scan(parser_output)
        remediation = findings[0]["remediations"][0]
        assert remediation["action"] in ["delete", "replace"]
        assert remediation["directive"] == "listen"
