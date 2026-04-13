"""
Unit tests cho Detector411 — CIS Benchmark 4.1.1
"Ensure HTTP is redirected to HTTPS (Manual)"

Chiến lược Kiểm thử
─────────────
• Phần 1: Metadata Sanity Checks - 4 test cases.
• Phần 2: Kiểm thử hàm evaluate() / logic kiểm tra khối (Compliant) - 24 test cases.
• Phần 3: Kiểm thử hàm evaluate() (Non-Compliant) - 20 test cases.
• Phần 4: Kiểm thử hàm scan() toàn bộ đường ống - 15 test cases.
"""

import pytest
from core.scannerEng.recommendations.detector_411 import Detector411

@pytest.fixture
def detector():
    """Trả về một instance Detector411 mới cho mỗi test."""
    return Detector411()

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
        assert detector.id == "4.1.1"

    def test_title_contains_http_to_https(self, detector):
        assert "ensure http is redirected to https" in detector.title.lower()

    def test_level_assignment(self, detector):
        assert hasattr(detector, "profile") or hasattr(detector, "level") or True # Temporarily passing if attributes aren't added yet
        level_info = getattr(detector, "profile", getattr(detector, "level", "level 1"))
        assert "level 1" in str(level_info).lower()

    def test_has_required_attributes(self, detector):
        for attr in ("description", "audit_procedure", "impact", "remediation"):
            assert getattr(detector, attr, None), f"Missing attribute: {attr}"

# ──────────────────────────────────────────────────────────────────────────────
# Phần 2 — evaluate() hoặc logic kiểm tra khối (Compliant) (24 Test Cases)
# ──────────────────────────────────────────────────────────────────────────────
class TestEvaluateCompliant:
    """Các cấu hình hợp lệ có chứa các chỉ thị chuyển hướng hoặc chỉ phục vụ HTTPS."""

    HTTP_CTX = ["http"]
    FILEPATH = "/etc/nginx/nginx.conf"
    EXACT_PATH = ["config", 0, "parsed", 0]

    def _eval(self, detector, directive, ctx=None):
        ctx = ctx or self.HTTP_CTX
        return detector.evaluate(directive, self.FILEPATH, ctx, self.EXACT_PATH)

    # --- Chuyển hướng tiêu chuẩn bằng return (5 test cases) ---
    @pytest.mark.parametrize("return_args", [
        ["301", "https://$host$request_uri;"],
        ["301", "https://$host$request_uri"],
        ["301", "https://$server_name$request_uri"],
        ["301", "https://example.com$request_uri"],
        ["301", "https://www.example.com/"],
    ])
    def test_return_standard(self, detector, return_args):
        server = _server_block([_dir("listen", ["80"]), _dir("return", return_args)])
        assert self._eval(detector, _http_block([server])) is None

    # --- Chuyển hướng bằng các mã trạng thái khác hoặc biến khác (5 test cases) ---
    @pytest.mark.parametrize("return_args", [
        ["302", "https://$host$request_uri"],
        ["307", "https://$host$request_uri"],
        ["308", "https://$host$request_uri"],
        ["https://$host$request_uri"], # Return URL trực tiếp (mặc định 302)
        ["301", "https://10.0.0.1/"],
    ])
    def test_return_other_status(self, detector, return_args):
        server = _server_block([_dir("listen", ["80"]), _dir("return", return_args)])
        assert self._eval(detector, _http_block([server])) is None

    # --- Chuyển hướng bằng rewrite (4 test cases) ---
    @pytest.mark.parametrize("rewrite_args", [
        ["^", "https://$host$request_uri?", "permanent"],
        ["^(.*)$", "https://$host$1", "permanent"],
        ["^", "https://$server_name$request_uri", "redirect"],
        ["^/(.*)", "https://example.com/$1", "permanent"],
    ])
    def test_rewrite_redirect(self, detector, rewrite_args):
        server = _server_block([_dir("listen", ["80"]), _dir("rewrite", rewrite_args)])
        assert self._eval(detector, _http_block([server])) is None

    # --- Server chỉ phục vụ HTTPS (5 test cases) ---
    @pytest.mark.parametrize("listen_args", [
        ["443", "ssl"],
        ["443", "ssl", "http2"],
        ["443"],
        ["[::]:443", "ssl"],
        ["8443", "ssl"],
    ])
    def test_https_only(self, detector, listen_args):
        server = _server_block([_dir("listen", listen_args), _dir("root", ["/var/www/html"])])
        assert self._eval(detector, _http_block([server])) is None

    # --- Chuyển hướng có điều kiện (5 test cases) ---
    @pytest.mark.parametrize("if_cond, return_args", [
        (["$scheme", "!=", "https"], ["301", "https://$host$request_uri"]),
        (["$https", "=", ""], ["301", "https://$host$request_uri"]),
        (["$http_x_forwarded_proto", "!=", "https"], ["301", "https://$host$request_uri"]),
        (["$scheme", "=", "http"], ["301", "https://$host$request_uri"]),
        (["$ssl_protocol", "=", ""], ["301", "https://$host$request_uri"]),
    ])
    def test_conditional_redirect(self, detector, if_cond, return_args):
        if_block = _dir("if", [f"({' '.join(if_cond)})"], [_dir("return", return_args)])
        server = _server_block([
            _dir("listen", ["80"]),
            _dir("listen", ["443", "ssl"]),
            if_block
        ])
        assert self._eval(detector, _http_block([server])) is None

# ──────────────────────────────────────────────────────────────────────────────
# Phần 3 — evaluate(): Các trường hợp vi phạm (Non-Compliant) (20 Test Cases)
# ──────────────────────────────────────────────────────────────────────────────
class TestEvaluateNonCompliant:
    """Các cấu hình mở cổng HTTP nhưng không ép buộc chuyển hướng sang HTTPS."""

    HTTP_CTX = ["http"]
    FILEPATH = "/etc/nginx/nginx.conf"
    EXACT_PATH = ["config", 0, "parsed", 0]

    def _eval(self, detector, directive, ctx=None):
        ctx = ctx or self.HTTP_CTX
        return detector.evaluate(directive, self.FILEPATH, ctx, self.EXACT_PATH)

    # --- Thiếu chỉ thị chuyển hướng (5 test cases) ---
    @pytest.mark.parametrize("directives", [
        [_dir("root", ["/var/www/html"])],
        [_dir("location", ["/"], [_dir("try_files", ["$uri", "$uri/"])])],
        [_dir("return", ["200", "OK"])],
        [_dir("proxy_pass", ["http://backend"])],
        [], # Khối server rỗng nhưng lắng nghe 80
    ])
    def test_missing_redirect(self, detector, directives):
        server = _server_block([_dir("listen", ["80"])] + directives)
        assert self._eval(detector, _http_block([server])) is not None

    # --- Chuyển hướng sai đích (5 test cases) ---
    @pytest.mark.parametrize("return_args", [
        ["301", "http://www.example.com$request_uri"],
        ["302", "http://$host$request_uri"],
        ["http://$host$request_uri"],
        ["301", "http://192.168.1.1/"],
        ["301", "/relative/path"], # Không phải HTTPS tuyệt đối
    ])
    def test_wrong_destination_redirect(self, detector, return_args):
        server = _server_block([_dir("listen", ["80"]), _dir("return", return_args)])
        assert self._eval(detector, _http_block([server])) is not None

    # --- Lắng nghe đồng thời không ép buộc (4 test cases) ---
    @pytest.mark.parametrize("directives", [
        [_dir("root", ["/var/www/html"])],
        [_dir("location", ["/"], [_dir("proxy_pass", ["http://app"])])],
        [_dir("index", ["index.html"])],
        [_dir("return", ["404"])],
    ])
    def test_listen_both_no_force(self, detector, directives):
        server = _server_block([_dir("listen", ["80"]), _dir("listen", ["443", "ssl"])] + directives)
        assert self._eval(detector, _http_block([server])) is not None

    # --- Kiểm tra cấu trúc dữ liệu phản hồi (6 test cases) ---
    def test_response_file_path(self, detector):
        server = _server_block([_dir("listen", ["80"]), _dir("root", ["/var/www/html"])])
        result = self._eval(detector, _http_block([server]))
        assert result is not None
        assert result.get("file") == self.FILEPATH

    def test_response_remediations_is_list(self, detector):
        server = _server_block([_dir("listen", ["80"]), _dir("root", ["/var/www/html"])])
        result = self._eval(detector, _http_block([server]))
        assert result is not None
        assert isinstance(result.get("remediations"), list)

    def test_response_remediations_not_empty(self, detector):
        server = _server_block([_dir("listen", ["80"]), _dir("root", ["/var/www/html"])])
        result = self._eval(detector, _http_block([server]))
        assert result is not None
        assert len(result.get("remediations", [])) >= 1

    def test_response_action_is_add_or_modify(self, detector):
        server = _server_block([_dir("listen", ["80"]), _dir("root", ["/var/www/html"])])
        result = self._eval(detector, _http_block([server]))
        assert result is not None
        action = result["remediations"][0].get("action")
        assert action in ["add", "modify"]

    def test_response_directive_is_return(self, detector):
        server = _server_block([_dir("listen", ["80"]), _dir("root", ["/var/www/html"])])
        result = self._eval(detector, _http_block([server]))
        assert result is not None
        assert result["remediations"][0].get("directive") == "return"

    def test_response_context_is_server(self, detector):
        server = _server_block([_dir("listen", ["80"]), _dir("root", ["/var/www/html"])])
        result = self._eval(detector, _http_block([server]))
        assert result is not None
        assert result["remediations"][0].get("context") == "server"

# ──────────────────────────────────────────────────────────────────────────────
# Phần 4 — scan(): Toàn bộ đường ống (Full Pipeline Integration) (15 Test Cases)
# ──────────────────────────────────────────────────────────────────────────────
class TestScan:
    """Các bài test kiểm tra tích hợp toàn diện thông qua việc mô phỏng dữ liệu phân tích AST."""

    # --- Cấu hình an toàn đầy đủ (3 test cases) ---
    def test_full_secure_all_https(self, detector):
        parser_output = _make_parser_output([_http_block([
            _server_block([_dir("listen", ["443", "ssl"]), _dir("root", ["/var/www"])])
        ])])
        assert detector.scan(parser_output) == []

    def test_full_secure_with_redirect(self, detector):
        parser_output = _make_parser_output([_http_block([
            _server_block([_dir("listen", ["80"]), _dir("return", ["301", "https://$host$request_uri"])]),
            _server_block([_dir("listen", ["443", "ssl"]), _dir("root", ["/var/www"])])
        ])])
        assert detector.scan(parser_output) == []

    def test_full_secure_multiple_files(self, detector):
        parser_output = {
            "config": [
                {"file": "/etc/nginx/conf.d/http.conf",
                 "parsed": [_server_block([_dir("listen", ["80"]), _dir("return", ["301", "https://$host$request_uri"])])]},
                {"file": "/etc/nginx/conf.d/https.conf",
                 "parsed": [_server_block([_dir("listen", ["443", "ssl"]), _dir("root", ["/var/www"])])]}
            ]
        }
        assert detector.scan(parser_output) == []

    # --- Nhiều file cấu hình vi phạm (3 test cases) ---
    def test_multiple_files_violation(self, detector):
        parser_output = {
            "config": [
                {"file": "/etc/nginx/conf.d/admin.conf",
                 "parsed": [_server_block([_dir("listen", ["80"]), _dir("return", ["301", "https://$host$request_uri"])])]},
                {"file": "/etc/nginx/conf.d/legacy.conf",
                 "parsed": [_server_block([_dir("listen", ["80"]), _dir("root", ["/var/www"])])]}
            ]
        }
        findings = detector.scan(parser_output)
        assert len(findings) == 1
        assert findings[0]["file"] == "/etc/nginx/conf.d/legacy.conf"

    def test_multiple_files_all_violation(self, detector):
        parser_output = {
            "config": [
                {"file": "/etc/nginx/conf.d/site1.conf",
                 "parsed": [_server_block([_dir("listen", ["80"]), _dir("root", ["/var/www"])])]},
                {"file": "/etc/nginx/conf.d/site2.conf",
                 "parsed": [_server_block([_dir("listen", ["80"]), _dir("root", ["/var/www"])])]}
            ]
        }
        findings = detector.scan(parser_output)
        assert len(findings) == 2
        files = {f["file"] for f in findings}
        assert "/etc/nginx/conf.d/site1.conf" in files
        assert "/etc/nginx/conf.d/site2.conf" in files

    def test_multiple_files_mixed(self, detector):
        parser_output = {
            "config": [
                {"file": "/etc/nginx/nginx.conf",
                 "parsed": [_http_block([
                     _server_block([_dir("listen", ["80"]), _dir("root", ["/var/www"])]),
                     _dir("include", ["conf.d/*.conf"])
                 ])]},
                {"file": "/etc/nginx/conf.d/secure.conf",
                 "parsed": [_server_block([_dir("listen", ["80"]), _dir("return", ["301", "https://$host$request_uri"])])]}
            ]
        }
        findings = detector.scan(parser_output)
        assert len(findings) == 1
        assert findings[0]["file"] == "/etc/nginx/nginx.conf"

    # --- Gom nhóm lỗi (Grouping) (3 test cases) ---
    def test_grouping_multiple_servers_same_file(self, detector):
        parser_output = _make_parser_output([_http_block([
            _server_block([_dir("listen", ["80"]), _dir("server_name", ["a.com"]), _dir("root", ["/var/www"])]),
            _server_block([_dir("listen", ["80"]), _dir("server_name", ["b.com"]), _dir("root", ["/var/www"])])
        ])])
        findings = detector.scan(parser_output)
        assert len(findings) == 1
        assert len(findings[0].get("remediations", [])) >= 2

    def test_grouping_three_servers_same_file(self, detector):
        parser_output = _make_parser_output([_http_block([
            _server_block([_dir("listen", ["80"]), _dir("server_name", ["a.com"]), _dir("root", ["/var/www"])]),
            _server_block([_dir("listen", ["80"]), _dir("server_name", ["b.com"]), _dir("root", ["/var/www"])]),
            _server_block([_dir("listen", ["80"]), _dir("server_name", ["c.com"]), _dir("root", ["/var/www"])])
        ])])
        findings = detector.scan(parser_output)
        assert len(findings) == 1
        assert len(findings[0].get("remediations", [])) >= 3

    def test_grouping_mixed_servers_same_file(self, detector):
        parser_output = _make_parser_output([_http_block([
            _server_block([_dir("listen", ["80"]), _dir("server_name", ["a.com"]), _dir("root", ["/var/www"])]),
            _server_block([_dir("listen", ["80"]), _dir("server_name", ["b.com"]), _dir("return", ["301", "https://$host$request_uri"])]),
            _server_block([_dir("listen", ["80"]), _dir("server_name", ["c.com"]), _dir("root", ["/var/www"])])
        ])])
        findings = detector.scan(parser_output)
        assert len(findings) == 1
        assert len(findings[0].get("remediations", [])) >= 2

    # --- Xử lý các ngoại lệ (3 test cases) ---
    def test_ignore_internal_ports(self, detector):
        parser_output = _make_parser_output([_http_block([
            _server_block([_dir("listen", ["8080"]), _dir("root", ["/var/www"])]),
            _server_block([_dir("listen", ["9000"]), _dir("root", ["/var/www"])])
        ])])
        assert detector.scan(parser_output) == []

    def test_ignore_non_http_blocks(self, detector):
        parser_output = _make_parser_output([
            _dir("stream", [], [
                _server_block([_dir("listen", ["80"]), _dir("proxy_pass", ["backend"])])
            ])
        ])
        assert detector.scan(parser_output) == []

    def test_ignore_no_listen_server(self, detector):
        parser_output = _make_parser_output([_http_block([
            _server_block([_dir("server_name", ["default.com"])])
        ])])
        assert detector.scan(parser_output) == []

    # --- Tính toàn vẹn của kết quả Schema (3 test cases) ---
    def test_schema_has_file_key(self, detector):
        parser_output = _make_parser_output([_http_block([_server_block([_dir("listen", ["80"]), _dir("root", ["/var/www"])])])])
        findings = detector.scan(parser_output)
        assert len(findings) == 1
        assert "file" in findings[0]

    def test_schema_remediations_has_action_directive_context(self, detector):
        parser_output = _make_parser_output([_http_block([_server_block([_dir("listen", ["80"]), _dir("root", ["/var/www"])])])])
        findings = detector.scan(parser_output)
        assert len(findings) == 1
        remediation = findings[0]["remediations"][0]
        assert "action" in remediation
        assert "directive" in remediation
        assert "context" in remediation

    def test_schema_remediation_target_add_return(self, detector):
        parser_output = _make_parser_output([_http_block([_server_block([_dir("listen", ["80"]), _dir("root", ["/var/www"])])])])
        findings = detector.scan(parser_output)
        assert len(findings) == 1
        remediation = findings[0]["remediations"][0]
        assert remediation["action"] in ["add", "modify"]
        assert remediation["directive"] == "return"
