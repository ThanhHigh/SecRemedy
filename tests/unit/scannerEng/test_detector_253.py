"""
Unit tests cho Detector253 — CIS Benchmark 2.5.3
"Ensure hidden file serving is disabled (Manual)"

Chiến lược Kiểm thử
─────────────
• Phần 1: Metadata Sanity Checks - 4 test cases.
• Phần 2: Kiểm thử hàm evaluate() / logic kiểm tra khối (Compliant) - 24 test cases.
• Phần 3: Kiểm thử hàm evaluate() (Non-Compliant) - 20 test cases.
• Phần 4: Kiểm thử hàm scan() toàn bộ đường ống - 15 test cases.
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

def _location_block(path: str, directives: list) -> dict:
    """Hàm hỗ trợ: tạo một block 'location' giả lập, mặc định sử dụng prefix match.
    Nếu path có chứa ~, hàm này vẫn gọi bình thường, coi toàn bộ path là 1 chuỗi args.
    """
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
        assert detector.id == "2.5.3"

    def test_title_contains_hidden_file_serving(self, detector):
        assert "hidden file serving is disabled" in detector.title.lower()

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
    """Các cấu hình hợp lệ có chứa chỉ thị location chặn file ẩn."""

    HTTP_CTX = ["http"]
    FILEPATH = "/etc/nginx/nginx.conf"
    EXACT_PATH = ["config", 0, "parsed", 0]

    def _eval(self, detector, directive, ctx=None):
        ctx = ctx or self.HTTP_CTX
        return detector.evaluate(directive, self.FILEPATH, ctx, self.EXACT_PATH)

    # --- Khai báo từ chối tiêu chuẩn (5 test cases) ---
    def test_deny_standard_1(self, detector):
        server = _server_block([_dir("location", ["~", r"/\."], [_dir("deny", ["all"])])])
        assert self._eval(detector, _http_block([server])) is None

    def test_deny_standard_2(self, detector):
        server = _server_block([_dir("location", ["~*", r"/\."], [_dir("deny", ["all"])])])
        assert self._eval(detector, _http_block([server])) is None

    def test_deny_standard_3(self, detector):
        server = _server_block([_dir("location", ["~", r"/\."], [_dir("deny", ["all"]), _dir("access_log", ["off"])])])
        assert self._eval(detector, _http_block([server])) is None

    def test_deny_standard_4(self, detector):
        server = _server_block([
            _dir("listen", ["80"]),
            _dir("location", ["~", r"/\."], [_dir("deny", ["all"])])
        ])
        assert self._eval(detector, _http_block([server])) is None

    def test_deny_standard_5(self, detector):
        # Kiểm tra khoảng trắng khác nhau trong path arguments
        server = _server_block([_dir("location", ["~", r"/\. "], [_dir("deny", ["all"])])])
        assert self._eval(detector, _http_block([server])) is None

    # --- Khai báo từ chối bằng mã trạng thái (5 test cases) ---
    def test_return_404(self, detector):
        server = _server_block([_dir("location", ["~", r"/\."], [_dir("return", ["404"])])])
        assert self._eval(detector, _http_block([server])) is None

    def test_return_403(self, detector):
        server = _server_block([_dir("location", ["~", r"/\."], [_dir("return", ["403"])])])
        assert self._eval(detector, _http_block([server])) is None

    def test_return_444(self, detector):
        server = _server_block([_dir("location", ["~", r"/\."], [_dir("return", ["444"])])])
        assert self._eval(detector, _http_block([server])) is None

    def test_return_404_with_text(self, detector):
        server = _server_block([_dir("location", ["~", r"/\."], [_dir("return", ["404", "Not Found"])])])
        assert self._eval(detector, _http_block([server])) is None

    def test_return_403_with_text(self, detector):
        server = _server_block([_dir("location", ["~", r"/\."], [_dir("return", ["403", "Forbidden"])])])
        assert self._eval(detector, _http_block([server])) is None

    # --- Có ngoại lệ hợp lệ (Let's Encrypt) (5 test cases) ---
    def test_allow_well_known_1(self, detector):
        server = _server_block([
            _dir("location", ["~", r"/\.well-known/acme-challenge"], [_dir("allow", ["all"])]),
            _dir("location", ["~", r"/\."], [_dir("deny", ["all"])])
        ])
        assert self._eval(detector, _http_block([server])) is None

    def test_allow_well_known_2(self, detector):
        server = _server_block([
            _dir("location", ["^~", "/.well-known/acme-challenge/"], [_dir("allow", ["all"])]),
            _dir("location", ["~", r"/\."], [_dir("deny", ["all"])])
        ])
        assert self._eval(detector, _http_block([server])) is None

    def test_allow_well_known_3(self, detector):
        server = _server_block([
            _dir("location", ["/.well-known"], [_dir("allow", ["all"])]),
            _dir("location", ["~", r"/\."], [_dir("deny", ["all"])])
        ])
        assert self._eval(detector, _http_block([server])) is None

    def test_allow_well_known_4(self, detector):
        server = _server_block([
            _dir("location", ["~", r"/\."], [_dir("deny", ["all"])]),
            _dir("location", ["~", r"/\.well-known"], [_dir("allow", ["all"])])
        ])
        assert self._eval(detector, _http_block([server])) is None

    def test_allow_well_known_5(self, detector):
        server = _server_block([
            _dir("location", ["~", r"/\.well-known/acme-challenge"], [_dir("return", ["200", "ok"])]),
            _dir("location", ["~", r"/\."], [_dir("return", ["404"])])
        ])
        assert self._eval(detector, _http_block([server])) is None

    # --- Vị trí file cấu hình include (4 test cases) ---
    def test_include_snippet_1(self, detector):
        parser_output = {
            "config": [
                {"file": "/etc/nginx/nginx.conf",
                 "parsed": [_http_block([_server_block([_dir("include", ["snippets/deny-hidden.conf"])])])]},
                {"file": "/etc/nginx/snippets/deny-hidden.conf",
                 "parsed": [_dir("location", ["~", r"/\."], [_dir("deny", ["all"])])]}
            ]
        }
        assert detector.scan(parser_output) == []

    def test_include_snippet_2(self, detector):
        parser_output = {
            "config": [
                {"file": "/etc/nginx/nginx.conf",
                 "parsed": [_http_block([_dir("include", ["conf.d/*.conf"])])]},
                {"file": "/etc/nginx/conf.d/default.conf",
                 "parsed": [_server_block([
                     _dir("include", ["snippets/deny-hidden.conf"]),
                     _dir("listen", ["80"])
                 ])]},
                {"file": "/etc/nginx/snippets/deny-hidden.conf",
                 "parsed": [_dir("location", ["~", r"/\."], [_dir("return", ["404"])])]}
            ]
        }
        assert detector.scan(parser_output) == []

    def test_include_snippet_3(self, detector):
        parser_output = {
            "config": [
                {"file": "/etc/nginx/nginx.conf",
                 "parsed": [_http_block([_server_block([_dir("include", ["snippets/*.conf"])])])]},
                {"file": "/etc/nginx/snippets/security.conf",
                 "parsed": [_dir("location", ["~", r"/\."], [_dir("deny", ["all"])])]}
            ]
        }
        assert detector.scan(parser_output) == []

    def test_include_snippet_4(self, detector):
        parser_output = {
            "config": [
                {"file": "/etc/nginx/nginx.conf",
                 "parsed": [_http_block([_dir("include", ["conf.d/api.conf"])])]},
                {"file": "/etc/nginx/conf.d/api.conf",
                 "parsed": [_server_block([
                     _dir("location", ["/",], [_dir("try_files", ["$uri", "$uri/", "/index.php?$query_string"])]),
                     _dir("include", ["snippets/deny-hidden.conf"])
                 ])]},
                {"file": "/etc/nginx/snippets/deny-hidden.conf",
                 "parsed": [_dir("location", ["~", r"/\."], [_dir("deny", ["all"])])]}
            ]
        }
        assert detector.scan(parser_output) == []

    # --- Khai báo Regular Expression nâng cao (5 test cases) ---
    def test_regex_advanced_1(self, detector):
        server = _server_block([_dir("location", ["~", r"/\.(?!well-known).*"], [_dir("deny", ["all"])])])
        assert self._eval(detector, _http_block([server])) is None

    def test_regex_advanced_2(self, detector):
        server = _server_block([_dir("location", ["~*", r"/\.(?!well-known).*"], [_dir("deny", ["all"])])])
        assert self._eval(detector, _http_block([server])) is None

    def test_regex_advanced_3(self, detector):
        server = _server_block([_dir("location", ["~", r"/\.(?!well-known\/)"], [_dir("deny", ["all"])])])
        assert self._eval(detector, _http_block([server])) is None

    def test_regex_advanced_4(self, detector):
        server = _server_block([_dir("location", ["~", r"/\.(?!well-known).*$"], [_dir("return", ["404"])])])
        assert self._eval(detector, _http_block([server])) is None

    def test_regex_advanced_5(self, detector):
        server = _server_block([_dir("location", ["~*", r"/\.(?!well-known\/)[^/]+"], [_dir("return", ["403"])])])
        assert self._eval(detector, _http_block([server])) is None

# ──────────────────────────────────────────────────────────────────────────────
# Phần 3 — evaluate(): Các trường hợp vi phạm (Non-Compliant) (20 Test Cases)
# ──────────────────────────────────────────────────────────────────────────────
class TestEvaluateNonCompliant:
    """Các cấu hình thiếu location chặn file ẩn hoặc định nghĩa không đầy đủ."""

    HTTP_CTX = ["http"]
    FILEPATH = "/etc/nginx/nginx.conf"
    EXACT_PATH = ["config", 0, "parsed", 0]

    def _eval(self, detector, directive, ctx=None):
        ctx = ctx or self.HTTP_CTX
        return detector.evaluate(directive, self.FILEPATH, ctx, self.EXACT_PATH)

    # --- Thiếu location chặn hoàn toàn (5 test cases) ---
    def test_missing_completely_1(self, detector):
        server = _server_block([_dir("listen", ["80"])])
        assert self._eval(detector, _http_block([server])) is not None

    def test_missing_completely_2(self, detector):
        server = _server_block([_dir("location", ["/",], [_dir("return", ["200"])])])
        assert self._eval(detector, _http_block([server])) is not None

    def test_missing_completely_3(self, detector):
        server = _server_block([_dir("root", ["/var/www/html"])])
        assert self._eval(detector, _http_block([server])) is not None

    def test_missing_completely_4(self, detector):
        server = _server_block([
            _dir("location", ["~", r"\.php$"], [_dir("fastcgi_pass", ["127.0.0.1:9000"])])
        ])
        assert self._eval(detector, _http_block([server])) is not None

    def test_missing_completely_5(self, detector):
        server = _server_block([])
        # Một server rỗng (không redirect) có thể cấu hình default, cũng bị coi là thiếu
        # Trừ khi nó bị filter ở hàm scan. Tại mức evaluate, nó vi phạm.
        assert self._eval(detector, _http_block([server])) is not None

    # --- Chặn không đầy đủ (5 test cases) ---
    def test_partial_deny_ht(self, detector):
        server = _server_block([_dir("location", ["~", r"/\.ht"], [_dir("deny", ["all"])])])
        assert self._eval(detector, _http_block([server])) is not None

    def test_partial_deny_git(self, detector):
        server = _server_block([_dir("location", ["~", r"/\.git"], [_dir("deny", ["all"])])])
        assert self._eval(detector, _http_block([server])) is not None

    def test_partial_deny_env(self, detector):
        server = _server_block([_dir("location", ["~", r"/\.env"], [_dir("deny", ["all"])])])
        assert self._eval(detector, _http_block([server])) is not None

    def test_partial_deny_multiple(self, detector):
        server = _server_block([_dir("location", ["~", r"\.(svn|git|env)"], [_dir("deny", ["all"])])])
        assert self._eval(detector, _http_block([server])) is not None

    def test_partial_deny_svn(self, detector):
        server = _server_block([_dir("location", ["~", r"/\.svn"], [_dir("deny", ["all"])])])
        assert self._eval(detector, _http_block([server])) is not None

    # --- Hành động không bảo mật (4 test cases) ---
    def test_insecure_action_allow_all(self, detector):
        server = _server_block([_dir("location", ["~", r"/\."], [_dir("allow", ["all"])])])
        assert self._eval(detector, _http_block([server])) is not None

    def test_insecure_action_empty(self, detector):
        server = _server_block([_dir("location", ["~", r"/\."], [])])
        assert self._eval(detector, _http_block([server])) is not None

    def test_insecure_action_log_only(self, detector):
        server = _server_block([_dir("location", ["~", r"/\."], [_dir("access_log", ["off"])])])
        assert self._eval(detector, _http_block([server])) is not None

    def test_insecure_action_allow_ip(self, detector):
        server = _server_block([_dir("location", ["~", r"/\."], [_dir("allow", ["127.0.0.1"])])])
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

    def test_response_directive_is_location(self, detector):
        server = _server_block([_dir("listen", ["80"])])
        result = self._eval(detector, _http_block([server]))
        assert result["remediations"][0]["directive"] == "location"

    def test_response_context_is_server(self, detector):
        server = _server_block([_dir("listen", ["80"])])
        result = self._eval(detector, _http_block([server]))
        assert result["remediations"][0]["context"] == "server"

# ──────────────────────────────────────────────────────────────────────────────
# Phần 4 — scan(): Toàn bộ đường ống (Full Pipeline Integration) (15 Test Cases)
# ──────────────────────────────────────────────────────────────────────────────
class TestScan:
    """Các bài test kiểm tra tích hợp toàn diện thông qua việc mô phỏng dữ liệu phân tích AST."""

    # --- Cấu hình an toàn đầy đủ (3 test cases) ---
    def test_full_secure_1(self, detector):
        parser_output = _make_parser_output([_http_block([
            _server_block([
                _dir("listen", ["80"]),
                _dir("location", ["~", r"/\."], [_dir("deny", ["all"])])
            ])
        ])])
        assert detector.scan(parser_output) == []

    def test_full_secure_2(self, detector):
        parser_output = _make_parser_output([_http_block([
            _server_block([
                _dir("listen", ["80"]),
                _dir("location", ["~", r"/\."], [_dir("deny", ["all"])])
            ]),
            _server_block([
                _dir("listen", ["443"]),
                _dir("location", ["~", r"/\."], [_dir("return", ["404"])])
            ])
        ])])
        assert detector.scan(parser_output) == []

    def test_full_secure_3_with_includes(self, detector):
        parser_output = {
            "config": [
                {"file": "/etc/nginx/nginx.conf",
                 "parsed": [_http_block([_dir("include", ["conf.d/*.conf"])])]},
                {"file": "/etc/nginx/conf.d/site.conf",
                 "parsed": [_server_block([
                     _dir("listen", ["80"]),
                     _dir("location", ["~", r"/\."], [_dir("deny", ["all"])])
                 ])]}
            ]
        }
        assert detector.scan(parser_output) == []

    # --- Nhiều file cấu hình vi phạm (3 test cases) ---
    def test_multiple_files_missing_location(self, detector):
        parser_output = {
            "config": [
                {"file": "/etc/nginx/conf.d/api.conf",
                 "parsed": [_server_block([_dir("listen", ["80"]), _dir("root", ["/var/www"])])]},
                {"file": "/etc/nginx/conf.d/default.conf",
                 "parsed": [_server_block([_dir("listen", ["443"]), _dir("root", ["/var/www"])])]}
            ]
        }
        findings = detector.scan(parser_output)
        assert len(findings) == 2
        files = {f["file"] for f in findings}
        assert "/etc/nginx/conf.d/api.conf" in files
        assert "/etc/nginx/conf.d/default.conf" in files

    def test_multiple_files_mixed(self, detector):
        parser_output = {
            "config": [
                {"file": "/etc/nginx/conf.d/secure.conf",
                 "parsed": [_server_block([
                     _dir("listen", ["80"]),
                     _dir("location", ["~", r"/\."], [_dir("deny", ["all"])])
                 ])]},
                {"file": "/etc/nginx/conf.d/insecure.conf",
                 "parsed": [_server_block([_dir("listen", ["443"]), _dir("root", ["/var/www"])])]}
            ]
        }
        findings = detector.scan(parser_output)
        assert len(findings) == 1
        assert findings[0]["file"] == "/etc/nginx/conf.d/insecure.conf"

    def test_multiple_files_partial_match(self, detector):
        parser_output = {
            "config": [
                {"file": "/etc/nginx/conf.d/site1.conf",
                 "parsed": [_server_block([
                     _dir("listen", ["80"]),
                     _dir("location", ["~", r"/\.ht"], [_dir("deny", ["all"])])
                 ])]},
                {"file": "/etc/nginx/conf.d/site2.conf",
                 "parsed": [_server_block([_dir("listen", ["443"]), _dir("root", ["/var/www"])])]}
            ]
        }
        findings = detector.scan(parser_output)
        assert len(findings) == 2

    # --- Gom nhóm lỗi (Grouping) (3 test cases) ---
    def test_grouping_multiple_servers_same_file(self, detector):
        parser_output = _make_parser_output([_http_block([
            _server_block([_dir("listen", ["80"]), _dir("root", ["/var/www"])]),
            _server_block([_dir("listen", ["8080"]), _dir("root", ["/var/www"])])
        ])])
        findings = detector.scan(parser_output)
        assert len(findings) == 1
        assert len(findings[0]["remediations"]) >= 2

    def test_grouping_three_servers_same_file(self, detector):
        parser_output = _make_parser_output([_http_block([
            _server_block([_dir("listen", ["81"]), _dir("root", ["/var/www"])]),
            _server_block([_dir("listen", ["82"]), _dir("root", ["/var/www"])]),
            _server_block([_dir("listen", ["83"]), _dir("root", ["/var/www"])])
        ])])
        findings = detector.scan(parser_output)
        assert len(findings) == 1
        assert len(findings[0]["remediations"]) >= 3

    def test_grouping_with_valid_and_invalid_servers(self, detector):
        parser_output = _make_parser_output([_http_block([
            _server_block([
                _dir("listen", ["80"]),
                _dir("location", ["~", r"/\."], [_dir("deny", ["all"])])
            ]),
            _server_block([_dir("listen", ["8080"]), _dir("root", ["/var/www"])])
        ])])
        findings = detector.scan(parser_output)
        assert len(findings) == 1
        assert len(findings[0]["remediations"]) >= 1

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
        # Mặc dù empty server là không có location ẩn, nhưng bộ quét có thể skip
        # vì không phục vụ file (không có root)
        parser_output = _make_parser_output([_http_block([
            _server_block([])
        ])])
        assert detector.scan(parser_output) == []

    def test_do_not_ignore_normal_server_with_root(self, detector):
        parser_output = _make_parser_output([_http_block([
            _server_block([
                _dir("listen", ["80"]),
                _dir("root", ["/var/www/html"])
            ])
        ])])
        assert len(detector.scan(parser_output)) == 1

    # --- Tính toàn vẹn của kết quả Schema (3 test cases) ---
    def test_schema_has_file_key(self, detector):
        parser_output = _make_parser_output([_http_block([_server_block([_dir("listen", ["80"]), _dir("root", ["/var/www"])])])])
        findings = detector.scan(parser_output)
        assert "file" in findings[0]

    def test_schema_remediations_has_action_directive_context(self, detector):
        parser_output = _make_parser_output([_http_block([_server_block([_dir("listen", ["80"]), _dir("root", ["/var/www"])])])])
        findings = detector.scan(parser_output)
        remediation = findings[0]["remediations"][0]
        assert "action" in remediation
        assert "directive" in remediation
        assert "context" in remediation

    def test_schema_remediation_target_add_location(self, detector):
        parser_output = _make_parser_output([_http_block([_server_block([_dir("listen", ["80"]), _dir("root", ["/var/www"])])])])
        findings = detector.scan(parser_output)
        remediation = findings[0]["remediations"][0]
        assert remediation["action"] == "add"
        assert remediation["directive"] == "location"
        assert remediation.get("block", [])  # Cần có nội dung để chèn vào block
