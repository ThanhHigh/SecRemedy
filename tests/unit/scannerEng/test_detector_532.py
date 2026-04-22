import pytest
from core.scannerEng.recommendations.detector_532 import Detector532


def _dir(directive: str, args: list = None, block: list = None) -> dict:
    d = {"directive": directive, "args": args or []}
    if block is not None:
        d["block"] = block
    return d


def _server_block(directives: list) -> dict:
    return _dir("server", [], directives)


def _http_block(directives: list) -> dict:
    return _dir("http", [], directives)


def _location_block(args: list, directives: list) -> dict:
    return _dir("location", args, directives)


def _make_parser_output(parsed_directives: list, filepath: str = "/etc/nginx/nginx.conf") -> dict:
    return {
        "status": "ok",
        "errors": [],
        "config": [
            {
                "file": filepath,
                "status": "ok",
                "errors": [],
                "parsed": parsed_directives
            }
        ]
    }


@pytest.fixture
def detector():
    return Detector532()

# =====================================================================
# 1. Kiểm tra Siêu dữ liệu (Metadata Sanity Checks) - 3 Test Cases
# =====================================================================


def test_metadata_id(detector):
    """Test 1: ID phải là '5.3.2'"""
    assert detector.id == "5.3.2"


def test_metadata_title(detector):
    """Test 2: Tiêu đề phải đúng"""
    assert detector.title == "Đảm bảo Content Security Policy (CSP) được bật và cấu hình hợp lý (Thủ công)"


def test_metadata_attributes(detector):
    """Test 3: Thuộc tính bắt buộc phải tồn tại"""
    assert hasattr(detector, "description")
    assert hasattr(detector, "audit_procedure")
    assert hasattr(detector, "impact")
    assert hasattr(detector, "remediation")

# =====================================================================
# 2. scan() - Toàn bộ đường ống (Full Pipeline Integration) - 42 Test Cases
# =====================================================================

# --- Hợp lệ - Cấu hình chuẩn (Valid Configuration) (5 Tests) ---


def test_valid_server_block(detector):
    """Test 4: Có `add_header Content-Security-Policy "default-src 'self'; frame-ancestors 'self'; form-action 'self';" always;` nằm trong block `server`"""
    out = _make_parser_output([_http_block([_server_block([
        _dir("add_header", ["Content-Security-Policy",
             '"default-src \'self\'; frame-ancestors \'self\'; form-action \'self\';"', "always"])
    ])])])
    assert detector.scan(out) == []


def test_valid_http_block(detector):
    """Test 5: Cấu hình nằm trong block `http` và áp dụng hợp lệ cho mọi server con"""
    out = _make_parser_output([_http_block([
        _dir("add_header", ["Content-Security-Policy",
             '"default-src \'self\'; frame-ancestors \'self\';"', "always"]),
        _server_block([])
    ])])
    assert detector.scan(out) == []


def test_valid_both_blocks(detector):
    """Test 6: Cấu hình hợp lệ xuất hiện ở cả `http` và `server` (ghi đè hợp lệ)"""
    out = _make_parser_output([_http_block([
        _dir("add_header", ["Content-Security-Policy",
             '"default-src \'self\'; frame-ancestors \'self\';"', "always"]),
        _server_block([
            _dir("add_header", [
                 "Content-Security-Policy", '"default-src \'self\'; frame-ancestors \'none\';"', "always"])
        ])
    ])])
    assert detector.scan(out) == []


def test_valid_location_block(detector):
    """Test 7: Cấu hình nằm trong block `location` hợp lệ"""
    out = _make_parser_output([_http_block([_server_block([
        _location_block(["/api"], [
            _dir("add_header", [
                 "Content-Security-Policy", '"default-src \'none\'; frame-ancestors \'none\';"', "always"])
        ])
    ])])])
    assert detector.scan(out) == []


def test_valid_report_only(detector):
    """Test 8: Cấu hình có `Content-Security-Policy-Report-Only` hợp lệ"""
    out = _make_parser_output([_http_block([_server_block([
        _dir("add_header", ["Content-Security-Policy-Report-Only",
             '"default-src \'self\'; frame-ancestors \'self\';"', "always"])
    ])])])
    assert detector.scan(out) == []

# --- Không hợp lệ - Thiếu hoặc sai cấu hình cơ bản (Misconfigured/Missing) (10 Tests) ---


def test_invalid_completely_missing(detector):
    """Test 9: Hoàn toàn không có chỉ thị `add_header Content-Security-Policy` trong toàn bộ cấu hình"""
    out = _make_parser_output([_http_block([_server_block([])])])
    res = detector.scan(out)
    assert len(res) == 1


def test_invalid_missing_always(detector):
    """Test 10: Có header nhưng thiếu chữ `always`"""
    out = _make_parser_output([_http_block([_server_block([
        _dir("add_header", ["Content-Security-Policy",
             '"default-src \'self\'; frame-ancestors \'self\';"'])
    ])])])
    res = detector.scan(out)
    assert len(res) == 1


def test_invalid_missing_default_src(detector):
    """Test 11: Có header nhưng thiếu chỉ thị `default-src`"""
    out = _make_parser_output([_http_block([_server_block([
        _dir("add_header", ["Content-Security-Policy",
             '"frame-ancestors \'self\';"', "always"])
    ])])])
    res = detector.scan(out)
    assert len(res) == 1


def test_invalid_missing_frame_ancestors(detector):
    """Test 12: Có header nhưng thiếu chỉ thị `frame-ancestors`"""
    out = _make_parser_output([_http_block([_server_block([
        _dir("add_header", ["Content-Security-Policy",
             '"default-src \'self\';"', "always"])
    ])])])
    res = detector.scan(out)
    assert len(res) == 1


def test_invalid_typo_header(detector):
    """Test 13: Tên header viết sai chính tả dẫn đến thiếu cấu hình hợp lệ"""
    out = _make_parser_output([_http_block([_server_block([
        _dir("add_header", ["Content-Security-Polic",
             '"default-src \'self\'; frame-ancestors \'self\';"', "always"])
    ])])])
    res = detector.scan(out)
    assert len(res) == 1


def test_invalid_commented_out(detector):
    """Test 14: Lệnh `add_header` bị comment đi trong cấu hình"""
    out = _make_parser_output([_http_block([_server_block([
        _dir("#", [
             "add_header Content-Security-Policy \"default-src 'self'; frame-ancestors 'self';\" always;"])
    ])])])
    res = detector.scan(out)
    assert len(res) == 1


def test_invalid_wrong_last_param(detector):
    """Test 15: Cấu hình tham số sau cùng sai `off` thay vì `always`"""
    out = _make_parser_output([_http_block([_server_block([
        _dir("add_header", ["Content-Security-Policy",
             '"default-src \'self\'; frame-ancestors \'self\';"', "off"])
    ])])])
    res = detector.scan(out)
    assert len(res) == 1


def test_invalid_other_headers_only(detector):
    """Test 16: Có nhiều header `add_header` khác nhau trong cấu hình nhưng không có `Content-Security-Policy`"""
    out = _make_parser_output([_http_block([_server_block([
        _dir("add_header", ["X-Frame-Options", "SAMEORIGIN"])
    ])])])
    res = detector.scan(out)
    assert len(res) == 1


def test_invalid_unsafe_inline(detector):
    """Test 17: Policy chứa tham số rủi ro: `unsafe-inline`"""
    out = _make_parser_output([_http_block([_server_block([
        _dir("add_header", ["Content-Security-Policy",
             '"default-src \'self\'; script-src \'unsafe-inline\'; frame-ancestors \'self\';"', "always"])
    ])])])
    res = detector.scan(out)
    assert len(res) == 1


def test_invalid_unsafe_eval(detector):
    """Test 18: Policy chứa tham số rủi ro: `unsafe-eval`"""
    out = _make_parser_output([_http_block([_server_block([
        _dir("add_header", ["Content-Security-Policy",
             '"default-src \'self\'; script-src \'unsafe-eval\'; frame-ancestors \'self\';"', "always"])
    ])])])
    res = detector.scan(out)
    assert len(res) == 1

# --- Kiểm tra theo cấp độ và sự kế thừa (Block Levels: http, server, location) (10 Tests) ---


def test_level_missing_http_server_payload(detector):
    """Test 19: Thiếu ở `http` và `server` -> Sinh payload `add` vào `http` hoặc `server`"""
    out = _make_parser_output([_http_block([_server_block([])])])
    res = detector.scan(out)
    assert len(res) == 1
    assert res[0]["remediations"][0]["action"] == "add"


def test_level_server_wrong_value_payload(detector):
    """Test 20: Cấu hình có `Content-Security-Policy` ở `server` nhưng sai tham số -> Trả về payload sửa (`replace`) tại `server` đó"""
    out = _make_parser_output([_http_block([_server_block([
        _dir("add_header", ["Content-Security-Policy",
             '"default-src \'self\';"', "always"])
    ])])])
    res = detector.scan(out)
    assert len(res) == 1
    assert res[0]["remediations"][0]["action"] == "replace"


def test_level_http_valid_server_empty(detector):
    """Test 21: Cấu hình đúng ở `http`, không có `add_header` nào khác ở `server` -> Hợp lệ do kế thừa"""
    out = _make_parser_output([_http_block([
        _dir("add_header", ["Content-Security-Policy",
             '"default-src \'self\'; frame-ancestors \'self\';"', "always"]),
        _server_block([])
    ])])
    assert detector.scan(out) == []


def test_level_http_valid_server_override_other(detector):
    """Test 22: Cấu hình đúng ở `http`, nhưng `server` có `add_header X-Frame-Options ...` -> Mất tính kế thừa, `server` thiếu `Content-Security-Policy` -> Không hợp lệ"""
    out = _make_parser_output([_http_block([
        _dir("add_header", ["Content-Security-Policy",
             '"default-src \'self\'; frame-ancestors \'self\';"', "always"]),
        _server_block([
            _dir("add_header", ["X-Frame-Options", "SAMEORIGIN"])
        ])
    ])])
    res = detector.scan(out)
    assert len(res) == 1


def test_level_server_valid_location_empty(detector):
    """Test 23: Cấu hình đúng ở `server`, `location` không có `add_header` nào -> Hợp lệ"""
    out = _make_parser_output([_http_block([
        _server_block([
            _dir("add_header", [
                 "Content-Security-Policy", '"default-src \'self\'; frame-ancestors \'self\';"', "always"]),
            _location_block(["/api"], [])
        ])
    ])])
    assert detector.scan(out) == []


def test_level_server_valid_location_override_other(detector):
    """Test 24: Cấu hình đúng ở `server`, `location` có `add_header X-XSS-Protection ...` -> Không hợp lệ ở `location` do mất kế thừa"""
    out = _make_parser_output([_http_block([
        _server_block([
            _dir("add_header", [
                 "Content-Security-Policy", '"default-src \'self\'; frame-ancestors \'self\';"', "always"]),
            _location_block(["/api"], [
                _dir("add_header", ["X-XSS-Protection", "1"])
            ])
        ])
    ])])
    res = detector.scan(out)
    assert len(res) == 1


def test_level_nested_location_override(detector):
    """Test 25: Nested location: `location` cha có CSP, `location` con có `add_header` khác -> Không hợp lệ ở `location` con"""
    out = _make_parser_output([_http_block([_server_block([
        _location_block(["/api"], [
            _dir("add_header", [
                 "Content-Security-Policy", '"default-src \'self\'; frame-ancestors \'self\';"', "always"]),
            _location_block(["/api/v1"], [
                _dir("add_header", ["X-Frame-Options", "DENY"])
            ])
        ])
    ])])])
    res = detector.scan(out)
    assert len(res) == 1


def test_level_multiple_servers(detector):
    """Test 26: Nhiều `server` block: một server có cấu hình chuẩn, một server khác thiếu hoàn toàn -> Vi phạm chỉ tính ở server thiếu"""
    out = _make_parser_output([_http_block([
        _server_block(
            [_dir("add_header", ["Content-Security-Policy", '"default-src \'self\'; frame-ancestors \'self\';"', "always"])]),
        _server_block([])
    ])])
    res = detector.scan(out)
    assert len(res) == 1


def test_level_server_override_missing_always(detector):
    """Test 27: Ghi đè ở `server` với CSP thiếu `always` trong khi `http` đã có đầy đủ -> Không hợp lệ tại `server`"""
    out = _make_parser_output([_http_block([
        _dir("add_header", ["Content-Security-Policy",
             '"default-src \'self\'; frame-ancestors \'self\';"', "always"]),
        _server_block([
            _dir("add_header", ["Content-Security-Policy",
                 '"default-src \'self\'; frame-ancestors \'self\';"'])
        ])
    ])])
    res = detector.scan(out)
    assert len(res) == 1


def test_level_server_missing_location_valid_location_missing(detector):
    """Test 28: Khối `server` thiếu, khối `location /` có cấu hình chuẩn, nhưng khối `location /api` không có gì -> Vi phạm hiển thị ở `server` / `location /api`"""
    out = _make_parser_output([_http_block([_server_block([
        _location_block(
            ["/"], [_dir("add_header", ["Content-Security-Policy", '"default-src \'self\'; frame-ancestors \'self\';"', "always"])]),
        _location_block(["/api"], [])
    ])])])
    res = detector.scan(out)
    assert len(res) >= 1

# --- Cấu hình đa tệp (Multi-file configurations) (10 Tests) ---


def test_multi_http_main_valid_child_inherited(detector):
    """Test 29: `nginx.conf` cấu hình chuẩn ở `http`, các file `conf.d/*.conf` kế thừa bình thường (không có `add_header` nào) -> Hợp lệ"""
    out = {
        "status": "ok", "errors": [], "config": [
            {"file": "/etc/nginx/nginx.conf", "status": "ok", "errors": [], "parsed": [
                _http_block(
                    [_dir("add_header", ["Content-Security-Policy", '"default-src \'self\'; frame-ancestors \'self\';"', "always"])])
            ]},
            {"file": "/etc/nginx/conf.d/app.conf", "status": "ok", "errors": [], "parsed": [
                _server_block([])
            ]}
        ]
    }
    assert detector.scan(out) == []


def test_multi_http_main_valid_child_override_other(detector):
    """Test 30: `nginx.conf` cấu hình chuẩn ở `http`, nhưng `conf.d/admin.conf` dùng một `add_header` khác gây mất kế thừa -> Vi phạm ở `admin.conf`"""
    out = {
        "status": "ok", "errors": [], "config": [
            {"file": "/etc/nginx/nginx.conf", "status": "ok", "errors": [], "parsed": [
                _http_block(
                    [_dir("add_header", ["Content-Security-Policy", '"default-src \'self\'; frame-ancestors \'self\';"', "always"])])
            ]},
            {"file": "/etc/nginx/conf.d/admin.conf", "status": "ok", "errors": [], "parsed": [
                _server_block(
                    [_dir("add_header", ["X-Frame-Options", "DENY"])])
            ]}
        ]
    }
    res = detector.scan(out)
    assert len(res) == 1
    assert res[0]["filepath"] == "/etc/nginx/conf.d/admin.conf"


def test_multi_main_empty_children_valid(detector):
    """Test 31: `nginx.conf` rỗng phần bảo mật, nhưng tất cả `conf.d/*.conf` đều định nghĩa CSP chuẩn ở cấp `server` -> Hợp lệ"""
    out = {
        "status": "ok", "errors": [], "config": [
            {"file": "/etc/nginx/nginx.conf", "status": "ok", "errors": [], "parsed": [
                _http_block([])
            ]},
            {"file": "/etc/nginx/conf.d/app.conf", "status": "ok", "errors": [], "parsed": [
                _server_block(
                    [_dir("add_header", ["Content-Security-Policy", '"default-src \'self\'; frame-ancestors \'self\';"', "always"])])
            ]}
        ]
    }
    assert detector.scan(out) == []


def test_multi_main_empty_one_child_missing(detector):
    """Test 32: `nginx.conf` rỗng, `admin.conf` có, `web.conf` thiếu hoàn toàn -> Vi phạm hiển thị ở `web.conf`"""
    out = {
        "status": "ok", "errors": [], "config": [
            {"file": "/etc/nginx/nginx.conf", "status": "ok", "errors": [], "parsed": [
                _http_block([])
            ]},
            {"file": "/etc/nginx/conf.d/admin.conf", "status": "ok", "errors": [], "parsed": [
                _server_block(
                    [_dir("add_header", ["Content-Security-Policy", '"default-src \'self\'; frame-ancestors \'self\';"', "always"])])
            ]},
            {"file": "/etc/nginx/conf.d/web.conf", "status": "ok", "errors": [], "parsed": [
                _server_block([])
            ]}
        ]
    }
    res = detector.scan(out)
    assert len(res) == 1
    assert res[0]["filepath"] == "/etc/nginx/conf.d/web.conf"


def test_multi_include_security_headers_server(detector):
    """Test 33: Cấu hình header được định nghĩa trong `security_headers.conf` và được `include` hợp lệ ở `server` -> Hợp lệ"""
    out = _make_parser_output([_http_block([
        _server_block([
            _dir("include", ["security_headers.conf"]),
            _dir("add_header", [
                 "Content-Security-Policy", '"default-src \'self\'; frame-ancestors \'self\';"', "always"])
        ])
    ])])
    assert detector.scan(out) == []


def test_multi_include_security_headers_location(detector):
    """Test 34: Lệnh `include security_headers.conf` ở trong `location` -> Hợp lệ cho riêng `location` đó"""
    out = _make_parser_output([_http_block([
        _server_block([
            _location_block(["/"], [
                _dir("include", ["security_headers.conf"]),
                _dir("add_header", [
                     "Content-Security-Policy", '"default-src \'self\'; frame-ancestors \'self\';"', "always"])
            ])
        ])
    ])])
    assert detector.scan(out) == []


def test_multi_include_missing_always(detector):
    """Test 35: File `security_headers.conf` được include nhưng thiếu tham số `always` -> Vi phạm trỏ vào file `security_headers.conf`"""
    out = {
        "status": "ok", "errors": [], "config": [
            {"file": "/etc/nginx/nginx.conf", "status": "ok", "errors": [], "parsed": [
                _http_block(
                    [_server_block([_dir("include", ["security.conf"])])])
            ]},
            {"file": "/etc/nginx/security.conf", "status": "ok", "errors": [], "parsed": [
                _dir("add_header", [
                     "Content-Security-Policy", '"default-src \'self\'; frame-ancestors \'self\';"'])
            ]}
        ]
    }
    res = detector.scan(out)
    assert len(res) == 1
    assert res[0]["filepath"] == "/etc/nginx/security.conf"


def test_multi_split_server_missing(detector):
    """Test 36: Một block `server` bị tách ra qua nhiều file `include`, cuối cùng cấu hình vẫn không chứa CSP -> Không hợp lệ"""
    out = _make_parser_output([_http_block([
        _server_block([_dir("include", ["server_parts.conf"])])
    ])])
    res = detector.scan(out)
    assert len(res) == 1


def test_multi_include_missing_file(detector):
    """Test 37: Dùng `include` để nạp tệp cấu hình nhưng tệp đó không tồn tại (AST rỗng phần includes) -> Coi như thiếu"""
    out = _make_parser_output([_http_block([
        _server_block([_dir("include", ["not_found.conf"])])
    ])])
    res = detector.scan(out)
    assert len(res) == 1


def test_multi_main_valid_child_server_override_other(detector):
    """Test 38: Cấu hình `http` ở file chính đủ chuẩn, nhưng file phụ chứa khối `server` khai báo `add_header` khác làm mất kế thừa -> Vi phạm tại file phụ"""
    out = {
        "status": "ok", "errors": [], "config": [
            {"file": "/etc/nginx/nginx.conf", "status": "ok", "errors": [], "parsed": [
                _http_block(
                    [_dir("add_header", ["Content-Security-Policy", '"default-src \'self\'; frame-ancestors \'self\';"', "always"])])
            ]},
            {"file": "/etc/nginx/conf.d/app.conf", "status": "ok", "errors": [], "parsed": [
                _server_block([_dir("add_header", ["X-XSS-Protection", "1"])])
            ]}
        ]
    }
    res = detector.scan(out)
    assert len(res) == 1
    assert res[0]["filepath"] == "/etc/nginx/conf.d/app.conf"


# --- Cấu trúc AST, Remediation Payload & Edge Cases (7 Tests) ---

def test_ast_malformed(detector):
    """Test 39: Lệnh `add_header` có cấu trúc AST sai hoặc chứa quá nhiều tham số -> Xử lý báo lỗi/tính là thiếu"""
    out = _make_parser_output([_http_block([_server_block([
        {"directive": "add_header"}
    ])])])
    res = detector.scan(out)
    assert len(res) == 1


def test_payload_add_correct_block(detector):
    """Test 40: Payload `add` chèn chỉ thị `add_header Content-Security-Policy "default-src 'self'; frame-ancestors 'self'; form-action 'self';" always;` vào khối `server` (hoặc `http`) khi phát hiện vi phạm do thiếu hoàn toàn"""
    out = _make_parser_output([_http_block([_server_block([])])])
    res = detector.scan(out)
    assert res[0]["remediations"][0]["action"] == "add"
    assert res[0]["remediations"][0]["directive"] == "add_header"
    assert res[0]["remediations"][0]["args"] == [
        "Content-Security-Policy", '"default-src \'self\'; frame-ancestors \'self\'; form-action \'self\';"', "always"]


def test_payload_replace_missing_always(detector):
    """Test 41: Payload `replace` thay thế chính xác chỉ thị hiện có nếu nó đang bị thiếu từ khóa `always` hoặc thiếu `frame-ancestors`"""
    out = _make_parser_output([_http_block([_server_block([
        _dir("add_header", ["Content-Security-Policy",
             '"default-src \'self\';"'])
    ])])])
    res = detector.scan(out)
    assert res[0]["remediations"][0]["action"] == "replace"
    assert "always" in res[0]["remediations"][0]["args"]
    assert "frame-ancestors" in res[0]["remediations"][0]["args"][1]


def test_payload_replace_unsafe_inline(detector):
    """Test 42: Payload `replace` loại bỏ các tham số rủi ro như `unsafe-inline` khỏi CSP hiện tại"""
    out = _make_parser_output([_http_block([_server_block([
        _dir("add_header", ["Content-Security-Policy",
             '"default-src \'self\'; script-src \'unsafe-inline\'; frame-ancestors \'self\';"', "always"])
    ])])])
    res = detector.scan(out)
    assert res[0]["remediations"][0]["action"] == "replace"
    assert "unsafe-inline" not in res[0]["remediations"][0]["args"][1]


def test_payload_exact_path_correct(detector):
    """Test 43: Payload đảm bảo `exact_path` mang giá trị array index chính xác để Auto-Remediation áp dụng đúng dòng cấu hình"""
    out = _make_parser_output([_http_block([_server_block([])])])
    res = detector.scan(out)
    assert isinstance(res[0]["remediations"][0]["exact_path"], list)
    assert res[0]["remediations"][0]["exact_path"][-1] == "block"


def test_edge_multiple_same_headers(detector):
    """Test 44: Nếu xuất hiện nhiều chỉ thị `Content-Security-Policy` trong cùng một block, kiểm tra khả năng xử lý trùng lặp và xác thực đúng giá trị hợp lệ cuối cùng"""
    out = _make_parser_output([_http_block([_server_block([
        _dir("add_header", ["Content-Security-Policy",
             '"default-src \'self\';"']),
        _dir("add_header", ["Content-Security-Policy",
             '"default-src \'self\'; frame-ancestors \'self\';"', "always"])
    ])])])
    assert detector.scan(out) == []


def test_edge_case_insensitive(detector):
    """Test 45: Xử lý không phân biệt hoa thường tên header: `CONTENT-SECURITY-POLICY`"""
    out = _make_parser_output([_http_block([_server_block([
        _dir("add_header", ["CONTENT-SECURITY-POLICY",
             '"default-src \'self\'; frame-ancestors \'self\';"', "always"])
    ])])])
    assert detector.scan(out) == []
