import pytest
from core.scannerEng.recommendations.detector_531 import Detector531


def _dir(directive: str, args: list = None, block: list = None) -> dict:
    d = {"directive": directive, "line": 1, "args": args or []}
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
    return Detector531()

# =====================================================================
# 1. Kiểm tra Siêu dữ liệu (Metadata Sanity Checks) - 3 Test Cases
# =====================================================================


def test_metadata_id(detector):
    """Test 1: ID phải là '5.3.1'"""
    assert detector.id == "5.3.1"


def test_metadata_title(detector):
    """Test 2: Tiêu đề phải đúng"""
    assert detector.title == "Đảm bảo header X-Content-Type-Options được cấu hình và kích hoạt"


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
    """Test 4: Có `add_header X-Content-Type-Options "nosniff" always;` nằm trong block `server`"""
    out = _make_parser_output([_http_block([_server_block([
        _dir("add_header", ["X-Content-Type-Options", '"nosniff"', "always"])
    ])])])
    assert detector.scan(out) == []


def test_valid_server_block_no_quotes(detector):
    """Test 5: Có `add_header X-Content-Type-Options nosniff always;` (không có ngoặc kép) nằm trong block `server`"""
    out = _make_parser_output([_http_block([_server_block([
        _dir("add_header", ["X-Content-Type-Options", "nosniff", "always"])
    ])])])
    assert detector.scan(out) == []


def test_valid_http_block(detector):
    """Test 6: Cấu hình nằm trong block `http` và áp dụng hợp lệ cho mọi server con"""
    out = _make_parser_output([_http_block([
        _dir("add_header", ["X-Content-Type-Options", '"nosniff"', "always"]),
        _server_block([])
    ])])
    assert detector.scan(out) == []


def test_valid_both_blocks(detector):
    """Test 7: Cấu hình hợp lệ xuất hiện ở cả `http` và `server` (ghi đè hợp lệ)"""
    out = _make_parser_output([_http_block([
        _dir("add_header", ["X-Content-Type-Options", '"nosniff"', "always"]),
        _server_block([
            _dir("add_header", [
                 "X-Content-Type-Options", '"nosniff"', "always"])
        ])
    ])])
    assert detector.scan(out) == []


def test_valid_location_block(detector):
    """Test 8: Cấu hình nằm trong block `location` hợp lệ"""
    out = _make_parser_output([_http_block([_server_block([
        _location_block(["/api"], [
            _dir("add_header", [
                 "X-Content-Type-Options", '"nosniff"', "always"])
        ])
    ])])])
    assert detector.scan(out) == []

# --- Không hợp lệ - Thiếu hoặc sai cấu hình (Misconfigured/Missing) (10 Tests) ---


def test_invalid_completely_missing(detector):
    """Test 9: Hoàn toàn không có chỉ thị `add_header X-Content-Type-Options` trong toàn bộ cấu hình"""
    out = _make_parser_output([_http_block([_server_block([])])])
    res = detector.scan(out)
    assert len(res) == 1


def test_invalid_missing_always(detector):
    """Test 10: Có header nhưng thiếu tham số `always`"""
    out = _make_parser_output([_http_block([_server_block([
        _dir("add_header", ["X-Content-Type-Options", '"nosniff"'])
    ])])])
    res = detector.scan(out)
    assert len(res) == 1


def test_invalid_wrong_value_sniff(detector):
    """Test 11: Có header với tham số `always` nhưng sai giá trị `nosniff`, ví dụ `sniff`"""
    out = _make_parser_output([_http_block([_server_block([
        _dir("add_header", ["X-Content-Type-Options", '"sniff"', "always"])
    ])])])
    res = detector.scan(out)
    assert len(res) == 1


def test_invalid_value_none(detector):
    """Test 12: Sai giá trị `none`"""
    out = _make_parser_output([_http_block([_server_block([
        _dir("add_header", ["X-Content-Type-Options", '"none"', "always"])
    ])])])
    res = detector.scan(out)
    assert len(res) == 1


def test_invalid_typo_header(detector):
    """Test 13: Tên header viết sai chính tả dẫn đến thiếu cấu hình hợp lệ"""
    out = _make_parser_output([_http_block([_server_block([
        _dir("add_header", ["X-Content-Type-Option", '"nosniff"', "always"])
    ])])])
    res = detector.scan(out)
    assert len(res) == 1


def test_invalid_commented_out(detector):
    """Test 14: Lệnh `add_header` bị comment đi trong cấu hình (AST coi như thiếu)"""
    out = _make_parser_output([_http_block([_server_block([
        _dir("#", ["add_header X-Content-Type-Options \"nosniff\" always;"])
    ])])])
    res = detector.scan(out)
    assert len(res) == 1


def test_invalid_wrong_last_param(detector):
    """Test 15: Cấu hình tham số sau cùng sai `off` thay vì `always`"""
    out = _make_parser_output([_http_block([_server_block([
        _dir("add_header", ["X-Content-Type-Options", '"nosniff"', "off"])
    ])])])
    res = detector.scan(out)
    assert len(res) == 1


def test_invalid_other_headers_only(detector):
    """Test 16: Có nhiều header `add_header` khác nhau trong cấu hình nhưng không có `X-Content-Type-Options`"""
    out = _make_parser_output([_http_block([_server_block([
        _dir("add_header", ["X-Frame-Options", "SAMEORIGIN"])
    ])])])
    res = detector.scan(out)
    assert len(res) == 1


def test_invalid_http_valid_server_overrides_other(detector):
    """Test 17: Header hợp lệ ở `http` nhưng ở `server` bị ghi đè bằng một `add_header` khác (tạo ra việc mất kế thừa) nên `server` thiếu header này"""
    out = _make_parser_output([_http_block([
        _dir("add_header", ["X-Content-Type-Options", '"nosniff"', "always"]),
        _server_block([
            _dir("add_header", ["X-XSS-Protection", '"1; mode=block"'])
        ])
    ])])
    res = detector.scan(out)
    assert len(res) == 1


def test_invalid_missing_http_and_server(detector):
    """Test 18: Thiếu `X-Content-Type-Options` ở cả khối `http` và tất cả các khối `server`"""
    out = _make_parser_output(
        [_http_block([_server_block([_location_block(["/"], [])])])])
    res = detector.scan(out)
    assert len(res) == 1

# --- Kiểm tra theo cấp độ (Block Levels: http, server, location) (10 Tests) ---


def test_level_missing_http_server_payload(detector):
    """Test 19: Thiếu ở `http` và `server` -> Sinh payload `add`"""
    out = _make_parser_output([_http_block([_server_block([])])])
    res = detector.scan(out)
    assert len(res) == 1
    assert res[0]["remediations"][0]["action"] == "add"


def test_level_server_wrong_value_payload(detector):
    """Test 20: Cấu hình có `X-Content-Type-Options` ở `server` nhưng sai tham số -> Trả về payload sửa (`replace`)"""
    out = _make_parser_output([_http_block([_server_block([
        _dir("add_header", ["X-Content-Type-Options", '"sniff"', "always"])
    ])])])
    res = detector.scan(out)
    assert len(res) == 1
    assert res[0]["remediations"][0]["action"] == "replace"


def test_level_http_valid_server_empty(detector):
    """Test 21: Cấu hình đúng ở `http`, không có `add_header` nào khác ở `server` -> Hợp lệ do kế thừa"""
    out = _make_parser_output([_http_block([
        _dir("add_header", ["X-Content-Type-Options", '"nosniff"', "always"]),
        _server_block([])
    ])])
    assert detector.scan(out) == []


def test_level_http_valid_server_override_other(detector):
    """Test 22: Cấu hình đúng ở `http`, nhưng `server` có `add_header X-Frame-Options ...` -> Mất tính kế thừa, `server` thiếu `X-Content-Type-Options` -> Không hợp lệ"""
    out = _make_parser_output([_http_block([
        _dir("add_header", ["X-Content-Type-Options", '"nosniff"', "always"]),
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
                 "X-Content-Type-Options", '"nosniff"', "always"]),
            _location_block(["/api"], [])
        ])
    ])])
    assert detector.scan(out) == []


def test_level_server_valid_location_override_other(detector):
    """Test 24: Cấu hình đúng ở `server`, `location` có `add_header X-XSS-Protection ...` -> Không hợp lệ ở `location` do mất kế thừa"""
    out = _make_parser_output([_http_block([
        _server_block([
            _dir("add_header", [
                 "X-Content-Type-Options", '"nosniff"', "always"]),
            _location_block(["/api"], [
                _dir("add_header", ["X-XSS-Protection", "1"])
            ])
        ])
    ])])
    res = detector.scan(out)
    assert len(res) == 1


def test_level_nested_location_override(detector):
    """Test 25: Nested location: `location` cha có `X-Content-Type-Options`, `location` con có `add_header` khác -> Không hợp lệ ở `location` con"""
    out = _make_parser_output([_http_block([_server_block([
        _location_block(["/api"], [
            _dir("add_header", [
                 "X-Content-Type-Options", '"nosniff"', "always"]),
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
            [_dir("add_header", ["X-Content-Type-Options", '"nosniff"', "always"])]),
        _server_block([])
    ])])
    res = detector.scan(out)
    assert len(res) == 1


def test_level_server_override_missing_always(detector):
    """Test 27: Ghi đè ở `server` với `add_header X-Content-Type-Options "nosniff";` (thiếu always) trong khi `http` đã có đầy đủ -> Không hợp lệ tại `server`"""
    out = _make_parser_output([_http_block([
        _dir("add_header", ["X-Content-Type-Options", '"nosniff"', "always"]),
        _server_block([
            _dir("add_header", ["X-Content-Type-Options", '"nosniff"'])
        ])
    ])])
    res = detector.scan(out)
    assert len(res) == 1


def test_level_server_missing_location_valid_location_missing(detector):
    """Test 28: Khối `server` thiếu, khối `location /` có cấu hình chuẩn, nhưng khối `location /api` không có gì -> Vi phạm hiển thị ở `server` / `location /api`"""
    out = _make_parser_output([_http_block([_server_block([
        _location_block(
            ["/"], [_dir("add_header", ["X-Content-Type-Options", '"nosniff"', "always"])]),
        _location_block(["/api"], [])
    ])])])
    res = detector.scan(out)
    assert len(res) >= 1

# --- Cấu hình đa tệp (Multi-file configurations) (10 Tests) ---


def test_multi_http_main_valid_child_inherited(detector):
    """Test 29: `nginx.conf` cấu hình chuẩn ở `http`, các file `conf.d/*.conf` kế thừa bình thường -> Hợp lệ"""
    out = {
        "status": "ok", "errors": [], "config": [
            {"file": "/etc/nginx/nginx.conf", "status": "ok", "errors": [], "parsed": [
                _http_block(
                    [_dir("add_header", ["X-Content-Type-Options", '"nosniff"', "always"])])
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
                    [_dir("add_header", ["X-Content-Type-Options", '"nosniff"', "always"])])
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
    """Test 31: `nginx.conf` rỗng phần bảo mật, nhưng tất cả `conf.d/*.conf` đều định nghĩa chuẩn ở cấp `server` -> Hợp lệ"""
    out = {
        "status": "ok", "errors": [], "config": [
            {"file": "/etc/nginx/nginx.conf", "status": "ok", "errors": [], "parsed": [
                _http_block([])
            ]},
            {"file": "/etc/nginx/conf.d/app.conf", "status": "ok", "errors": [], "parsed": [
                _server_block(
                    [_dir("add_header", ["X-Content-Type-Options", '"nosniff"', "always"])])
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
                    [_dir("add_header", ["X-Content-Type-Options", '"nosniff"', "always"])])
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
                 "X-Content-Type-Options", '"nosniff"', "always"])
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
                     "X-Content-Type-Options", '"nosniff"', "always"])
            ])
        ])
    ])])
    assert detector.scan(out) == []


def test_multi_include_missing_always(detector):
    """Test 35: File `security_headers.conf` được include nhưng thiếu tham số `always` cho `X-Content-Type-Options` -> Vi phạm trỏ vào file `security_headers.conf`"""
    out = {
        "status": "ok", "errors": [], "config": [
            {"file": "/etc/nginx/nginx.conf", "status": "ok", "errors": [], "parsed": [
                _http_block(
                    [_server_block([_dir("include", ["security.conf"])])])
            ]},
            {"file": "/etc/nginx/security.conf", "status": "ok", "errors": [], "parsed": [
                _dir("add_header", ["X-Content-Type-Options", '"nosniff"'])
            ]}
        ]
    }
    res = detector.scan(out)
    assert len(res) == 1
    assert res[0]["filepath"] == "/etc/nginx/security.conf"


def test_multi_split_server_missing(detector):
    """Test 36: Một block `server` bị tách ra qua nhiều file `include`, cuối cùng cấu hình vẫn không chứa header `X-Content-Type-Options` -> Không hợp lệ"""
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
                    [_dir("add_header", ["X-Content-Type-Options", '"nosniff"', "always"])])
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
        {"directive": "add_header", "line": 1}
    ])])])
    res = detector.scan(out)
    assert len(res) == 1


def test_payload_add_correct_block(detector):
    """Test 40: Payload `add` chèn chỉ thị `add_header X-Content-Type-Options "nosniff" always;` vào khối `server` khi phát hiện vi phạm do thiếu hoàn toàn"""
    out = _make_parser_output([_http_block([_server_block([])])])
    res = detector.scan(out)
    assert res[0]["remediations"][0]["action"] == "add"
    assert res[0]["remediations"][0]["directive"] == "add_header"
    assert res[0]["remediations"][0]["args"] == [
        "X-Content-Type-Options", '"nosniff"', "always"]


def test_payload_replace_missing_always(detector):
    """Test 41: Payload `replace` thay thế chính xác chỉ thị hiện có nếu nó đang bị thiếu từ khóa `always`"""
    out = _make_parser_output([_http_block([_server_block([
        _dir("add_header", ["X-Content-Type-Options", '"nosniff"'])
    ])])])
    res = detector.scan(out)
    assert res[0]["remediations"][0]["action"] == "replace"
    assert res[0]["remediations"][0]["args"] == [
        "X-Content-Type-Options", '"nosniff"', "always"]


def test_payload_replace_wrong_value(detector):
    """Test 42: Payload `replace` sửa tham số bị sai"""
    out = _make_parser_output([_http_block([_server_block([
        _dir("add_header", ["X-Content-Type-Options", "sniff", "always"])
    ])])])
    res = detector.scan(out)
    assert res[0]["remediations"][0]["action"] == "replace"


def test_payload_exact_path_correct(detector):
    """Test 43: Payload đảm bảo `exact_path` mang giá trị array index chính xác để Auto-Remediation áp dụng đúng dòng cấu hình"""
    out = _make_parser_output([_http_block([_server_block([])])])
    res = detector.scan(out)
    assert isinstance(res[0]["remediations"][0]["exact_path"], list)
    assert res[0]["remediations"][0]["exact_path"][-1] == "block"


def test_edge_multiple_same_headers(detector):
    """Test 44: Nếu xuất hiện nhiều chỉ thị `add_header X-Content-Type-Options` trong cùng một block, kiểm tra khả năng xử lý trùng lặp"""
    out = _make_parser_output([_http_block([_server_block([
        _dir("add_header", ["X-Content-Type-Options", '"sniff"']),
        _dir("add_header", ["X-Content-Type-Options", '"nosniff"', "always"])
    ])])])
    assert detector.scan(out) == []


def test_edge_case_insensitive(detector):
    """Test 45: Xử lý không phân biệt hoa thường tên header: `X-CONTENT-TYPE-OPTIONS`"""
    out = _make_parser_output([_http_block([_server_block([
        _dir("add_header", ["X-CONTENT-TYPE-OPTIONS", '"nosniff"', "always"])
    ])])])
    assert detector.scan(out) == []
