import pytest
from core.scannerEng.recommendations.detector_511 import Detector511


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


def _make_parser_output(parsed_directives: list, file: str = "/etc/nginx/nginx.conf") -> dict:
    return {
        "status": "ok",
        "errors": [],
        "config": [
            {
                "file": file,
                "status": "ok",
                "errors": [],
                "parsed": parsed_directives
            }
        ]
    }


@pytest.fixture
def detector():
    return Detector511()

# =====================================================================
# 1. Kiểm tra Siêu dữ liệu (Metadata Sanity Checks) - 3 Test Cases
# =====================================================================


def test_metadata_id(detector):
    """Test 1: ID phải là '5.1.1'"""
    assert detector.id == "5.1.1"


def test_metadata_title(detector):
    """Test 2: Tiêu đề phải đúng"""
    assert detector.title == "Đảm bảo các bộ lọc allow và deny giới hạn truy cập từ các địa chỉ IP cụ thể"


def test_metadata_attributes(detector):
    """Test 3: Thuộc tính bắt buộc"""
    assert hasattr(detector, "description")
    assert hasattr(detector, "audit_procedure")
    assert hasattr(detector, "impact")
    assert hasattr(detector, "remediation")

# =====================================================================
# 2. Kiểm thử hàm scan() - 42 Test Cases
# =====================================================================

# --- Hợp lệ - Có cấu hình allow/deny chuẩn (Valid IP Filtering) ---


def test_valid_allow_deny_location(detector):
    """Test 4: Có `allow [IP];` và theo sau là `deny all;` trong cùng một khối `location`."""
    out = _make_parser_output([_http_block([_server_block([
        _location_block(["/admin"], [
            _dir("allow", ["192.168.1.0/24"]),
            _dir("deny", ["all"])
        ])
    ])])])
    assert detector.scan(out) == []


def test_valid_multiple_allow_deny(detector):
    """Test 5: Có nhiều chỉ thị `allow` và kết thúc bằng `deny all;`."""
    out = _make_parser_output([_http_block([_server_block([
        _location_block(["/api"], [
            _dir("allow", ["10.0.0.1"]),
            _dir("allow", ["2001:db8::/32"]),
            _dir("deny", ["all"])
        ])
    ])])])
    assert detector.scan(out) == []


def test_valid_allow_deny_server(detector):
    """Test 6: Cấu hình `allow` và `deny all;` hợp lệ ở cấp độ khối `server`."""
    out = _make_parser_output([_http_block([_server_block([
        _dir("allow", ["10.0.0.0/8"]),
        _dir("deny", ["all"]),
        _location_block(["/"], [])
    ])])])
    assert detector.scan(out) == []


def test_valid_allow_deny_http(detector):
    """Test 7: Cấu hình `allow` và `deny all;` hợp lệ ở cấp độ khối `http`."""
    out = _make_parser_output([_http_block([
        _dir("allow", ["192.168.1.100"]),
        _dir("deny", ["all"]),
        _server_block([])
    ])])
    assert detector.scan(out) == []


def test_valid_multiple_locations_protected(detector):
    """Test 8: Có nhiều khối `location` được bảo vệ đầy đủ."""
    out = _make_parser_output([_http_block([_server_block([
        _location_block(
            ["/admin"], [_dir("allow", ["10.0.0.1"]), _dir("deny", ["all"])]),
        _location_block(
            ["/api"], [_dir("allow", ["10.0.0.2"]), _dir("deny", ["all"])])
    ])])])
    assert detector.scan(out) == []

# --- Không hợp lệ - Cấu hình thiếu an toàn (Misconfigured/Missing deny all) ---


def test_invalid_no_allow_deny(detector):
    """Test 9: Hoàn toàn không có chỉ thị `allow` hay `deny`."""
    out = _make_parser_output([_http_block([_server_block([
        _location_block(["/"], [])
    ])])])
    assert detector.scan(out) == []


def test_invalid_allow_missing_deny(detector):
    """Test 10: Có `allow` nhưng lại thiếu chốt chặn `deny all;` ở cuối khối."""
    out = _make_parser_output([_http_block([_server_block([
        _location_block(["/admin"], [
            _dir("allow", ["192.168.1.0/24"])
        ])
    ])])])
    res = detector.scan(out)
    assert len(res) == 1
    assert res[0]["remediations"][0]["action"] == "add"


def test_invalid_deny_before_allow(detector):
    """Test 11: Chỉ thị `deny all;` được đặt TRƯỚC `allow`."""
    out = _make_parser_output([_http_block([_server_block([
        _location_block(["/admin"], [
            _dir("deny", ["all"]),
            _dir("allow", ["192.168.1.0/24"])
        ])
    ])])])
    res = detector.scan(out)
    assert len(res) == 1


def test_invalid_deny_specific_only(detector):
    """Test 12: Có `allow` nhưng chỉ dùng `deny [IP_khác];` cụ thể mà không có `deny all;`."""
    out = _make_parser_output([_http_block([_server_block([
        _location_block(["/admin"], [
            _dir("allow", ["192.168.1.0/24"]),
            _dir("deny", ["10.0.0.1"])
        ])
    ])])])
    res = detector.scan(out)
    assert len(res) == 1


def test_invalid_allow_all(detector):
    """Test 13: Sử dụng chỉ thị `allow all;`."""
    out = _make_parser_output([_http_block([_server_block([
        _location_block(["/public"], [
            _dir("allow", ["all"]),
            _dir("deny", ["all"])
        ])
    ])])])
    res = detector.scan(out)
    assert len(res) == 1


def test_invalid_deny_all_different_block(detector):
    """Test 14: Có `deny all;` nhưng nằm ở khác block so với `allow` và không được kế thừa đúng cách."""
    out = _make_parser_output([_http_block([_server_block([
        _location_block(["/a"], [_dir("allow", ["1.1.1.1"])]),
        _location_block(["/b"], [_dir("deny", ["all"])])
    ])])])
    res = detector.scan(out)
    assert len(res) == 1


def test_invalid_sensitive_location_no_restriction(detector):
    """Test 15: Có cấu hình location nhạy cảm (/admin) nhưng không hề có giới hạn IP nào.
       Assume flags if allow is used improperly or no restriction is on admin.
    """
    out = _make_parser_output([_http_block([_server_block([
        _location_block(["/admin"], [_dir("allow", ["1.1.1.1"])])
    ])])])
    res = detector.scan(out)
    assert len(res) == 1


def test_invalid_allow_no_args(detector):
    """Test 16: Chỉ thị `allow` không có tham số (thiếu IP)."""
    out = _make_parser_output([_http_block([_server_block([
        _location_block(["/admin"], [
            _dir("allow", []),
            _dir("deny", ["all"])
        ])
    ])])])
    res = detector.scan(out)
    assert len(res) == 1


def test_invalid_commented_deny_all(detector):
    """Test 17: Chỉ thị `deny all;` bị comment đi (Crossplane bỏ qua dẫn đến bị coi là thiếu)."""
    out = _make_parser_output([_http_block([_server_block([
        _location_block(["/admin"], [
            _dir("allow", ["10.0.0.1"])
        ])
    ])])])
    res = detector.scan(out)
    assert len(res) == 1


def test_invalid_http_allow_overridden_by_server_allow_all(detector):
    """Test 18: Cấu hình `allow` / `deny all;` cấp độ `http` nhưng bị `allow all;` ghi đè hoàn toàn ở cấp độ `server`."""
    out = _make_parser_output([_http_block([
        _dir("allow", ["10.0.0.1"]),
        _dir("deny", ["all"]),
        _server_block([
            _dir("allow", ["all"])
        ])
    ])])
    res = detector.scan(out)
    assert len(res) == 1

# --- Kiểm tra theo cấp độ (Block Levels: http, server, location) ---


def test_level_http_valid(detector):
    """Test 19: `allow`/`deny` định nghĩa ở `http`, không bị khối con nào ghi đè -> Hợp lệ toàn cục."""
    out = _make_parser_output([_http_block([
        _dir("allow", ["10.0.0.1"]),
        _dir("deny", ["all"]),
        _server_block([_location_block(["/"], [])])
    ])])
    assert detector.scan(out) == []


def test_level_http_overridden_invalid_server(detector):
    """Test 20: `allow`/`deny` ở `http`, nhưng bị `allow all;` ở một khối `server` ghi đè -> Không hợp lệ tại `server` đó."""
    out = _make_parser_output([_http_block([
        _dir("allow", ["10.0.0.1"]),
        _dir("deny", ["all"]),
        _server_block([_dir("allow", ["all"])])
    ])])
    res = detector.scan(out)
    assert len(res) == 1


def test_level_server_valid(detector):
    """Test 21: `allow`/`deny` ở `server`, không bị khối `location` con ghi đè -> Hợp lệ."""
    out = _make_parser_output([_http_block([
        _server_block([
            _dir("allow", ["10.0.0.1"]),
            _dir("deny", ["all"]),
            _location_block(["/"], [])
        ])
    ])])
    assert detector.scan(out) == []


def test_level_server_overridden_invalid_location(detector):
    """Test 22: `allow`/`deny` ở `server`, nhưng bị `allow all;` ở khối `location` ghi đè -> Không hợp lệ tại `location`."""
    out = _make_parser_output([_http_block([
        _server_block([
            _dir("allow", ["10.0.0.1"]),
            _dir("deny", ["all"]),
            _location_block(["/"], [_dir("allow", ["all"])])
        ])
    ])])
    res = detector.scan(out)
    assert len(res) == 1


def test_level_location_only(detector):
    """Test 23: Không có giới hạn ở `http` và `server`, chỉ cấu hình đúng ở một `location` duy nhất -> Hợp lệ cho riêng location đó."""
    out = _make_parser_output([_http_block([_server_block([
        _location_block(["/public"], []),
        _location_block(["/admin"], [
            _dir("allow", ["10.0.0.1"]),
            _dir("deny", ["all"])
        ])
    ])])])
    assert detector.scan(out) == []


def test_level_nested_location_inherited(detector):
    """Test 24: Location lồng nhau (nested location): location cha có `allow`/`deny all;`, location con không khai báo lại (được kế thừa) -> Hợp lệ."""
    out = _make_parser_output([_http_block([_server_block([
        _location_block(["/api"], [
            _dir("allow", ["10.0.0.1"]),
            _dir("deny", ["all"]),
            _location_block(["/api/v1"], [])
        ])
    ])])])
    assert detector.scan(out) == []


def test_level_nested_location_override_invalid(detector):
    """Test 25: Location lồng nhau: location cha có `allow`/`deny all;`, location con lại khai báo `allow all;` -> Không hợp lệ tại location con."""
    out = _make_parser_output([_http_block([_server_block([
        _location_block(["/api"], [
            _dir("allow", ["10.0.0.1"]),
            _dir("deny", ["all"]),
            _location_block(["/api/v1"], [_dir("allow", ["all"])])
        ])
    ])])])
    res = detector.scan(out)
    assert len(res) == 1


def test_level_multiple_servers_one_invalid(detector):
    """Test 26: Nhiều `server` block: một server cấu hình allow/deny đúng chuẩn, một server khác mở toang -> Vi phạm ở server mở toang."""
    out = _make_parser_output([_http_block([
        _server_block([_dir("allow", ["10.0.0.1"]), _dir("deny", ["all"])]),
        _server_block([_dir("allow", ["10.0.0.2"])])
    ])])
    res = detector.scan(out)
    assert len(res) == 1


def test_level_override_missing_deny(detector):
    """Test 27: Ghi đè chỉ thị `allow` ở scope nhỏ hơn nhưng quên chốt bằng `deny all;` -> Không hợp lệ."""
    out = _make_parser_output([_http_block([
        _dir("allow", ["10.0.0.1"]),
        _dir("deny", ["all"]),
        _server_block([
            _dir("allow", ["10.0.0.2"])
        ])
    ])])
    res = detector.scan(out)
    assert len(res) == 1


def test_level_override_deny_specific(detector):
    """Test 28: Ghi đè `deny all;` bằng một địa chỉ IP cụ thể ở scope nhỏ hơn -> Không hợp lệ vì thiếu chốt chặn deny all."""
    out = _make_parser_output([_http_block([
        _dir("allow", ["10.0.0.1"]),
        _dir("deny", ["all"]),
        _server_block([
            _dir("allow", ["10.0.0.1"]),
            _dir("deny", ["192.168.1.1"])
        ])
    ])])
    res = detector.scan(out)
    assert len(res) == 1

# --- Cấu hình đa tệp (Multi-file configurations) ---


def test_multi_main_valid_child_inherited(detector):
    """Test 29: `nginx.conf` có `allow`/`deny all;`, các file `conf.d/*.conf` kế thừa bình thường -> Hợp lệ."""
    out = {
        "status": "ok",
        "errors": [],
        "config": [
            {
                "file": "/etc/nginx/nginx.conf",
                "status": "ok",
                "errors": [],
                "parsed": [_http_block([
                    _dir("allow", ["10.0.0.1"]),
                    _dir("deny", ["all"])
                ])]
            },
            {
                "file": "/etc/nginx/conf.d/app.conf",
                "status": "ok",
                "errors": [],
                "parsed": [_server_block([])]
            }
        ]
    }
    assert detector.scan(out) == []


def test_multi_main_open_child_valid(detector):
    """Test 30: `nginx.conf` mở, nhưng tất cả các file cấu hình server trong `conf.d/*.conf` đều bảo vệ nghiêm ngặt bằng allow/deny -> Hợp lệ."""
    out = {
        "status": "ok",
        "errors": [],
        "config": [
            {
                "file": "/etc/nginx/nginx.conf",
                "status": "ok",
                "errors": [],
                "parsed": [_http_block([])]
            },
            {
                "file": "/etc/nginx/conf.d/app.conf",
                "status": "ok",
                "errors": [],
                "parsed": [_server_block([_dir("allow", ["10.0.0.1"]), _dir("deny", ["all"])])]
            }
        ]
    }
    assert detector.scan(out) == []


def test_multi_child_invalid(detector):
    """Test 31: `nginx.conf` rỗng, `conf.d/admin.conf` cấu hình đúng, nhưng `conf.d/web.conf` lạm dụng `allow all;` -> Vi phạm hiển thị ở `web.conf`."""
    out = {
        "status": "ok",
        "errors": [],
        "config": [
            {
                "file": "/etc/nginx/nginx.conf",
                "status": "ok",
                "errors": [],
                "parsed": [_http_block([])]
            },
            {
                "file": "/etc/nginx/conf.d/web.conf",
                "status": "ok",
                "errors": [],
                "parsed": [_server_block([_dir("allow", ["all"])])]
            }
        ]
    }
    res = detector.scan(out)
    assert len(res) == 1
    assert res[0]["file"] == "/etc/nginx/conf.d/web.conf"


def test_multi_allow_main_deny_child(detector):
    """Test 32: Chỉ thị `allow` nằm ở file chính, `deny all;` nằm ở file phụ (trong cùng block thông qua lệnh include) -> Hợp lệ."""
    out = _make_parser_output([_http_block([
        _dir("allow", ["10.0.0.1"]),
        _dir("deny", ["all"])
    ])])
    assert detector.scan(out) == []


def test_multi_child_missing_deny(detector):
    """Test 33: Chỉ thị `allow` nằm ở file phụ, nhưng thiếu `deny all;` -> Vi phạm hiển thị tại file phụ."""
    out = {
        "status": "ok",
        "errors": [],
        "config": [
            {
                "file": "/etc/nginx/nginx.conf",
                "status": "ok",
                "errors": [],
                "parsed": [_http_block([])]
            },
            {
                "file": "/etc/nginx/conf.d/app.conf",
                "status": "ok",
                "errors": [],
                "parsed": [_server_block([_dir("allow", ["10.0.0.1"])])]
            }
        ]
    }
    res = detector.scan(out)
    assert len(res) == 1
    assert res[0]["file"] == "/etc/nginx/conf.d/app.conf"


def test_multi_include_list_missing_deny(detector):
    """Test 34: File chính include file danh sách IP nhưng quên không có `deny all;` đi kèm ở cuối."""
    out = _make_parser_output([_http_block([
        _dir("allow", ["10.0.0.1"])
    ])])
    res = detector.scan(out)
    assert len(res) == 1


def test_multi_child_allow_all_infects(detector):
    """Test 35: File `conf.d/default.conf` chứa `allow all;` ở cấp `server` làm lây nhiễm rủi ro."""
    out = {
        "status": "ok",
        "errors": [],
        "config": [
            {
                "file": "/etc/nginx/nginx.conf",
                "status": "ok",
                "errors": [],
                "parsed": [_http_block([])]
            },
            {
                "file": "/etc/nginx/conf.d/app.conf",
                "status": "ok",
                "errors": [],
                "parsed": [_server_block([_dir("allow", ["all"])])]
            }
        ]
    }
    res = detector.scan(out)
    assert len(res) == 1


def test_multi_server_across_includes(detector):
    """Test 36: Một block `server` trải dài qua nhiều file include có tổng hợp đủ cấu hình `allow`/`deny all;` -> Hợp lệ."""
    out = _make_parser_output([_http_block([_server_block([
        _dir("allow", ["10.0.0.1"]),
        _dir("deny", ["all"])
    ])])])
    assert detector.scan(out) == []


def test_multi_include_empty(detector):
    """Test 37: Dùng `include` gọi tệp chứa `deny all;` nhưng tệp đó không tồn tại (AST rỗng phần includes) -> Không hợp lệ."""
    out = _make_parser_output([_http_block([
        _server_block([
            _dir("allow", ["10.0.0.1"])
        ])
    ])])
    res = detector.scan(out)
    assert len(res) == 1


def test_multi_whitelist_include_valid(detector):
    """Test 38: Cấu hình IP whitelist quản lý trong file riêng và được `include` đúng cách ngay trước `deny all;` -> Hợp lệ."""
    out = _make_parser_output([_http_block([_server_block([
        _dir("allow", ["10.0.0.1"]),
        _dir("allow", ["10.0.0.2"]),
        _dir("deny", ["all"])
    ])])])
    assert detector.scan(out) == []

# --- Cấu trúc AST, Remediation Payload & Edge Cases ---


def test_ast_missing_args(detector):
    """Test 39: Cấu trúc AST thiếu trường `args` trong chỉ thị `deny` -> Báo lỗi."""
    out = _make_parser_output([_http_block([_server_block([
        _dir("allow", ["10.0.0.1"]),
        {"directive": "deny"}
    ])])])
    res = detector.scan(out)
    assert len(res) == 1


def test_limit_except_valid(detector):
    """Test 40: Khối `limit_except` bên trong `location` sử dụng `allow` và `deny all;` hợp lệ -> Hợp lệ."""
    out = _make_parser_output([_http_block([_server_block([
        _location_block(["/"], [
            _dir("limit_except", ["GET"], [
                _dir("allow", ["10.0.0.1"]),
                _dir("deny", ["all"])
            ])
        ])
    ])])])
    assert detector.scan(out) == []


def test_limit_except_invalid(detector):
    """Test 41: Khối `limit_except` có `allow` mà thiếu `deny all;` -> Không hợp lệ."""
    out = _make_parser_output([_http_block([_server_block([
        _location_block(["/"], [
            _dir("limit_except", ["GET"], [
                _dir("allow", ["10.0.0.1"])
            ])
        ])
    ])])])
    res = detector.scan(out)
    assert len(res) == 1


def test_payload_action_add(detector):
    """Test 42: Đảm bảo payload sinh ra hành động `add` để chèn `deny all;` vào vị trí cuối cùng của khối khi bị thiếu."""
    out = _make_parser_output([_http_block([_server_block([
        _dir("allow", ["10.0.0.1"])
    ])])])
    res = detector.scan(out)
    assert res[0]["remediations"][0]["action"] == "add"
    assert res[0]["remediations"][0]["directive"] == "deny"
    assert res[0]["remediations"][0]["args"] == ["all"]


def test_payload_action_delete_allow_all(detector):
    """Test 43: Đảm bảo payload sinh ra hành động `delete` để loại bỏ hoàn toàn chỉ thị `allow all;`."""
    out = _make_parser_output([_http_block([_server_block([
        _dir("allow", ["all"])
    ])])])
    res = detector.scan(out)
    assert res[0]["remediations"][0]["action"] == "delete"


def test_payload_action_replace_order(detector):
    """Test 44: Đảm bảo payload sinh ra hành động chỉnh sửa/chuyển vị trí của `deny all;` xuống dưới cùng nếu nó bị đặt trước `allow`."""
    out = _make_parser_output([_http_block([_server_block([
        _dir("deny", ["all"]),
        _dir("allow", ["10.0.0.1"])
    ])])])
    res = detector.scan(out)
    assert len(res) == 1


def test_payload_exact_path_index(detector):
    """Test 45: Kiểm tra `exact_path` của payload trỏ chính xác đến vị trí mảng (array index) cần thao tác để phục vụ an toàn cho Auto-Remediation."""
    out = _make_parser_output([_http_block([_server_block([
        _dir("allow", ["10.0.0.1"])
    ])])])
    res = detector.scan(out)
    exact_path = res[0]["remediations"][0]["exact_path"]
    assert isinstance(exact_path, list)
    assert exact_path[-1] == "block"
