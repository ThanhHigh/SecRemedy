import pytest
from core.scannerEng.recommendations.detector_253 import Detector253


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
    return Detector253()

# =====================================================================
# 1. Kiểm tra Siêu dữ liệu (Metadata Sanity Checks) - 3 Test Cases
# =====================================================================


def test_metadata_id(detector):
    """Test 1: ID = '2.5.3'"""
    assert detector.id == "2.5.3"


def test_metadata_title(detector):
    """Test 2: Tiêu đề phải đúng"""
    assert detector.title == "Đảm bảo vô hiệu hóa việc phục vụ các file ẩn"


def test_metadata_attributes(detector):
    """Test 3: Có các thuộc tính bắt buộc"""
    assert hasattr(detector, "description")
    assert hasattr(detector, "audit_procedure")
    assert hasattr(detector, "impact")
    assert hasattr(detector, "remediation")

# =====================================================================
# 2. Kiểm thử hàm scan(): Toàn bộ đường ống (Full Pipeline Integration) - 42 Test Cases
# =====================================================================

# --- Hợp lệ - Cấu hình an toàn (Valid Configurations) ---


def test_valid_full_config(detector):
    """Test 4: Khối server chứa cả ngoại lệ ACME và quy tắc chặn file ẩn"""
    out = _make_parser_output([_http_block([
        _server_block([
            _location_block(["^~", "/.well-known/acme-challenge/"], [
                _dir("allow", ["all"])
            ]),
            _location_block(["~", "/\\."], [
                _dir("deny", ["all"])
            ])
        ])
    ])])
    assert detector.scan(out) == []


def test_valid_deny_only(detector):
    """Test 5: Khối server chỉ chứa quy tắc chặn file ẩn (không có ACME)"""
    out = _make_parser_output([_http_block([
        _server_block([
            _location_block(["~", "/\\."], [
                _dir("deny", ["all"])
            ])
        ])
    ])])
    assert detector.scan(out) == []


def test_valid_multiple_servers(detector):
    """Test 6: Nhiều khối server, tất cả đều có quy tắc chặn"""
    out = _make_parser_output([_http_block([
        _server_block([
            _location_block(["~", "/\\."], [_dir("deny", ["all"])])
        ]),
        _server_block([
            _location_block(["~", "/\\."], [_dir("deny", ["all"])])
        ])
    ])])
    assert detector.scan(out) == []


def test_valid_deny_and_return(detector):
    """Test 7: Khối location vừa chứa deny all vừa return 404"""
    out = _make_parser_output([_http_block([
        _server_block([
            _location_block(["~", "/\\."], [
                _dir("deny", ["all"]),
                _dir("return", ["404"])
            ])
        ])
    ])])
    assert detector.scan(out) == []


def test_valid_acme_before_deny(detector):
    """Test 8: Quy tắc ACME đặt trước quy tắc chặn file ẩn"""
    out = _make_parser_output([_http_block([
        _server_block([
            _location_block(["^~", "/.well-known/acme-challenge/"],
                            [_dir("allow", ["all"])]),
            _location_block(["~", "/\\."], [_dir("deny", ["all"])])
        ])
    ])])
    assert detector.scan(out) == []

# --- Không hợp lệ - Thiếu cấu hình (Missing Configuration) ---


def test_missing_no_locations(detector):
    """Test 9: Khối server hoàn toàn không có khối location nào -> Trả về add"""
    out = _make_parser_output([_http_block([
        _server_block([])
    ])])
    res = detector.scan(out)
    assert len(res) == 1
    assert res[0]["remediations"][0]["action"] == "add"


def test_missing_other_locations_exist(detector):
    """Test 10: Khối server có location khác nhưng thiếu location chặn file ẩn -> Trả về add"""
    out = _make_parser_output([_http_block([
        _server_block([
            _location_block(["/"], [_dir("return", ["200"])])
        ])
    ])])
    res = detector.scan(out)
    assert len(res) == 1
    assert res[0]["remediations"][0]["action"] == "add"


def test_missing_some_servers(detector):
    """Test 11: Nhiều khối server, một số thiếu quy tắc chặn -> add cho khối thiếu"""
    out = _make_parser_output([_http_block([
        _server_block([
            _location_block(["~", "/\\."], [_dir("deny", ["all"])])
        ]),
        _server_block([])
    ])])
    res = detector.scan(out)
    assert len(res) == 1
    assert len(res[0]["remediations"]) == 1


def test_missing_empty_server(detector):
    """Test 12: Khối server trống rỗng -> Trả về add"""
    out = _make_parser_output([_http_block([
        _server_block([])
    ])])
    res = detector.scan(out)
    assert len(res) == 1
    assert res[0]["remediations"][0]["action"] == "add"


def test_missing_no_server_blocks(detector):
    """Test 13: File cấu hình không có khối server nào (chỉ có http) -> Bỏ qua (không báo lỗi)"""
    out = _make_parser_output([_http_block([
        _dir("sendfile", ["on"])
    ])])
    assert detector.scan(out) == []


def test_missing_main_file(detector):
    """Test 14: Thiếu quy tắc chặn ở khối server trong file nginx.conf"""
    out = {
        "status": "ok", "errors": [], "config": [{
            "file": "/etc/nginx/nginx.conf", "status": "ok", "errors": [],
            "parsed": [_http_block([_server_block([])])]
        }]
    }
    res = detector.scan(out)
    assert len(res) == 1
    assert res[0]["file"] == "/etc/nginx/nginx.conf"


def test_missing_include_file(detector):
    """Test 15: Thiếu quy tắc chặn ở khối server trong file được include"""
    out = {
        "status": "ok", "errors": [], "config": [
            {
                "file": "/etc/nginx/nginx.conf", "status": "ok", "errors": [],
                "parsed": [_http_block([])]
            },
            {
                "file": "/etc/nginx/conf.d/default.conf", "status": "ok", "errors": [],
                "parsed": [_server_block([])]
            }
        ]
    }
    res = detector.scan(out)
    assert len(res) == 1
    assert res[0]["file"] == "/etc/nginx/conf.d/default.conf"


def test_missing_multiple_servers_same_file(detector):
    """Test 16: Thiếu quy tắc ở nhiều khối server trong cùng một file cấu hình"""
    out = _make_parser_output([_http_block([
        _server_block([]),
        _server_block([])
    ])])
    res = detector.scan(out)
    assert len(res) == 1
    assert len(res[0]["remediations"]) == 2


def test_missing_multiple_files(detector):
    """Test 17: Thiếu quy tắc ở nhiều khối server trải dài trên nhiều file khác nhau"""
    out = {
        "status": "ok", "errors": [], "config": [
            {
                "file": "file1.conf", "status": "ok", "errors": [],
                "parsed": [_server_block([])]
            },
            {
                "file": "file2.conf", "status": "ok", "errors": [],
                "parsed": [_server_block([])]
            }
        ]
    }
    res = detector.scan(out)
    assert len(res) == 2


def test_missing_exact_match_instead_of_regex(detector):
    """Test 18: location chặn nhưng dùng exact match '= /.' thay vì regex -> Trả về add"""
    out = _make_parser_output([_http_block([
        _server_block([
            _location_block(["=", "/."], [_dir("deny", ["all"])])
        ])
    ])])
    res = detector.scan(out)
    assert len(res) == 1
    assert res[0]["remediations"][0]["action"] == "add"

# --- Không hợp lệ - Cấu hình sai logic (Invalid Logic) ---


def test_invalid_allow_instead_of_deny(detector):
    """Test 19: Có location chặn nhưng bên trong là allow all thay vì deny all -> Báo lỗi"""
    out = _make_parser_output([_http_block([
        _server_block([
            _location_block(["~", "/\\."], [_dir("allow", ["all"])])
        ])
    ])])
    res = detector.scan(out)
    assert len(res) == 1


def test_invalid_empty_location(detector):
    """Test 20: Có location chặn nhưng block rỗng -> Báo lỗi"""
    out = _make_parser_output([_http_block([
        _server_block([
            _location_block(["~", "/\\."], [])
        ])
    ])])
    res = detector.scan(out)
    assert len(res) == 1


def test_invalid_return_only(detector):
    """Test 21: location chặn chỉ chứa return 404 nhưng thiếu deny all -> Báo lỗi"""
    out = _make_parser_output([_http_block([
        _server_block([
            _location_block(["~", "/\\."], [_dir("return", ["404"])])
        ])
    ])])
    res = detector.scan(out)
    assert len(res) == 1


def test_invalid_acme_only(detector):
    """Test 22: Có ngoại lệ ACME nhưng thiếu location chặn file ẩn -> Báo lỗi"""
    out = _make_parser_output([_http_block([
        _server_block([
            _location_block(
                ["^~", "/.well-known/acme-challenge/"], [_dir("allow", ["all"])])
        ])
    ])])
    res = detector.scan(out)
    assert len(res) == 1


def test_invalid_acme_after_deny(detector):
    """Test 23: Quy tắc ACME nằm sau quy tắc chặn (Sai thứ tự ưu tiên regex) -> Báo lỗi"""
    out = _make_parser_output([_http_block([
        _server_block([
            _location_block(["~", "/\\."], [_dir("deny", ["all"])]),
            _location_block(
                ["^~", "/.well-known/acme-challenge/"], [_dir("allow", ["all"])])
        ])
    ])])
    res = detector.scan(out)
    assert len(res) == 1


def test_invalid_specific_git(detector):
    """Test 24: Quy tắc chặn chỉ nhắm cụ thể vào .git chứ không chặn toàn bộ file ẩn -> Báo lỗi"""
    out = _make_parser_output([_http_block([
        _server_block([
            _location_block(["~", "/\\.git"], [_dir("deny", ["all"])])
        ])
    ])])
    res = detector.scan(out)
    assert len(res) == 1


def test_invalid_specific_env(detector):
    """Test 25: Quy tắc chặn chỉ nhắm cụ thể vào .env chứ không chặn toàn bộ file ẩn -> Báo lỗi"""
    out = _make_parser_output([_http_block([
        _server_block([
            _location_block(["~", "/\\.env"], [_dir("deny", ["all"])])
        ])
    ])])
    res = detector.scan(out)
    assert len(res) == 1


def test_invalid_deny_wrong_args(detector):
    """Test 26: Chỉ thị deny có đối số sai (vd: IP thay vì all) -> Báo lỗi"""
    out = _make_parser_output([_http_block([
        _server_block([
            _location_block(["~", "/\\."], [_dir("deny", ["192.168.1.1"])])
        ])
    ])])
    res = detector.scan(out)
    assert len(res) == 1


def test_invalid_nested_location(detector):
    """Test 27: Khối location chặn nằm lồng bên trong một location khác -> Báo thiếu toàn cục (báo lỗi add)"""
    out = _make_parser_output([_http_block([
        _server_block([
            _location_block(["/"], [
                _location_block(["~", "/\\."], [_dir("deny", ["all"])])
            ])
        ])
    ])])
    res = detector.scan(out)
    assert len(res) == 1
    assert res[0]["remediations"][0]["action"] == "add"


def test_invalid_commented_deny(detector):
    """Test 28: Chỉ thị deny all tồn tại nhưng bị comment ra (AST bỏ qua) -> Coi như thiếu, báo lỗi"""
    out = _make_parser_output([_http_block([
        _server_block([
            # giả sử deny bị comment
            _location_block(["~", "/\\."], [_dir("return", ["404"])])
        ])
    ])])
    res = detector.scan(out)
    assert len(res) == 1

# --- Xử lý Đa ngữ cảnh & Hành động Remediation (Context & Actions) ---


def test_context_action_add(detector):
    """Test 29: Kiểm tra action là 'add' khi thiếu khối chặn"""
    out = _make_parser_output([_http_block([_server_block([])])])
    res = detector.scan(out)
    assert res[0]["remediations"][0]["action"] == "add"


def test_context_logical_context_add(detector):
    """Test 30: Kiểm tra logical_context của hành động add là ['http', 'server']"""
    out = _make_parser_output([_http_block([_server_block([])])])
    res = detector.scan(out)
    assert res[0]["remediations"][0]["logical_context"] == ["http", "server"]


def test_context_exact_path_add(detector):
    """Test 31: Kiểm tra exact_path trỏ chính xác vào mảng block của khối server bị thiếu"""
    out = _make_parser_output([_http_block([_server_block([])])])
    res = detector.scan(out)
    assert res[0]["remediations"][0]["exact_path"] == [
        "config", 0, "parsed", 0, "block", 0, "block"]


def test_context_payload_includes_both(detector):
    """Test 32: Payload remediations khi add phải bao gồm cả 2 location: ACME và chặn file ẩn"""
    out = _make_parser_output([_http_block([_server_block([])])])
    res = detector.scan(out)
    rem = res[0]["remediations"][0]
    assert len(rem["block"]) == 2
    assert rem["block"][0]["args"] == ["^~", "/.well-known/acme-challenge/"]
    assert rem["block"][1]["args"] == ["~", "/\\."]


def test_context_payload_structure_valid(detector):
    """Test 33: Kiểm tra cấu trúc JSON của khối location được add hợp lệ"""
    out = _make_parser_output([_http_block([_server_block([])])])
    res = detector.scan(out)
    rem = res[0]["remediations"][0]
    assert rem["directive"] == "location"
    assert "block" in rem


def test_context_payload_schema(detector):
    """Test 34: Xác minh payload trả về khớp mẫu scan_result.json"""
    out = _make_parser_output([_http_block([_server_block([])])])
    res = detector.scan(out)
    rem = res[0]["remediations"][0]
    assert "action" in rem
    assert "exact_path" in rem


def test_context_exact_path_existing_locations(detector):
    """Test 35: exact_path tính toán đúng khi khối server đã có sẵn các location khác"""
    out = _make_parser_output([_http_block([
        _server_block([
            _location_block(["/"], [])
        ])
    ])])
    res = detector.scan(out)
    assert res[0]["remediations"][0]["exact_path"][-1] == "block"


def test_context_exact_path_empty_server(detector):
    """Test 36: exact_path tính toán đúng khi chèn vào block server rỗng"""
    out = _make_parser_output([_http_block([_server_block([])])])
    res = detector.scan(out)
    assert res[0]["remediations"][0]["exact_path"][-1] == "block"


def test_context_group_by_file_same_file(detector):
    """Test 37: Kiểm tra việc gộp lỗi khi một file có 3 khối server đều thiếu quy tắc"""
    out = _make_parser_output([_http_block([
        _server_block([]), _server_block([]), _server_block([])
    ])])
    res = detector.scan(out)
    assert len(res) == 1
    assert len(res[0]["remediations"]) == 3


def test_context_group_by_file_multi_include(detector):
    """Test 38: Kiểm tra việc gộp lỗi khi nhiều file include đều vi phạm"""
    out = {
        "status": "ok", "errors": [], "config": [
            {"file": "1.conf", "status": "ok", "errors": [],
                "parsed": [_server_block([])]},
            {"file": "2.conf", "status": "ok",
                "errors": [], "parsed": [_server_block([])]}
        ]
    }
    res = detector.scan(out)
    assert len(res) == 2


def test_context_no_duplicate_remediations(detector):
    """Test 39: Đảm bảo không tạo remediation trùng lặp cho cùng một khối server"""
    out = _make_parser_output([_http_block([_server_block([])])])
    res = detector.scan(out)
    assert len(res[0]["remediations"]) == 1


def test_context_replace_or_add_when_invalid(detector):
    """Test 40: action là replace hoặc add nếu khối location đã tồn tại nhưng sai logic bên trong"""
    out = _make_parser_output([_http_block([
        _server_block([
            _location_block(["~", "/\\."], [_dir("allow", ["all"])])
        ])
    ])])
    res = detector.scan(out)
    assert len(res) == 1

# --- Cấu hình Đa tệp & Ngoại lệ (Multi-file & Edge cases) ---


def test_edge_deep_include_map(detector):
    """Test 41: Khối server trong file include sâu vi phạm -> ánh xạ file chuẩn xác"""
    out = {
        "status": "ok", "errors": [], "config": [
            {"file": "conf.d/sub/app.conf", "status": "ok",
                "errors": [], "parsed": [_server_block([])]}
        ]
    }
    res = detector.scan(out)
    assert res[0]["file"] == "conf.d/sub/app.conf"


def test_edge_main_invalid_child_valid(detector):
    """Test 42: Khối server trong nginx.conf vi phạm, trong api.conf hợp lệ -> Chỉ lỗi file chính"""
    out = {
        "status": "ok", "errors": [], "config": [
            {"file": "nginx.conf", "status": "ok",
                "errors": [], "parsed": [_server_block([])]},
            {"file": "api.conf", "status": "ok", "errors": [], "parsed": [_server_block([
                _location_block(["~", "/\\."], [_dir("deny", ["all"])])
            ])]}
        ]
    }
    res = detector.scan(out)
    assert len(res) == 1
    assert res[0]["file"] == "nginx.conf"


def test_edge_ignore_third_party(detector):
    """Test 43: Bỏ qua khối của module bên thứ ba có tên gần giống (vd server_custom)"""
    out = _make_parser_output([_http_block([
        _dir("server_custom", [], []),
        _server_block([
            _location_block(["~", "/\\."], [_dir("deny", ["all"])])
        ])
    ])])
    assert detector.scan(out) == []


def test_edge_quotes_location(detector):
    """Test 44: Xử lý giá trị chuỗi của location có bọc ngoặc kép"""
    out = _make_parser_output([_http_block([
        _server_block([
            _location_block(['"~"', '"/\\."'], [_dir("deny", ["all"])])
        ])
    ])])
    assert detector.scan(out) == []


def test_edge_missing_block_ast(detector):
    """Test 45: Đảm bảo không crash nếu cấu trúc AST khuyết thiếu trường block"""
    out = _make_parser_output([
        _dir("http", [])  # thiếu mảng block hoàn toàn
    ])
    res = detector.scan(out)
    assert len(res) == 0
