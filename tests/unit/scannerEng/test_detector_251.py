import pytest
from core.scannerEng.recommendations.detector_251 import Detector251


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
    return Detector251()

# =====================================================================
# 1. Kiểm tra Siêu dữ liệu (Metadata Sanity Checks) - 3 Test Cases
# =====================================================================


def test_metadata_id(detector):
    """Test 1: ID phải là '2.5.1'"""
    assert detector.id == "2.5.1"


def test_metadata_title(detector):
    """Test 2: Tiêu đề phải đúng"""
    assert detector.title == "Đảm bảo chỉ thị server_tokens được đặt thành 'off'"


def test_metadata_attributes(detector):
    """Test 3: Thuộc tính bắt buộc"""
    assert hasattr(detector, "description")
    assert hasattr(detector, "audit_procedure")
    assert hasattr(detector, "impact")
    assert hasattr(detector, "remediation")

# =====================================================================
# 2. Kiểm thử hàm scan() - 42 Test Cases
# =====================================================================

# --- Hợp lệ - server_tokens off (Valid Configurations) ---


def test_valid_http_off(detector):
    """Test 4: Chỉ chứa `server_tokens off;` trong khối `http`."""
    out = _make_parser_output([_http_block([
        _dir("server_tokens", ["off"])
    ])])
    assert detector.scan(out) == []


def test_valid_http_and_server_off(detector):
    """Test 5: Khối `http` có `server_tokens off;` và khối `server` cũng có `server_tokens off;`."""
    out = _make_parser_output([_http_block([
        _dir("server_tokens", ["off"]),
        _server_block([
            _dir("server_tokens", ["off"])
        ])
    ])])
    assert detector.scan(out) == []


def test_valid_http_multiple_servers(detector):
    """Test 6: Khối `http` có `server_tokens off;` và nhiều khối `server` không định nghĩa lại."""
    out = _make_parser_output([_http_block([
        _dir("server_tokens", ["off"]),
        _server_block([_dir("listen", ["80"])]),
        _server_block([_dir("listen", ["443"])])
    ])])
    assert detector.scan(out) == []


def test_valid_http_and_location_off(detector):
    """Test 7: Khối `http` có `server_tokens off;` và khối `location` cũng có `server_tokens off;`."""
    out = _make_parser_output([_http_block([
        _dir("server_tokens", ["off"]),
        _server_block([
            _location_block(["/"], [
                _dir("server_tokens", ["off"])
            ])
        ])
    ])])
    assert detector.scan(out) == []


def test_valid_nested_deep_off(detector):
    """Test 8: Cấu trúc lồng sâu `http` -> `server` -> `location` đều có `server_tokens off;`."""
    out = _make_parser_output([_http_block([
        _dir("server_tokens", ["off"]),
        _server_block([
            _dir("server_tokens", ["off"]),
            _location_block(["/"], [
                _dir("server_tokens", ["off"])
            ])
        ])
    ])])
    assert detector.scan(out) == []

# --- Không hợp lệ - Giá trị sai (Invalid Values) ---


def test_invalid_http_on(detector):
    """Test 9: Khối `http` chứa `server_tokens on;` -> Trả về `replace` thành `off`."""
    out = _make_parser_output([_http_block([
        _dir("server_tokens", ["on"])
    ])])
    res = detector.scan(out)
    assert len(res) == 1
    assert res[0]["remediations"][0]["action"] == "replace"
    assert res[0]["remediations"][0]["args"] == ["off"]


def test_invalid_http_build(detector):
    """Test 10: Khối `http` chứa `server_tokens build;` -> Trả về `replace` thành `off`."""
    out = _make_parser_output([_http_block([
        _dir("server_tokens", ["build"])
    ])])
    res = detector.scan(out)
    assert len(res) == 1
    assert res[0]["remediations"][0]["action"] == "replace"


def test_invalid_server_on(detector):
    """Test 11: Khối `server` chứa `server_tokens on;` -> Trả về `replace`."""
    out = _make_parser_output([_http_block([
        _dir("server_tokens", ["off"]),
        _server_block([
            _dir("server_tokens", ["on"])
        ])
    ])])
    res = detector.scan(out)
    assert len(res) == 1
    assert res[0]["remediations"][0]["action"] == "replace"


def test_invalid_location_on(detector):
    """Test 12: Khối `location` chứa `server_tokens on;` -> Trả về `replace`."""
    out = _make_parser_output([_http_block([
        _dir("server_tokens", ["off"]),
        _server_block([
            _location_block(["/"], [
                _dir("server_tokens", ["on"])
            ])
        ])
    ])])
    res = detector.scan(out)
    assert len(res) == 1
    assert res[0]["remediations"][0]["action"] == "replace"


def test_invalid_server_on_http_off(detector):
    """Test 13: `http` có `off`, nhưng `server` có `on` -> Chỉ `replace` ở `server`."""
    out = _make_parser_output([_http_block([
        _dir("server_tokens", ["off"]),
        _server_block([
            _dir("server_tokens", ["on"])
        ])
    ])])
    res = detector.scan(out)
    assert len(res) == 1
    assert len(res[0]["remediations"]) == 1
    assert res[0]["remediations"][0]["logical_context"] == ["http", "server"]


def test_invalid_http_on_server_off(detector):
    """Test 14: `http` có `on`, `server` có `off` -> `replace` ở `http`."""
    out = _make_parser_output([_http_block([
        _dir("server_tokens", ["on"]),
        _server_block([
            _dir("server_tokens", ["off"])
        ])
    ])])
    res = detector.scan(out)
    assert len(res) == 1
    assert len(res[0]["remediations"]) == 1
    assert res[0]["remediations"][0]["logical_context"] == ["http"]


def test_invalid_multiple_servers_on(detector):
    """Test 15: Nhiều khối `server` đều chứa `server_tokens on;`."""
    out = _make_parser_output([_http_block([
        _dir("server_tokens", ["off"]),
        _server_block([_dir("server_tokens", ["on"])]),
        _server_block([_dir("server_tokens", ["on"])])
    ])])
    res = detector.scan(out)
    assert len(res) == 1
    assert len(res[0]["remediations"]) == 2


def test_invalid_http_uppercase_ON(detector):
    """Test 16: Khối `http` chứa `server_tokens ON;` (In hoa) -> Trả về `replace`."""
    out = _make_parser_output([_http_block([
        _dir("server_tokens", ["ON"])
    ])])
    res = detector.scan(out)
    assert len(res) == 1
    assert res[0]["remediations"][0]["action"] == "replace"


def test_invalid_whitespace_on(detector):
    """Test 17: Khối `http` có khoảng trắng dư thừa `server_tokens  on ;`."""
    # Thư viện parse thường gộp arguments, test logic nhận diện.
    out = _make_parser_output([_http_block([
        _dir("server_tokens", ["on "])
    ])])
    res = detector.scan(out)
    assert len(res) == 1
    assert res[0]["remediations"][0]["action"] == "replace"


def test_invalid_multiple_directives_same_block(detector):
    """Test 18: Có 2 chỉ thị `server_tokens` trong cùng 1 khối (1 `on`, 1 `off`)."""
    out = _make_parser_output([_http_block([
        _dir("server_tokens", ["off"]),
        _dir("server_tokens", ["on"])
    ])])
    res = detector.scan(out)
    assert len(res) == 1
    # Có thể replace cái "on" hoặc cảnh báo, ở đây mong muốn ít nhất 1 replace.
    assert res[0]["remediations"][0]["action"] == "replace"

# --- Không hợp lệ - Bị thiếu (Missing Directive) ---


def test_missing_empty_http(detector):
    """Test 19: Khối `http` trống, không có `server_tokens` -> Trả về `add` vào `http`."""
    out = _make_parser_output([_http_block([])])
    res = detector.scan(out)
    assert len(res) == 1
    assert res[0]["remediations"][0]["action"] == "add"


def test_missing_http_other_directives(detector):
    """Test 20: Khối `http` có các chỉ thị khác nhưng thiếu `server_tokens` -> Trả về `add`."""
    out = _make_parser_output([_http_block([
        _dir("sendfile", ["on"])
    ])])
    res = detector.scan(out)
    assert len(res) == 1
    assert res[0]["remediations"][0]["action"] == "add"


def test_missing_no_http_block(detector):
    """Test 21: Không có khối `http` nào trong cấu hình (cấu hình rỗng)."""
    out = _make_parser_output([])
    res = detector.scan(out)
    assert len(res) == 1
    # Yêu cầu ít nhất 1 file được báo lỗi (file chính).
    assert res[0]["remediations"][0]["action"] == "add"


def test_missing_in_server_and_http(detector):
    """Test 22: Khối `server` không có `server_tokens`, và `http` cũng thiếu -> Báo thiếu `add` ở `http`."""
    out = _make_parser_output([_http_block([
        _server_block([])
    ])])
    res = detector.scan(out)
    assert len(res) == 1
    assert len(res[0]["remediations"]) == 1
    assert res[0]["remediations"][0]["action"] == "add"
    assert res[0]["remediations"][0]["logical_context"] == ["http"]


def test_missing_only_server_block_exists(detector):
    """Test 23: File cấu hình chỉ có khối `server` (không thấy `http`) và thiếu `server_tokens` -> Trả về `add`."""
    out = _make_parser_output([_server_block([])])
    res = detector.scan(out)
    assert len(res) == 1
    assert res[0]["remediations"][0]["action"] == "add"


def test_missing_multi_files(detector):
    """Test 24: Thiếu `server_tokens` trong nhiều file khác nhau nhưng file gốc có khối `http`."""
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
                "parsed": [_server_block([])]
            }
        ]
    }
    res = detector.scan(out)
    assert len(res) == 1
    # Chỉ cần add vào http block ở file gốc
    assert res[0]["filepath"] == "/etc/nginx/nginx.conf"


def test_missing_commented_out(detector):
    """Test 25: Chỉ thị bị comment `# server_tokens off;` (thư viện AST bỏ qua) -> Bị coi là thiếu -> `add`."""
    out = _make_parser_output([_http_block([
        # AST sẽ không có server_tokens
        _dir("sendfile", ["on"])
    ])])
    res = detector.scan(out)
    assert len(res) == 1
    assert res[0]["remediations"][0]["action"] == "add"

# --- Xử lý đa ngữ cảnh (Context Bindings) ---


def test_context_server_only(detector):
    """Test 26: `server_tokens off` nằm trong `server` nhưng thiếu ở `http` -> Vẫn yêu cầu `add` ở `http`."""
    out = _make_parser_output([_http_block([
        _server_block([
            _dir("server_tokens", ["off"])
        ])
    ])])
    res = detector.scan(out)
    assert len(res) == 1
    assert res[0]["remediations"][0]["action"] == "add"
    assert res[0]["remediations"][0]["logical_context"] == ["http"]


def test_context_http_and_server_on(detector):
    """Test 27: `server_tokens on` nằm ở cả `http` và `server` -> `replace` cả hai."""
    out = _make_parser_output([_http_block([
        _dir("server_tokens", ["on"]),
        _server_block([
            _dir("server_tokens", ["on"])
        ])
    ])])
    res = detector.scan(out)
    assert len(res) == 1
    assert len(res[0]["remediations"]) == 2


def test_context_global_on(detector):
    """Test 28: `server_tokens` nằm ngoài khối `http` (Global context) với giá trị `on` -> Bắt lỗi `replace`."""
    out = _make_parser_output([
        _dir("server_tokens", ["on"]),
        _http_block([_dir("server_tokens", ["off"])])
    ])
    res = detector.scan(out)
    assert len(res) == 1
    assert res[0]["remediations"][0]["logical_context"] == []  # Global
    assert res[0]["remediations"][0]["action"] == "replace"


def test_context_in_if_block(detector):
    """Test 29: `server_tokens` nằm trong `if` block với giá trị `on`."""
    out = _make_parser_output([_http_block([
        _dir("server_tokens", ["off"]),
        _server_block([
            _dir("if", ["($host)"], [
                _dir("server_tokens", ["on"])
            ])
        ])
    ])])
    res = detector.scan(out)
    assert len(res) == 1
    assert res[0]["remediations"][0]["action"] == "replace"


def test_context_variable_value(detector):
    """Test 30: `server_tokens` được cấu hình qua biến `$val`."""
    out = _make_parser_output([_http_block([
        _dir("server_tokens", ["$val"])
    ])])
    res = detector.scan(out)
    assert len(res) == 1
    assert res[0]["remediations"][0]["action"] == "replace"

# --- Cấu hình đa tệp (Multi-file configurations) ---


def test_multifile_missing_and_on(detector):
    """Test 31: `nginx.conf` thiếu, `conf.d/default.conf` có `on` -> Lỗi ở cả 2 file."""
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
                "file": "/etc/nginx/conf.d/default.conf",
                "status": "ok",
                "errors": [],
                "parsed": [_server_block([_dir("server_tokens", ["on"])])]
            }
        ]
    }
    res = detector.scan(out)
    assert len(res) == 2
    actions = [r["remediations"][0]["action"] for r in res]
    assert "add" in actions
    assert "replace" in actions


def test_multifile_main_off_child_on(detector):
    """Test 32: `nginx.conf` có `off`, `conf.d/api.conf` có `on` -> Chỉ báo `replace` ở `api.conf`."""
    out = {
        "status": "ok",
        "errors": [],
        "config": [
            {
                "file": "/etc/nginx/nginx.conf",
                "status": "ok",
                "errors": [],
                "parsed": [_http_block([_dir("server_tokens", ["off"])])]
            },
            {
                "file": "/etc/nginx/conf.d/api.conf",
                "status": "ok",
                "errors": [],
                "parsed": [_server_block([_dir("server_tokens", ["on"])])]
            }
        ]
    }
    res = detector.scan(out)
    assert len(res) == 1
    assert res[0]["filepath"] == "/etc/nginx/conf.d/api.conf"
    assert res[0]["remediations"][0]["action"] == "replace"


def test_multifile_all_on(detector):
    """Test 33: 3 files, mỗi file đều có `server_tokens on;` -> Gom lỗi theo 3 files."""
    out = {
        "status": "ok",
        "errors": [],
        "config": [
            {
                "file": "/etc/nginx/nginx.conf",
                "status": "ok",
                "errors": [],
                "parsed": [_http_block([_dir("server_tokens", ["on"])])]
            },
            {
                "file": "/etc/nginx/conf.d/api1.conf",
                "status": "ok",
                "errors": [],
                "parsed": [_server_block([_dir("server_tokens", ["on"])])]
            },
            {
                "file": "/etc/nginx/conf.d/api2.conf",
                "status": "ok",
                "errors": [],
                "parsed": [_server_block([_dir("server_tokens", ["on"])])]
            }
        ]
    }
    res = detector.scan(out)
    assert len(res) == 3


def test_multifile_deep_include(detector):
    """Test 34: File include nằm sâu `conf.d/sub/app.conf` chứa vi phạm -> Map đúng file."""
    out = {
        "status": "ok",
        "errors": [],
        "config": [
            {
                "file": "/etc/nginx/nginx.conf",
                "status": "ok",
                "errors": [],
                "parsed": [_http_block([_dir("server_tokens", ["off"])])]
            },
            {
                "file": "/etc/nginx/conf.d/sub/app.conf",
                "status": "ok",
                "errors": [],
                "parsed": [_server_block([_dir("server_tokens", ["on"])])]
            }
        ]
    }
    res = detector.scan(out)
    assert len(res) == 1
    assert res[0]["filepath"] == "/etc/nginx/conf.d/sub/app.conf"


def test_multifile_missing_everywhere(detector):
    """Test 35: Nhiều file include, không file nào có `server_tokens` -> Báo lỗi `add` vào file chính."""
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
                "file": "/etc/nginx/conf.d/api1.conf",
                "status": "ok",
                "errors": [],
                "parsed": [_server_block([])]
            },
        ]
    }
    res = detector.scan(out)
    assert len(res) == 1
    assert res[0]["filepath"] == "/etc/nginx/nginx.conf"
    assert res[0]["remediations"][0]["action"] == "add"

# --- Cấu trúc lồng nhau và ngoại lệ (Nested structures & edge cases) ---


def test_edge_exact_path_last_item(detector):
    """Test 36: `exact_path` tính toán đúng khi `server_tokens` là phần tử cuối cùng trong `http`."""
    out = _make_parser_output([_http_block([
        _dir("sendfile", ["on"]),
        _dir("server_tokens", ["on"])
    ])])
    res = detector.scan(out)
    assert res[0]["remediations"][0]["exact_path"][-1] == 1


def test_edge_exact_path_add_empty(detector):
    """Test 37: `exact_path` tính toán đúng khi phải `add` vào `block` rỗng."""
    out = _make_parser_output([_http_block([])])
    res = detector.scan(out)
    assert res[0]["remediations"][0]["exact_path"] == [
        "config", 0, "parsed", 0, "block"]


def test_edge_logical_context_add(detector):
    """Test 38: `logical_context` của `add` chứa đúng `['http']`."""
    out = _make_parser_output([_http_block([])])
    res = detector.scan(out)
    assert res[0]["remediations"][0]["logical_context"] == ["http"]


def test_edge_logical_context_replace(detector):
    """Test 39: `logical_context` của `replace` chứa đúng `['http', 'server', 'location']`."""
    out = _make_parser_output([_http_block([
        _dir("server_tokens", ["off"]),
        _server_block([
            _location_block(["/"], [
                _dir("server_tokens", ["on"])
            ])
        ])
    ])])
    res = detector.scan(out)
    assert res[0]["remediations"][0]["logical_context"] == [
        "http", "server", "location"]


def test_edge_quotes_double(detector):
    """Test 40: Xử lý khi giá trị là chuỗi có ngoặc kép `"on"` -> replace."""
    out = _make_parser_output([_http_block([
        _dir("server_tokens", ['"on"'])
    ])])
    res = detector.scan(out)
    assert len(res) == 1
    assert res[0]["remediations"][0]["action"] == "replace"


def test_edge_quotes_single(detector):
    """Test 41: Xử lý khi giá trị là chuỗi có nháy đơn `'on'` -> replace."""
    out = _make_parser_output([_http_block([
        _dir("server_tokens", ["'on'"])
    ])])
    res = detector.scan(out)
    assert len(res) == 1
    assert res[0]["remediations"][0]["action"] == "replace"


def test_edge_quotes_off(detector):
    """Test 42: Xử lý khi giá trị là chuỗi có ngoặc `"off"` hoặc `'off'` -> Hợp lệ."""
    out = _make_parser_output([_http_block([
        _dir("server_tokens", ['"off"']),
        _server_block([
            _dir("server_tokens", ["'off'"])
        ])
    ])])
    assert detector.scan(out) == []


def test_edge_ignore_similar_names(detector):
    """Test 43: Bỏ qua cấu hình của module bên thứ ba có tên tương tự (vd `server_tokens_custom`)."""
    out = _make_parser_output([_http_block([
        _dir("server_tokens_custom", ["on"]),
        _dir("server_tokens", ["off"])
    ])])
    assert detector.scan(out) == []


def test_edge_action_verify_replace(detector):
    """Test 44: Xác minh thuộc tính `action` là `replace` khi directive đã tồn tại."""
    out = _make_parser_output([_http_block([
        _dir("server_tokens", ["on"])
    ])])
    res = detector.scan(out)
    assert res[0]["remediations"][0]["action"] == "replace"
    assert res[0]["remediations"][0]["directive"] == "server_tokens"
    assert res[0]["remediations"][0]["args"] == ["off"]


def test_edge_payload_structure(detector):
    """Test 45: Đảm bảo cấu trúc payload JSON `remediations` khớp hoàn toàn với `scan_result.json`."""
    out = _make_parser_output([_http_block([])])
    res = detector.scan(out)
    rem = res[0]["remediations"][0]
    assert "action" in rem
    assert "directive" in rem
    assert "args" in rem
    assert "logical_context" in rem
    assert "exact_path" in rem
    assert rem["action"] == "add"
    assert rem["directive"] == "server_tokens"
    assert rem["args"] == ["off"]
