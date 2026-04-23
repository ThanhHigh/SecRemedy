import pytest
from core.scannerEng.recommendations.detector_252 import Detector252


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
    return Detector252()

# =====================================================================
# 1. Kiểm tra Siêu dữ liệu (Metadata Sanity Checks) - 3 Test Cases
# =====================================================================


def test_metadata_id(detector):
    """Test 1: ID phải là '2.5.2'"""
    assert detector.id == "2.5.2"


def test_metadata_title(detector):
    """Test 2: Tiêu đề phải đúng"""
    assert detector.title == "Đảm bảo các trang lỗi mặc định và trang index.html không tham chiếu đến NGINX"


def test_metadata_attributes(detector):
    """Test 3: Thuộc tính bắt buộc"""
    assert hasattr(detector, "description")
    assert hasattr(detector, "audit_procedure")
    assert hasattr(detector, "impact")
    assert hasattr(detector, "remediation")

# =====================================================================
# 2. Kiểm thử hàm scan() - 42 Test Cases
# =====================================================================

# --- Hợp lệ - Đã định nghĩa error_page (Valid Configurations) ---


def test_valid_http_both_error_pages(detector):
    """Test 4: Khối `http` chứa `error_page 404` và `error_page 500 502 503 504`."""
    out = _make_parser_output([_http_block([
        _dir("error_page", ["404", "/404.html"]),
        _dir("error_page", ["500", "502", "503", "504", "/50x.html"])
    ])])
    assert detector.scan(out) == []


def test_valid_server_both_error_pages(detector):
    """Test 5: Khối `server` chứa `error_page 404` và `error_page 500 502 503 504`."""
    out = _make_parser_output([_http_block([
        _server_block([
            _dir("error_page", ["404", "/404.html"]),
            _dir("error_page", ["500", "502", "503", "504", "/50x.html"])
        ])
    ])])
    assert detector.scan(out) == []


def test_valid_mixed_http_and_server(detector):
    """Test 6: Khối `http` định nghĩa `error_page 404`, khối `server` định nghĩa `error_page 50x`."""
    out = _make_parser_output([_http_block([
        _dir("error_page", ["404", "/404.html"]),
        _server_block([
            _dir("error_page", ["500", "502", "503", "504", "/50x.html"])
        ])
    ])])
    assert detector.scan(out) == []


def test_valid_multiple_servers_full(detector):
    """Test 7: Nhiều khối `server` đều tự định nghĩa `error_page` đầy đủ."""
    out = _make_parser_output([_http_block([
        _server_block([
            _dir("error_page", ["404", "/404.html"]),
            _dir("error_page", ["500", "502", "503", "504", "/50x.html"])
        ]),
        _server_block([
            _dir("error_page", ["404", "/custom_404.html"]),
            _dir("error_page", ["500", "502",
                 "503", "504", "/custom_50x.html"])
        ])
    ])])
    assert detector.scan(out) == []


def test_valid_error_page_code_change(detector):
    """Test 8: Cấu hình `error_page` có đổi mã HTTP response (`error_page 404 =200 /empty.html;`)."""
    out = _make_parser_output([_http_block([
        _server_block([
            _dir("error_page", ["404", "=200", "/empty.html"]),
            _dir("error_page", ["500", "502", "503",
                 "504", "=200", "/empty.html"])
        ])
    ])])
    assert detector.scan(out) == []

# --- Không hợp lệ - Thiếu hoàn toàn error_page (Missing Entirely) ---


def test_missing_empty_http(detector):
    """Test 9: Khối `http` trống, không có `error_page` -> Trả về `add` `error_page` vào `http` hoặc `server`."""
    out = _make_parser_output([_http_block([])])
    res = detector.scan(out)
    assert len(res) == 1
    actions = [r["action"] for r in res[0]["remediations"]]
    assert "add" in actions
    directives = [r["directive"] for r in res[0]["remediations"]]
    assert "error_page" in directives


def test_missing_empty_server(detector):
    """Test 10: Khối `server` trống, không có `error_page` (và `http` cũng không) -> Trả về `add`."""
    out = _make_parser_output([_http_block([_server_block([])])])
    res = detector.scan(out)
    assert len(res) == 1
    assert res[0]["remediations"][0]["action"] == "add"


def test_missing_http_other_directives(detector):
    """Test 11: Cấu hình chỉ có `http` với các directive khác, thiếu `error_page` -> Trả về `add`."""
    out = _make_parser_output([_http_block([_dir("sendfile", ["on"])])])
    res = detector.scan(out)
    assert len(res) == 1
    assert res[0]["remediations"][0]["action"] == "add"


def test_missing_multiple_servers(detector):
    """Test 12: Cấu hình có nhiều `server`, không `server` nào có `error_page` -> Trả về `add` cho từng `server`."""
    out = _make_parser_output([_http_block([
        _server_block([]),
        _server_block([])
    ])])
    res = detector.scan(out)
    assert len(res) == 1
    # Báo thiếu ở http bao ngoài hoặc ở từng server
    assert len(res[0]["remediations"]) > 0


def test_missing_in_server_only_location(detector):
    """Test 13: `location` có `error_page` nhưng `server` tổng thể không có (không bảo vệ toàn cục) -> Trả về `add` ở `server`."""
    out = _make_parser_output([_http_block([
        _server_block([
            _location_block(["/"], [
                _dir("error_page", ["404", "/404.html"])
            ])
        ])
    ])])
    res = detector.scan(out)
    assert len(res) == 1
    assert res[0]["remediations"][0]["action"] == "add"


def test_missing_empty_config(detector):
    """Test 14: File cấu hình rỗng."""
    out = _make_parser_output([])
    res = detector.scan(out)
    assert len(res) == 1
    assert res[0]["remediations"][0]["action"] == "add"


def test_missing_server_listen_only(detector):
    """Test 15: Khối `server` chỉ có `listen` và `server_name`, thiếu `error_page`."""
    out = _make_parser_output([_http_block([
        _server_block([
            _dir("listen", ["80"]),
            _dir("server_name", ["test.com"])
        ])
    ])])
    res = detector.scan(out)
    assert len(res) == 1
    assert res[0]["remediations"][0]["action"] == "add"


def test_missing_server_in_include(detector):
    """Test 16: Khối `server` nằm trong file include thiếu `error_page`."""
    out = {
        "status": "ok",
        "errors": [],
        "config": [
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
    assert res[0]["remediations"][0]["action"] == "add"


def test_missing_commented_out(detector):
    """Test 17: Chỉ thị bị comment `# error_page 404 /404.html;` -> Bị coi là thiếu -> `add`."""
    # AST bỏ qua comment, do đó trống
    out = _make_parser_output([_http_block([
        _server_block([])
    ])])
    res = detector.scan(out)
    assert len(res) == 1
    assert res[0]["remediations"][0]["action"] == "add"


def test_missing_proxy_server(detector):
    """Test 18: Block `server` cấu hình làm proxy, nhưng quên cấu hình `error_page` chặn lỗi proxy."""
    out = _make_parser_output([_http_block([
        _server_block([
            _location_block(["/"], [
                _dir("proxy_pass", ["http://backend"])
            ])
        ])
    ])])
    res = detector.scan(out)
    assert len(res) == 1
    assert res[0]["remediations"][0]["action"] == "add"

# --- Không hợp lệ - Thiếu một số mã lỗi quan trọng (Partial Missing) ---


def test_partial_missing_50x(detector):
    """Test 19: Có `error_page 404` nhưng thiếu nhóm `500 502 503 504` -> Trả về `add` nhóm 50x."""
    out = _make_parser_output([_http_block([
        _server_block([
            _dir("error_page", ["404", "/404.html"])
        ])
    ])])
    res = detector.scan(out)
    assert len(res) == 1
    args = [r["args"] for r in res[0]["remediations"]]
    assert any("500" in a for a in args)


def test_partial_missing_404(detector):
    """Test 20: Có `error_page 50x` nhưng thiếu `404` -> Trả về `add` mã 404."""
    out = _make_parser_output([_http_block([
        _server_block([
            _dir("error_page", ["500", "502", "503", "504", "/50x.html"])
        ])
    ])])
    res = detector.scan(out)
    assert len(res) == 1
    args = [r["args"] for r in res[0]["remediations"]]
    assert any("404" in a for a in args)


def test_partial_missing_404_and_50x_with_403(detector):
    """Test 21: Có `error_page` cho lỗi 403, nhưng thiếu 404 và 50x -> Trả về `add` mã 404, 50x."""
    out = _make_parser_output([_http_block([
        _server_block([
            _dir("error_page", ["403", "/403.html"])
        ])
    ])])
    res = detector.scan(out)
    assert len(res) == 1
    args = sum([r["args"] for r in res[0]["remediations"]], [])
    assert "404" in args
    assert "500" in args


def test_partial_override_loses_inherited(detector):
    """Test 22: Khối `http` có `404`, `server` ghi đè bằng `error_page 403` -> Báo lỗi ở `server`."""
    out = _make_parser_output([_http_block([
        _dir("error_page", ["404", "/404.html"]),
        _dir("error_page", ["500", "502", "503", "504", "/50x.html"]),
        _server_block([
            _dir("error_page", ["403", "/403.html"])  # Ghi đè thừa kế
        ])
    ])])
    res = detector.scan(out)
    assert len(res) == 1
    assert res[0]["remediations"][0]["action"] == "add"
    assert "server" in res[0]["remediations"][0]["logical_context"]


def test_partial_missing_some_50x(detector):
    """Test 23: Cấu hình `error_page` gộp `404 500 502`, thiếu `503 504`."""
    out = _make_parser_output([_http_block([
        _server_block([
            _dir("error_page", ["404", "500", "502", "/error.html"])
        ])
    ])])
    res = detector.scan(out)
    assert len(res) == 1
    args = sum([r["args"] for r in res[0]["remediations"]], [])
    assert "503" in args or "500" in args  # Add them back


def test_partial_syntax_error(detector):
    """Test 24: `error_page` được khai báo nhưng không trỏ tới file cụ thể (cú pháp sai)."""
    out = _make_parser_output([_http_block([
        _server_block([
            _dir("error_page", ["404"])  # Thiếu file đích
        ])
    ])])
    res = detector.scan(out)
    assert len(res) == 1
    assert res[0]["remediations"][0]["action"] == "add"


def test_partial_split_50x(detector):
    """Test 25: Có `error_page 500 502 503 504` nhưng args bị tách làm nhiều directive nhỏ lẻ -> (Test case đặc biệt)."""
    out = _make_parser_output([_http_block([
        _server_block([
            _dir("error_page", ["404", "/404.html"]),
            _dir("error_page", ["500", "/50x.html"]),
            _dir("error_page", ["502", "/50x.html"]),
            _dir("error_page", ["503", "/50x.html"]),
            _dir("error_page", ["504", "/50x.html"])
        ])
    ])])
    assert detector.scan(out) == []

# --- Xử lý đa ngữ cảnh (Context Bindings) ---


def test_context_http_inheritance(detector):
    """Test 26: `error_page` nằm trong `http` -> Tất cả `server` bên trong được thừa kế (Hợp lệ)."""
    out = _make_parser_output([_http_block([
        _dir("error_page", ["404", "/404.html"]),
        _dir("error_page", ["500", "502", "503", "504", "/50x.html"]),
        _server_block([]),
        _server_block([])
    ])])
    assert detector.scan(out) == []


def test_context_http_overriden(detector):
    """Test 27: `error_page` nằm trong `http`, nhưng một `server` khai báo `error_page 403` -> Báo lỗi `add`."""
    out = _make_parser_output([_http_block([
        _dir("error_page", ["404", "/404.html"]),
        _dir("error_page", ["500", "502", "503", "504", "/50x.html"]),
        _server_block([]),  # Inherits fine
        _server_block([
            _dir("error_page", ["403", "/403.html"])  # Overrides
        ])
    ])])
    res = detector.scan(out)
    assert len(res) == 1
    assert "server" in res[0]["remediations"][0]["logical_context"]


def test_context_global(detector):
    """Test 28: `error_page` nằm ngoài khối `http` (Global context) -> Cú pháp không hợp lệ theo Nginx, báo thiếu."""
    out = _make_parser_output([
        _dir("error_page", ["404", "/404.html"]),
        _http_block([
            _server_block([])
        ])
    ])
    res = detector.scan(out)
    assert len(res) == 1
    assert res[0]["remediations"][0]["action"] == "add"


def test_context_if_block(detector):
    """Test 29: `error_page` nằm trong `if` block -> Không khuyến khích, báo lỗi để add vào `server`."""
    out = _make_parser_output([_http_block([
        _server_block([
            _dir("if", ["($host)"], [
                _dir("error_page", ["404", "/404.html"]),
                _dir("error_page", ["500", "502", "503", "504", "/50x.html"])
            ])
        ])
    ])])
    res = detector.scan(out)
    assert len(res) == 1
    assert res[0]["remediations"][0]["action"] == "add"


def test_context_one_server_missing(detector):
    """Test 30: Một `server` có `error_page` đầy đủ, một `server` khác thì không -> Chỉ báo lỗi `add` cho `server` thiếu."""
    out = _make_parser_output([_http_block([
        _server_block([
            _dir("error_page", ["404", "/404.html"]),
            _dir("error_page", ["500", "502", "503", "504", "/50x.html"])
        ]),
        _server_block([])
    ])])
    res = detector.scan(out)
    assert len(res) == 1
    assert res[0]["remediations"][0]["action"] == "add"

# --- Cấu hình đa tệp (Multi-file configurations) ---


def test_multifile_one_missing(detector):
    """Test 31: `nginx.conf` thiếu `error_page`, file include `conf.d/app.conf` thiếu -> Báo lỗi ở `app.conf`."""
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
    files = [r["file"] for r in res]
    assert "/etc/nginx/conf.d/app.conf" in files or "/etc/nginx/nginx.conf" in files


def test_multifile_inheritance(detector):
    """Test 32: `nginx.conf` định nghĩa `error_page` trong `http`, `conf.d/api.conf` không định nghĩa lại -> Hợp lệ."""
    out = {
        "status": "ok",
        "errors": [],
        "config": [
            {
                "file": "/etc/nginx/nginx.conf",
                "status": "ok",
                "errors": [],
                "parsed": [_http_block([
                    _dir("error_page", ["404", "/404.html"]),
                    _dir("error_page", ["500", "502",
                         "503", "504", "/50x.html"])
                ])]
            },
            {
                "file": "/etc/nginx/conf.d/api.conf",
                "status": "ok",
                "errors": [],
                "parsed": [_server_block([])]
            }
        ]
    }
    assert detector.scan(out) == []


def test_multifile_override(detector):
    """Test 33: `nginx.conf` có `error_page`, `conf.d/api.conf` ghi đè `error_page 401` -> Báo lỗi ở `api.conf`."""
    out = {
        "status": "ok",
        "errors": [],
        "config": [
            {
                "file": "/etc/nginx/nginx.conf",
                "status": "ok",
                "errors": [],
                "parsed": [_http_block([
                    _dir("error_page", ["404", "/404.html"]),
                    _dir("error_page", ["500", "502",
                         "503", "504", "/50x.html"])
                ])]
            },
            {
                "file": "/etc/nginx/conf.d/api.conf",
                "status": "ok",
                "errors": [],
                "parsed": [_server_block([
                    _dir("error_page", ["401", "/401.html"])
                ])]
            }
        ]
    }
    res = detector.scan(out)
    assert len(res) == 1
    assert res[0]["file"] == "/etc/nginx/conf.d/api.conf"


def test_multifile_group_by_file(detector):
    """Test 34: 3 files cấu hình `server`, tất cả đều thiếu `error_page` -> Gộp lỗi theo 3 files."""
    out = {
        "status": "ok",
        "errors": [],
        "config": [
            {
                "file": "/etc/nginx/conf.d/api1.conf",
                "status": "ok",
                "errors": [],
                "parsed": [_server_block([])]
            },
            {
                "file": "/etc/nginx/conf.d/api2.conf",
                "status": "ok",
                "errors": [],
                "parsed": [_server_block([])]
            },
            {
                "file": "/etc/nginx/conf.d/api3.conf",
                "status": "ok",
                "errors": [],
                "parsed": [_server_block([])]
            }
        ]
    }
    res = detector.scan(out)
    assert len(res) == 3


def test_multifile_deep_path(detector):
    """Test 35: File include nằm sâu trong nhiều cấp thư mục thiếu `error_page`."""
    out = {
        "status": "ok",
        "errors": [],
        "config": [
            {
                "file": "/etc/nginx/conf.d/deep/path/to/app.conf",
                "status": "ok",
                "errors": [],
                "parsed": [_server_block([])]
            }
        ]
    }
    res = detector.scan(out)
    assert len(res) == 1
    assert res[0]["file"] == "/etc/nginx/conf.d/deep/path/to/app.conf"

# --- Cấu trúc lồng nhau và ngoại lệ (Nested structures & edge cases) ---


def test_edge_exact_path_add_server(detector):
    """Test 36: `exact_path` tính toán chính xác khi `add` vào cuối khối `server`."""
    out = _make_parser_output([_http_block([
        _server_block([
            _dir("listen", ["80"])
        ])
    ])])
    res = detector.scan(out)
    assert res[0]["remediations"][0]["exact_path"] == [
        "config", 0, "parsed", 0, "block", 0, "block"]


def test_edge_logical_context(detector):
    """Test 37: `logical_context` của `add` chứa đúng `['http', 'server']`."""
    out = _make_parser_output([_http_block([
        _server_block([])
    ])])
    res = detector.scan(out)
    assert res[0]["remediations"][0]["logical_context"] == ["http", "server"]


def test_edge_quotes(detector):
    """Test 38: Xử lý khi giá trị args của `error_page` được viết bằng chuỗi có dấu ngoặc kép."""
    out = _make_parser_output([_http_block([
        _server_block([
            _dir("error_page", ['"404"', '"/404.html"']),
            _dir("error_page", ["'500'", "'502'",
                 "'503'", "'504'", "'/50x.html'"])
        ])
    ])])
    assert detector.scan(out) == []


def test_edge_duplicates(detector):
    """Test 39: Xử lý nhiều chỉ thị `error_page` định nghĩa trùng lặp."""
    out = _make_parser_output([_http_block([
        _server_block([
            _dir("error_page", ["404", "/404.html"]),
            _dir("error_page", ["404", "/404_2.html"]),
            _dir("error_page", ["500", "502", "503", "504", "/50x.html"])
        ])
    ])])
    assert detector.scan(out) == []


def test_edge_action_always_add(detector):
    """Test 40: Xác minh thuộc tính `action` luôn là `add` khi phát hiện thiếu trang lỗi mặc định."""
    out = _make_parser_output([_http_block([])])
    res = detector.scan(out)
    for rem in res[0]["remediations"]:
        assert rem["action"] == "add"


def test_edge_no_delete_or_replace(detector):
    """Test 41: Xác minh không có hành động `delete` hay `replace` bị tạo nhầm."""
    out = _make_parser_output([_http_block([
        _server_block([
            _dir("error_page", ["403", "/403.html"])
        ])
    ])])
    res = detector.scan(out)
    for r in res[0]["remediations"]:
        assert r["action"] not in ["delete", "replace"]


def test_edge_empty_server(detector):
    """Test 42: Xử lý khi `server` block rỗng (không có directives bên trong)."""
    out = _make_parser_output([_http_block([
        _server_block([])
    ])])
    res = detector.scan(out)
    assert len(res) == 1
    assert res[0]["remediations"][0]["action"] == "add"


def test_edge_empty_http(detector):
    """Test 43: Xử lý khối `http` rỗng (thêm `error_page` vào `http` hoặc `server`)."""
    out = _make_parser_output([_http_block([])])
    res = detector.scan(out)
    assert len(res) == 1
    assert res[0]["remediations"][0]["logical_context"] == ["http"]


def test_edge_env_vars(detector):
    """Test 44: Xử lý khi biến môi trường được dùng trong tham số của `error_page`."""
    out = _make_parser_output([_http_block([
        _server_block([
            _dir("error_page", ["404", "$my_404_page"]),
            _dir("error_page", ["500", "502", "503", "504", "$my_50x_page"])
        ])
    ])])
    assert detector.scan(out) == []


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
    assert rem["directive"] == "error_page"
