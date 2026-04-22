import pytest
from core.scannerEng.recommendations.detector_411 import Detector411

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
    return Detector411()

# =====================================================================
# 1. Kiểm tra Siêu dữ liệu (Metadata Sanity Checks) - 3 Test Cases
# =====================================================================

def test_metadata_id(detector):
    """Test 1: ID phải là '4.1.1'"""
    assert detector.id == "4.1.1"

def test_metadata_title(detector):
    """Test 2: Tiêu đề phải đúng"""
    assert detector.title == "Đảm bảo HTTP được chuyển hướng sang HTTPS"

def test_metadata_attributes(detector):
    """Test 3: Thuộc tính bắt buộc"""
    assert hasattr(detector, "description")
    assert hasattr(detector, "audit_procedure")
    assert hasattr(detector, "impact")
    assert hasattr(detector, "remediation")

# =====================================================================
# 2. Kiểm thử hàm scan() - 42 Test Cases
# =====================================================================

# --- Hợp lệ - Đã cấu hình chuyển hướng (Valid Configurations) ---

def test_valid_redirect_301_host(detector):
    """Test 4: Khối `server` lắng nghe port 80 và có `return 301 https://$host$request_uri;`."""
    out = _make_parser_output([_http_block([
        _server_block([
            _dir("listen", ["80"]),
            _dir("return", ["301", "https://$host$request_uri"])
        ])
    ])])
    assert detector.scan(out) == []

def test_valid_redirect_301_domain(detector):
    """Test 5: Khối `server` lắng nghe port 80 và có `return 301 https://example.com$request_uri;`."""
    out = _make_parser_output([_http_block([
        _server_block([
            _dir("listen", ["80"]),
            _dir("return", ["301", "https://example.com$request_uri"])
        ])
    ])])
    assert detector.scan(out) == []

def test_valid_redirect_302(detector):
    """Test 6: Khối `server` lắng nghe port 80 và có `return 302 https://$host$request_uri;`."""
    out = _make_parser_output([_http_block([
        _server_block([
            _dir("listen", ["80"]),
            _dir("return", ["302", "https://$host$request_uri"])
        ])
    ])])
    assert detector.scan(out) == []

def test_valid_listen_ssl_only(detector):
    """Test 7: Khối `server` lắng nghe port 443 với tham số `ssl` (không cần chuyển hướng, bỏ qua)."""
    out = _make_parser_output([_http_block([
        _server_block([
            _dir("listen", ["443", "ssl"])
        ])
    ])])
    assert detector.scan(out) == []

def test_valid_listen_both_with_redirect(detector):
    """Test 8: Khối `server` lắng nghe cả port 80 và 8080, có `return 301 https://$host$request_uri;`."""
    out = _make_parser_output([_http_block([
        _server_block([
            _dir("listen", ["80"]),
            _dir("listen", ["8080"]),
            _dir("return", ["301", "https://$host$request_uri"])
        ])
    ])])
    assert detector.scan(out) == []

# --- Không hợp lệ - Thiếu hoàn toàn chuyển hướng (Missing Entirely) ---

def test_missing_redirect(detector):
    """Test 9: Khối `server` lắng nghe port 80 không có chỉ thị `return` -> Trả về `add`."""
    out = _make_parser_output([_http_block([
        _server_block([
            _dir("listen", ["80"])
        ])
    ])])
    res = detector.scan(out)
    assert len(res) == 1
    assert res[0]["remediations"][0]["action"] == "add"
    assert res[0]["remediations"][0]["directive"] == "return"

def test_missing_with_location(detector):
    """Test 10: Khối `server` lắng nghe port 80 có khối `location /` -> Trả về `add`."""
    out = _make_parser_output([_http_block([
        _server_block([
            _dir("listen", ["80"]),
            _location_block(["/"], [
                _dir("root", ["/var/www/html"])
            ])
        ])
    ])])
    res = detector.scan(out)
    assert len(res) == 1
    assert res[0]["remediations"][0]["action"] == "add"

def test_missing_default_port(detector):
    """Test 11: Khối `server` không có tham số port (mặc định Nginx là 80) thiếu `return` -> Trả về `add`."""
    out = _make_parser_output([_http_block([
        _server_block([
            _dir("server_name", ["example.com"])
        ])
    ])])
    res = detector.scan(out)
    assert len(res) == 1
    assert res[0]["remediations"][0]["action"] == "add"

def test_missing_multiple_servers(detector):
    """Test 12: Nhiều khối `server` lắng nghe port 80 đều thiếu `return` -> Trả về `add` cho từng `server`."""
    out = _make_parser_output([_http_block([
        _server_block([_dir("listen", ["80"])]),
        _server_block([_dir("listen", ["80"])])
    ])])
    res = detector.scan(out)
    assert len(res) == 1
    assert len(res[0]["remediations"]) == 2

def test_missing_mixed_ports(detector):
    """Test 13: Khối `server` lắng nghe cả 80 và 443 nhưng thiếu `return`."""
    out = _make_parser_output([_http_block([
        _server_block([
            _dir("listen", ["80"]),
            _dir("listen", ["443", "ssl"])
        ])
    ])])
    res = detector.scan(out)
    assert len(res) == 1
    assert res[0]["remediations"][0]["action"] == "add"

def test_missing_empty_server(detector):
    """Test 14: Khối `server` rỗng (không có directive nào) -> Trả về `add`."""
    out = _make_parser_output([_http_block([
        _server_block([])
    ])])
    res = detector.scan(out)
    assert len(res) == 1
    assert res[0]["remediations"][0]["action"] == "add"

def test_missing_only_listen_servername(detector):
    """Test 15: Khối `server` chỉ chứa `listen` và `server_name`, thiếu `return`."""
    out = _make_parser_output([_http_block([
        _server_block([
            _dir("listen", ["80"]),
            _dir("server_name", ["test.com"])
        ])
    ])])
    res = detector.scan(out)
    assert len(res) == 1
    assert res[0]["remediations"][0]["action"] == "add"

def test_missing_in_include_file(detector):
    """Test 16: Khối `server` nằm trong file include thiếu `return`."""
    out = {
        "status": "ok",
        "errors": [],
        "config": [
            {
                "file": "/etc/nginx/conf.d/app.conf",
                "status": "ok",
                "errors": [],
                "parsed": [_server_block([_dir("listen", ["80"])])]
            }
        ]
    }
    res = detector.scan(out)
    assert len(res) == 1
    assert res[0]["filepath"] == "/etc/nginx/conf.d/app.conf"
    assert res[0]["remediations"][0]["action"] == "add"

def test_missing_commented_redirect(detector):
    """Test 17: Chỉ thị chuyển hướng bị comment (AST bỏ qua) -> Trả về `add`."""
    out = _make_parser_output([_http_block([
        _server_block([
            _dir("listen", ["80"]),
            _dir("server_name", ["test.com"])
        ])
    ])])
    res = detector.scan(out)
    assert len(res) == 1
    assert res[0]["remediations"][0]["action"] == "add"

def test_missing_with_proxy_pass(detector):
    """Test 18: Block `server` 80 làm proxy nhưng quên chuyển hướng HTTP sang HTTPS -> Trả về `add`."""
    out = _make_parser_output([_http_block([
        _server_block([
            _dir("listen", ["80"]),
            _location_block(["/"], [
                _dir("proxy_pass", ["http://127.0.0.1:8080"])
            ])
        ])
    ])])
    res = detector.scan(out)
    assert len(res) == 1
    assert res[0]["remediations"][0]["action"] == "add"

# --- Không hợp lệ - Chuyển hướng sai hoặc không phải HTTPS (Invalid Redirects) ---

def test_invalid_redirect_http(detector):
    """Test 19: Có `return 301 http://$host$request_uri;` -> Trả về `replace`."""
    out = _make_parser_output([_http_block([
        _server_block([
            _dir("listen", ["80"]),
            _dir("return", ["301", "http://$host$request_uri"])
        ])
    ])])
    res = detector.scan(out)
    assert len(res) == 1
    assert res[0]["remediations"][0]["action"] == "replace"

def test_invalid_redirect_200(detector):
    """Test 20: Có `return 200 "OK";` trong khối `server` port 80 -> Trả về `replace`."""
    out = _make_parser_output([_http_block([
        _server_block([
            _dir("listen", ["80"]),
            _dir("return", ["200", "OK"])
        ])
    ])])
    res = detector.scan(out)
    assert len(res) == 1
    assert res[0]["remediations"][0]["action"] == "replace"

def test_invalid_redirect_404(detector):
    """Test 21: Có `return 404;` trong khối `server` port 80 -> Trả về `replace`."""
    out = _make_parser_output([_http_block([
        _server_block([
            _dir("listen", ["80"]),
            _dir("return", ["404"])
        ])
    ])])
    res = detector.scan(out)
    assert len(res) == 1
    assert res[0]["remediations"][0]["action"] == "replace"

def test_invalid_redirect_relative(detector):
    """Test 22: Có chuyển hướng tương đối `return 301 /path;` -> Báo lỗi `replace`."""
    out = _make_parser_output([_http_block([
        _server_block([
            _dir("listen", ["80"]),
            _dir("return", ["301", "/path"])
        ])
    ])])
    res = detector.scan(out)
    assert len(res) == 1
    assert res[0]["remediations"][0]["action"] == "replace"

def test_invalid_redirect_rewrite_http(detector):
    """Test 23: Sử dụng `rewrite` chuyển hướng sang HTTP -> Trả về `add` hoặc `replace`."""
    out = _make_parser_output([_http_block([
        _server_block([
            _dir("listen", ["80"]),
            _dir("rewrite", ["^(.*)$", "http://$host$1", "permanent"])
        ])
    ])])
    res = detector.scan(out)
    assert len(res) == 1
    # rewrite sai thì thêm return vào
    assert res[0]["remediations"][0]["action"] in ["add", "replace"]

def test_invalid_redirect_missing_url(detector):
    """Test 24: Chỉ thị `return` thiếu URL (`return 301;`) -> Báo lỗi `replace`."""
    out = _make_parser_output([_http_block([
        _server_block([
            _dir("listen", ["80"]),
            _dir("return", ["301"])
        ])
    ])])
    res = detector.scan(out)
    assert len(res) == 1
    assert res[0]["remediations"][0]["action"] == "replace"

def test_invalid_redirect_in_location_only(detector):
    """Test 25: `return 301 https...` nằm trong `location` (không bảo vệ toàn cục) -> `add` ở `server`."""
    out = _make_parser_output([_http_block([
        _server_block([
            _dir("listen", ["80"]),
            _location_block(["/"], [
                _dir("return", ["301", "https://$host$request_uri"])
            ])
        ])
    ])])
    res = detector.scan(out)
    assert len(res) == 1
    assert res[0]["remediations"][0]["action"] == "add"
    assert res[0]["remediations"][0]["logical_context"] == ["http", "server"]

# --- Xử lý đa ngữ cảnh (Context Bindings) ---

def test_context_location_return_200(detector):
    """Test 26: `server` có `return 301 https...` hợp lệ, `location` con có `return 200` -> Hợp lệ."""
    out = _make_parser_output([_http_block([
        _server_block([
            _dir("listen", ["80"]),
            _dir("return", ["301", "https://$host$request_uri"]),
            _location_block(["/"], [
                _dir("return", ["200", "OK"])
            ])
        ])
    ])])
    assert detector.scan(out) == []

def test_context_multiple_listens_one_return(detector):
    """Test 27: `server` có nhiều `listen`, 1 `return 301 https...` -> Hợp lệ."""
    out = _make_parser_output([_http_block([
        _server_block([
            _dir("listen", ["80"]),
            _dir("listen", ["8080"]),
            _dir("return", ["301", "https://$host$request_uri"])
        ])
    ])])
    assert detector.scan(out) == []

def test_context_return_outside_server(detector):
    """Test 28: `return 301 https...` nằm ở `http` -> Lỗi, `server` 80 thiếu chuyển hướng -> `add`."""
    out = _make_parser_output([_http_block([
        _dir("return", ["301", "https://$host$request_uri"]),
        _server_block([
            _dir("listen", ["80"])
        ])
    ])])
    res = detector.scan(out)
    assert len(res) == 1
    assert res[0]["remediations"][0]["action"] == "add"

def test_context_return_in_if(detector):
    """Test 29: `return` hợp lệ nằm trong `if` -> Hợp lệ."""
    out = _make_parser_output([_http_block([
        _server_block([
            _dir("listen", ["80"]),
            _dir("if", ["($scheme = http)"], [
                _dir("return", ["301", "https://$host$request_uri"])
            ])
        ])
    ])])
    assert detector.scan(out) == []

def test_context_mixed_servers(detector):
    """Test 30: Một `server` 80 hợp lệ, một `server` 80 thiếu -> Chỉ báo lỗi cho `server` thiếu."""
    out = _make_parser_output([_http_block([
        _server_block([
            _dir("listen", ["80"]),
            _dir("return", ["301", "https://$host$request_uri"])
        ]),
        _server_block([
            _dir("listen", ["80"])
        ])
    ])])
    res = detector.scan(out)
    assert len(res) == 1
    assert len(res[0]["remediations"]) == 1

# --- Cấu hình đa tệp (Multi-file configurations) ---

def test_multifile_main_missing_child_valid(detector):
    """Test 31: `nginx.conf` có `server` 80 thiếu, `app.conf` có `server` 80 hợp lệ -> Lỗi ở `nginx.conf`."""
    out = {
        "status": "ok",
        "errors": [],
        "config": [
            {
                "file": "/etc/nginx/nginx.conf",
                "status": "ok",
                "errors": [],
                "parsed": [_http_block([_server_block([_dir("listen", ["80"])])])]
            },
            {
                "file": "/etc/nginx/conf.d/app.conf",
                "status": "ok",
                "errors": [],
                "parsed": [_server_block([
                    _dir("listen", ["80"]),
                    _dir("return", ["301", "https://$host$request_uri"])
                ])]
            }
        ]
    }
    res = detector.scan(out)
    assert len(res) == 1
    assert res[0]["filepath"] == "/etc/nginx/nginx.conf"

def test_multifile_main_none_child_missing(detector):
    """Test 32: `nginx.conf` không có `server`, `api.conf` có `server` 80 thiếu -> Lỗi ở `api.conf`."""
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
                "file": "/etc/nginx/conf.d/api.conf",
                "status": "ok",
                "errors": [],
                "parsed": [_server_block([_dir("listen", ["80"])])]
            }
        ]
    }
    res = detector.scan(out)
    assert len(res) == 1
    assert res[0]["filepath"] == "/etc/nginx/conf.d/api.conf"

def test_multifile_both_missing(detector):
    """Test 33: Cả hai file đều có `server` 80 thiếu chuyển hướng -> Báo lỗi cả 2."""
    out = {
        "status": "ok",
        "errors": [],
        "config": [
            {
                "file": "/etc/nginx/nginx.conf",
                "status": "ok",
                "errors": [],
                "parsed": [_http_block([_server_block([_dir("listen", ["80"])])])]
            },
            {
                "file": "/etc/nginx/conf.d/api.conf",
                "status": "ok",
                "errors": [],
                "parsed": [_server_block([_dir("listen", ["80"])])]
            }
        ]
    }
    res = detector.scan(out)
    assert len(res) == 2

def test_multifile_three_files(detector):
    """Test 34: 3 file cấu hình chứa `server` 80, tất cả đều thiếu -> Gộp theo 3 files."""
    out = {
        "status": "ok",
        "errors": [],
        "config": [
            {
                "file": f"/etc/nginx/conf.d/api{i}.conf",
                "status": "ok",
                "errors": [],
                "parsed": [_server_block([_dir("listen", ["80"])])]
            } for i in range(3)
        ]
    }
    res = detector.scan(out)
    assert len(res) == 3

def test_multifile_deep_include_missing(detector):
    """Test 35: File include nằm sâu định nghĩa `server` 80 thiếu -> Trả về đúng tên file."""
    out = {
        "status": "ok",
        "errors": [],
        "config": [
            {
                "file": "/etc/nginx/conf.d/sub/app.conf",
                "status": "ok",
                "errors": [],
                "parsed": [_server_block([_dir("listen", ["80"])])]
            }
        ]
    }
    res = detector.scan(out)
    assert len(res) == 1
    assert res[0]["filepath"] == "/etc/nginx/conf.d/sub/app.conf"

# --- Cấu trúc lồng nhau và ngoại lệ (Nested structures & edge cases) ---

def test_edge_exact_path_add(detector):
    """Test 36: `exact_path` tính toán chính xác khi `add` vào khối `server`."""
    out = _make_parser_output([_http_block([
        _server_block([_dir("listen", ["80"])])
    ])])
    res = detector.scan(out)
    rem = res[0]["remediations"][0]
    assert rem["exact_path"] == ["config", 0, "parsed", 0, "block", 0, "block"]

def test_edge_logical_context(detector):
    """Test 37: `logical_context` chứa đúng `['http', 'server']`."""
    out = _make_parser_output([_http_block([
        _server_block([_dir("listen", ["80"])])
    ])])
    res = detector.scan(out)
    rem = res[0]["remediations"][0]
    assert rem["logical_context"] == ["http", "server"]

def test_edge_quotes_double(detector):
    """Test 38: Xử lý giá trị có ngoặc kép `return 301 "https://$host$request_uri";`."""
    out = _make_parser_output([_http_block([
        _server_block([
            _dir("listen", ["80"]),
            _dir("return", ["301", '"https://$host$request_uri"'])
        ])
    ])])
    assert detector.scan(out) == []

def test_edge_listen_multiple_args(detector):
    """Test 39: Chỉ thị `listen` có nhiều tham số `listen 80 default_server reuseport;` thiếu return."""
    out = _make_parser_output([_http_block([
        _server_block([
            _dir("listen", ["80", "default_server", "reuseport"])
        ])
    ])])
    res = detector.scan(out)
    assert len(res) == 1
    assert res[0]["remediations"][0]["action"] == "add"

def test_edge_action_verify(detector):
    """Test 40: Xác minh `action` là `replace` khi có chuyển hướng sai."""
    out = _make_parser_output([_http_block([
        _server_block([
            _dir("listen", ["80"]),
            _dir("return", ["301", "http://bad"])
        ])
    ])])
    res = detector.scan(out)
    assert res[0]["remediations"][0]["action"] == "replace"

def test_edge_ipv6_only(detector):
    """Test 41: Khối `server` chỉ chứa cấu hình IPv6 `listen [::]:80;` thiếu `return`."""
    out = _make_parser_output([_http_block([
        _server_block([
            _dir("listen", ["[::]:80"])
        ])
    ])])
    res = detector.scan(out)
    assert len(res) == 1
    assert res[0]["remediations"][0]["action"] == "add"

def test_edge_ipv4_and_ipv6(detector):
    """Test 42: `listen 80;` và `listen [::]:80;` thiếu `return`."""
    out = _make_parser_output([_http_block([
        _server_block([
            _dir("listen", ["80"]),
            _dir("listen", ["[::]:80"])
        ])
    ])])
    res = detector.scan(out)
    assert len(res) == 1
    assert res[0]["remediations"][0]["action"] == "add"

def test_edge_redirect_308(detector):
    """Test 43: Hỗ trợ chuyển hướng 308 `return 308 https://$host$request_uri;`."""
    out = _make_parser_output([_http_block([
        _server_block([
            _dir("listen", ["80"]),
            _dir("return", ["308", "https://$host$request_uri"])
        ])
    ])])
    assert detector.scan(out) == []

def test_edge_custom_env_var(detector):
    """Test 44: URL `return` chứa biến môi trường tùy chỉnh `https://$custom_host...` -> Hợp lệ."""
    out = _make_parser_output([_http_block([
        _server_block([
            _dir("listen", ["80"]),
            _dir("return", ["301", "https://$custom_host$request_uri"])
        ])
    ])])
    assert detector.scan(out) == []

def test_edge_payload_structure(detector):
    """Test 45: Đảm bảo cấu trúc payload JSON `remediations` khớp hoàn toàn với `scan_result.json`."""
    out = _make_parser_output([_http_block([
        _server_block([
            _dir("listen", ["80"])
        ])
    ])])
    res = detector.scan(out)
    rem = res[0]["remediations"][0]
    assert "action" in rem
    assert "directive" in rem
    assert "args" in rem
    assert "logical_context" in rem
    assert "exact_path" in rem
    assert rem["action"] == "add"
    assert rem["directive"] == "return"
    assert rem["args"] == ["301", "https://$host$request_uri"]
