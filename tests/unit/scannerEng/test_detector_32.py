import pytest
from core.scannerEng.recommendations.detector_32 import Detector32


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
    return Detector32()


# =====================================================================
# 1. Kiểm tra Siêu dữ liệu (Metadata Sanity Checks) - 3 Test Cases
# =====================================================================

def test_metadata_id(detector):
    """Test 1: ID = '3.2'"""
    assert detector.id == "3.2"


def test_metadata_title(detector):
    """Test 2: Tiêu đề phản ánh đúng chuẩn CIS"""
    assert detector.title == "Đảm bảo tính năng ghi log truy cập (access_log) được bật"


def test_metadata_attributes(detector):
    """Test 3: Có các thuộc tính bắt buộc"""
    assert hasattr(detector, "description")
    assert hasattr(detector, "audit_procedure")
    assert hasattr(detector, "impact")
    assert hasattr(detector, "remediation")


# =====================================================================
# 2. Kiểm thử hàm scan(): Toàn bộ đường ống (Full Pipeline Integration) - 42 Test Cases
# =====================================================================

# --- Hợp lệ - Bật Access Log đúng chuẩn (Valid Configuration) ---

def test_valid_access_log_http(detector):
    """Test 4: access_log hợp lệ trong khối http."""
    out = _make_parser_output([_http_block([
        _dir("access_log", ["/var/log/nginx/access.log"])
    ])])
    assert detector.scan(out) == []


def test_valid_access_log_server(detector):
    """Test 5: access_log hợp lệ trong khối server."""
    out = _make_parser_output([_http_block([
        _server_block([
            _dir("access_log", ["/var/log/nginx/access.log"])
        ])
    ])])
    assert detector.scan(out) == []


def test_valid_access_log_location(detector):
    """Test 6: access_log hợp lệ trong khối location /."""
    out = _make_parser_output([_http_block([
        _server_block([
            _location_block(["/"], [
                _dir("access_log", ["/var/log/nginx/access.log"])
            ])
        ])
    ])])
    assert detector.scan(out) == []


def test_valid_implicit_access_log(detector):
    """Test 7: Không khai báo access_log (Mặc định Nginx bật log) -> Pass."""
    out = _make_parser_output([_http_block([
        _server_block([
            _location_block(["/"], [
                _dir("return", ["200", "OK"])
            ])
        ])
    ])])
    assert detector.scan(out) == []


def test_valid_access_log_with_format(detector):
    """Test 8: Cấu hình access_log có định dạng custom."""
    out = _make_parser_output([_http_block([
        _dir("access_log", ["/var/log/nginx/access.log", "main_json"])
    ])])
    assert detector.scan(out) == []


def test_valid_exception_favicon(detector):
    """Test 9: access_log off; đúng ngoại lệ location = /favicon.ico."""
    out = _make_parser_output([_http_block([
        _server_block([
            _location_block(["=", "/favicon.ico"], [
                _dir("access_log", ["off"])
            ])
        ])
    ])])
    assert detector.scan(out) == []


def test_valid_exception_robots(detector):
    """Test 10: access_log off; đúng ngoại lệ location = /robots.txt."""
    out = _make_parser_output([_http_block([
        _server_block([
            _location_block(["=", "/robots.txt"], [
                _dir("access_log", ["off"])
            ])
        ])
    ])])
    assert detector.scan(out) == []


def test_valid_exception_static_files(detector):
    """Test 11: access_log off; cho ngoại lệ static files."""
    out = _make_parser_output([_http_block([
        _server_block([
            _location_block(["~*", "\\.(css|js|jpg|jpeg|png)$"], [
                _dir("access_log", ["off"])
            ])
        ])
    ])])
    assert detector.scan(out) == []


def test_valid_multiple_access_logs(detector):
    """Test 12: Nhiều access_log hợp lệ trong http."""
    out = _make_parser_output([_http_block([
        _dir("access_log", ["/var/log/nginx/access1.log"]),
        _dir("access_log", ["/var/log/nginx/access2.log"])
    ])])
    assert detector.scan(out) == []


def test_valid_inheritance(detector):
    """Test 13: http có access_log hợp lệ, server kế thừa -> Pass."""
    out = _make_parser_output([_http_block([
        _dir("access_log", ["/var/log/nginx/access.log"]),
        _server_block([
            _location_block(["/"], [
                _dir("return", ["200", "OK"])
            ])
        ])
    ])])
    assert detector.scan(out) == []


# --- Không hợp lệ - Tắt Access Log (access_log off;) ---

def test_invalid_http_access_log_off(detector):
    """Test 14: access_log off; ở http."""
    out = _make_parser_output([_http_block([
        _dir("access_log", ["off"])
    ])])
    res = detector.scan(out)
    assert len(res) == 1
    assert res[0]["remediations"][0]["action"] == "delete"


def test_invalid_server_access_log_off(detector):
    """Test 15: access_log off; ở server."""
    out = _make_parser_output([_http_block([
        _server_block([
            _dir("access_log", ["off"])
        ])
    ])])
    res = detector.scan(out)
    assert len(res) == 1


def test_invalid_both_http_server(detector):
    """Test 16: access_log off; ở cả http và server."""
    out = _make_parser_output([_http_block([
        _dir("access_log", ["off"]),
        _server_block([
            _dir("access_log", ["off"])
        ])
    ])])
    res = detector.scan(out)
    assert len(res) == 1
    assert len(res[0]["remediations"]) == 2


def test_invalid_server_only_off(detector):
    """Test 17: http mặc định, server tắt log."""
    out = _make_parser_output([_http_block([
        _server_block([
            _dir("access_log", ["off"])
        ])
    ])])
    res = detector.scan(out)
    assert len(res) == 1


def test_invalid_server_overrides_http(detector):
    """Test 18: http bật log, server ghi đè tắt log."""
    out = _make_parser_output([_http_block([
        _dir("access_log", ["/var/log/nginx/access.log"]),
        _server_block([
            _dir("access_log", ["off"])
        ])
    ])])
    res = detector.scan(out)
    assert len(res) == 1


def test_invalid_location_root_off(detector):
    """Test 19: access_log off; ở location /."""
    out = _make_parser_output([_http_block([
        _server_block([
            _location_block(["/"], [
                _dir("access_log", ["off"])
            ])
        ])
    ])])
    res = detector.scan(out)
    assert len(res) == 1


def test_invalid_location_php_off(detector):
    """Test 20: access_log off; ở location ~.php$."""
    out = _make_parser_output([_http_block([
        _server_block([
            _location_block(["~", "\\.php$"], [
                _dir("access_log", ["off"])
            ])
        ])
    ])])
    res = detector.scan(out)
    assert len(res) == 1


def test_invalid_multiple_servers_all_off(detector):
    """Test 21: Nhiều server đều tắt log."""
    out = _make_parser_output([_http_block([
        _server_block([_dir("access_log", ["off"])]),
        _server_block([_dir("access_log", ["off"])])
    ])])
    res = detector.scan(out)
    assert len(res) == 1
    assert len(res[0]["remediations"]) == 2


def test_invalid_location_api_off(detector):
    """Test 22: access_log off; ở location /api/."""
    out = _make_parser_output([_http_block([
        _server_block([
            _location_block(["/api/"], [
                _dir("access_log", ["off"])
            ])
        ])
    ])])
    res = detector.scan(out)
    assert len(res) == 1


def test_invalid_ssl_server_off(detector):
    """Test 23: server ssl bị tắt log."""
    out = _make_parser_output([_http_block([
        _server_block([
            _dir("listen", ["443", "ssl"]),
            _dir("access_log", ["off"])
        ])
    ])])
    res = detector.scan(out)
    assert len(res) == 1


def test_invalid_case_insensitive_off(detector):
    """Test 24: access_log OFF;."""
    out = _make_parser_output([_http_block([
        _server_block([
            _dir("access_log", ["OFF"])
        ])
    ])])
    res = detector.scan(out)
    assert len(res) == 1


def test_invalid_quoted_off(detector):
    """Test 25: access_log "off";."""
    out = _make_parser_output([_http_block([
        _dir("access_log", ["\"off\""])
    ])])
    res = detector.scan(out)
    assert len(res) == 1


def test_invalid_mix_off_and_path(detector):
    """Test 26: Có access_log off; cùng với access_log /path/."""
    out = _make_parser_output([_http_block([
        _server_block([
            _dir("access_log", ["/var/log/nginx/access.log"]),
            _dir("access_log", ["off"])
        ])
    ])])
    res = detector.scan(out)
    assert len(res) == 1
    assert len(res[0]["remediations"]) == 1


def test_invalid_off_with_extra_args(detector):
    """Test 27: access_log off có thêm tham số."""
    out = _make_parser_output([_http_block([
        _server_block([
            _dir("access_log", ["off", "main"])
        ])
    ])])
    res = detector.scan(out)
    assert len(res) == 1


def test_invalid_repeated_off(detector):
    """Test 28: Lặp lại access_log off;."""
    out = _make_parser_output([_http_block([
        _server_block([
            _dir("access_log", ["off"]),
            _dir("access_log", ["off"])
        ])
    ])])
    res = detector.scan(out)
    assert len(res) == 1
    assert len(res[0]["remediations"]) == 2


# --- Cấu hình đa tệp (Multi-file configurations) ---

def test_multifile_child_server_off(detector):
    """Test 29: nginx.conf bật log, app.conf tắt log."""
    out = {
        "status": "ok", "errors": [], "config": [
            {
                "file": "nginx.conf", "status": "ok", "errors": [],
                "parsed": [_http_block([_dir("access_log", ["/var/log/nginx/access.log"])])]
            },
            {
                "file": "app.conf", "status": "ok", "errors": [],
                "parsed": [_server_block([_dir("access_log", ["off"])])]
            }
        ]
    }
    res = detector.scan(out)
    assert len(res) == 1
    assert res[0]["file"] == "app.conf"


def test_multifile_parent_http_off(detector):
    """Test 30: app.conf bật log, nginx.conf tắt log."""
    out = {
        "status": "ok", "errors": [], "config": [
            {
                "file": "nginx.conf", "status": "ok", "errors": [],
                "parsed": [_http_block([_dir("access_log", ["off"])])]
            },
            {
                "file": "app.conf", "status": "ok", "errors": [],
                "parsed": [_server_block([_dir("access_log", ["/var/log/nginx/access.log"])])]
            }
        ]
    }
    res = detector.scan(out)
    assert len(res) == 1
    assert res[0]["file"] == "nginx.conf"


def test_multifile_all_children_off(detector):
    """Test 31: Tất cả file trong conf.d đều tắt log."""
    out = {
        "status": "ok", "errors": [], "config": [
            {"file": "1.conf", "status": "ok", "errors": [], "parsed": [
                _server_block([_dir("access_log", ["off"])])]},
            {"file": "2.conf", "status": "ok", "errors": [], "parsed": [
                _server_block([_dir("access_log", ["off"])])]}
        ]
    }
    res = detector.scan(out)
    assert len(res) == 2


def test_multifile_included_location_off(detector):
    """Test 32: access_log off; ở location trong file include."""
    out = {
        "status": "ok", "errors": [], "config": [
            {
                "file": "sub.conf", "status": "ok", "errors": [],
                "parsed": [_location_block(["/api"], [_dir("access_log", ["off"])])]
            }
        ]
    }
    res = detector.scan(out)
    assert len(res) == 1


def test_multifile_parent_off_child_on(detector):
    """Test 33: nginx.conf tắt log, admin.conf bật log -> Lỗi ở nginx.conf."""
    out = {
        "status": "ok", "errors": [], "config": [
            {
                "file": "nginx.conf", "status": "ok", "errors": [],
                "parsed": [_http_block([_dir("access_log", ["off"])])]
            },
            {
                "file": "admin.conf", "status": "ok", "errors": [],
                "parsed": [_server_block([_dir("access_log", ["/var/log/nginx/admin.log"])])]
            }
        ]
    }
    res = detector.scan(out)
    assert len(res) == 1
    assert res[0]["file"] == "nginx.conf"


def test_multifile_exception_include(detector):
    """Test 34: File include ngoại lệ (favicon) chứa access_log off; -> Pass."""
    out = {
        "status": "ok", "errors": [], "config": [
            {
                "file": "favicon.conf", "status": "ok", "errors": [],
                "parsed": [_location_block(["=", "/favicon.ico"], [_dir("access_log", ["off"])])]
            }
        ]
    }
    assert detector.scan(out) == []


def test_multifile_multiple_locations_off(detector):
    """Test 35: Hai file conf khác nhau đều tắt log ở location /."""
    out = {
        "status": "ok", "errors": [], "config": [
            {"file": "1.conf", "status": "ok", "errors": [], "parsed": [
                _location_block(["/"], [_dir("access_log", ["off"])])]},
            {"file": "2.conf", "status": "ok", "errors": [], "parsed": [
                _location_block(["/"], [_dir("access_log", ["off"])])]}
        ]
    }
    res = detector.scan(out)
    assert len(res) == 2


def test_multifile_server_includes_off(detector):
    """Test 36: Server include file tắt log."""
    out_merged = _make_parser_output([_http_block([
        _server_block([
            _dir("access_log", ["off"])
        ])
    ])])
    res = detector.scan(out_merged)
    assert len(res) == 1


def test_multifile_off_in_if(detector):
    """Test 37: access_log off; trong block if."""
    out = _make_parser_output([_http_block([
        _server_block([
            _location_block(["/"], [
                _dir("if", ["($test)"], [
                    _dir("access_log", ["off"])
                ])
            ])
        ])
    ])])
    res = detector.scan(out)
    assert len(res) == 1


def test_multifile_no_http_block_server_off(detector):
    """Test 38: File ko có http, chỉ có server tắt log."""
    out = _make_parser_output([
        _server_block([
            _dir("access_log", ["off"])
        ])
    ])
    res = detector.scan(out)
    assert len(res) == 1


# --- Kiểm tra Payload Remediation và Ngoại lệ cấu trúc ---

def test_edge_payload_http(detector):
    """Test 39: Payload action: delete cho http."""
    out = _make_parser_output([_http_block([
        _dir("access_log", ["off"])
    ])])
    res = detector.scan(out)
    rem = res[0]["remediations"][0]
    assert rem["action"] == "delete"
    assert rem["directive"] == "access_log"


def test_edge_payload_server(detector):
    """Test 40: Payload action: delete cho server."""
    out = _make_parser_output([_http_block([
        _server_block([
            _dir("access_log", ["off"])
        ])
    ])])
    res = detector.scan(out)
    rem = res[0]["remediations"][0]
    assert rem["action"] == "delete"
    assert rem["exact_path"][-1] == 0


def test_edge_multiple_deletes(detector):
    """Test 41: Nhiều vi phạm trả về mảng delete."""
    out = _make_parser_output([_http_block([
        _server_block([
            _location_block(["/a"], [_dir("access_log", ["off"])]),
            _location_block(["/b"], [_dir("access_log", ["off"])])
        ])
    ])])
    res = detector.scan(out)
    assert len(res[0]["remediations"]) == 2


def test_edge_empty_config(detector):
    """Test 42: Cấu hình rỗng -> Pass."""
    out = _make_parser_output([])
    assert detector.scan(out) == []


def test_edge_dev_null(detector):
    """Test 43: access_log trỏ tới /dev/null."""
    out = _make_parser_output([_http_block([
        _dir("access_log", ["/dev/null"])
    ])])
    res = detector.scan(out)
    assert len(res) == 1


def test_edge_exact_path_index(detector):
    """Test 44: Xử lý index exact_path."""
    out = _make_parser_output([_http_block([
        _server_block([
            _dir("server_name", ["test"]),
            _dir("listen", ["80"]),
            _dir("access_log", ["off"])
        ])
    ])])
    res = detector.scan(out)
    rem = res[0]["remediations"][0]
    assert rem["exact_path"][-1] == 2


def test_edge_delete_only_off(detector):
    """Test 45: delete không ảnh hưởng access_log khác."""
    out = _make_parser_output([_http_block([
        _server_block([
            _dir("access_log", ["/var/log/test.log"]),
            _dir("access_log", ["off"])
        ])
    ])])
    res = detector.scan(out)
    assert len(res) == 1
    rem = res[0]["remediations"]
    assert len(rem) == 1
    assert rem[0]["exact_path"][-1] == 1
