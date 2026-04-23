import pytest
from core.scannerEng.recommendations.detector_242 import Detector242


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
    return Detector242()

# =====================================================================
# 1. Kiểm tra Siêu dữ liệu (Metadata Sanity Checks) - 3 Test Cases
# =====================================================================


def test_metadata_id(detector):
    """Test 1: ID phải là '2.4.2'"""
    assert detector.id == "2.4.2"


def test_metadata_title(detector):
    """Test 2: Tiêu đề phải đúng"""
    assert detector.title == "Đảm bảo các yêu cầu đến tên máy chủ không xác định bị từ chối"


def test_metadata_attributes(detector):
    """Test 3: Thuộc tính bắt buộc"""
    assert hasattr(detector, "description")
    assert hasattr(detector, "audit_procedure")
    assert hasattr(detector, "impact")
    assert hasattr(detector, "remediation")

# =====================================================================
# 2. Kiểm thử hàm scan() - 42 Test Cases
# =====================================================================

# --- Hợp lệ - Có Catch-All đúng chuẩn (Valid Catch-All) ---


def test_valid_catch_all_http(detector):
    """Test 4: Có `listen 80 default_server;` và `return 444;`."""
    out = _make_parser_output([_http_block([_server_block([
        _dir("listen", ["80", "default_server"]),
        _dir("return", ["444"])
    ])])])
    assert detector.scan(out) == []


def test_valid_catch_all_https(detector):
    """Test 5: Có `listen 443 ssl default_server;`, `return 444;`, `ssl_reject_handshake on;`."""
    out = _make_parser_output([_http_block([_server_block([
        _dir("listen", ["443", "ssl", "default_server"]),
        _dir("ssl_reject_handshake", ["on"]),
        _dir("return", ["444"])
    ])])])
    assert detector.scan(out) == []


def test_valid_catch_all_ipv4_ipv6(detector):
    """Test 6: Có cả IPv4 và IPv6 `default_server` với `return 4xx`."""
    out = _make_parser_output([_http_block([_server_block([
        _dir("listen", ["80", "default_server"]),
        _dir("listen", ["[::]:80", "default_server"]),
        _dir("return", ["404"])
    ])])])
    assert detector.scan(out) == []


def test_valid_catch_all_no_port(detector):
    """Test 7: Có `listen default_server;` trả về `403` hoặc `400`."""
    out = _make_parser_output([_http_block([_server_block([
        _dir("listen", ["default_server"]),
        _dir("return", ["403"])
    ])])])
    assert detector.scan(out) == []


def test_valid_catch_all_in_location(detector):
    """Test 8: Có `listen 80 default_server;` và location `/` chứa `return 444;`."""
    out = _make_parser_output([_http_block([_server_block([
        _dir("listen", ["80", "default_server"]),
        _location_block(["/"], [
            _dir("return", ["444"])
        ])
    ])])])
    assert detector.scan(out) == []

# --- Không hợp lệ - Thiếu Catch-All (Missing Catch-All) ---


def test_missing_server_block(detector):
    """Test 9: Không có khối `server` nào."""
    out = _make_parser_output([_http_block([
        _dir("server_tokens", ["off"])
    ])])
    res = detector.scan(out)
    assert len(res) == 1
    assert res[0]["remediations"][0]["action"] == "add"


def test_missing_default_server_flag(detector):
    """Test 10: Có `server` nhưng không có `default_server`."""
    out = _make_parser_output([_http_block([_server_block([
        _dir("listen", ["80"]),
        _dir("server_name", ["example.com"])
    ])])])
    assert len(detector.scan(out)) == 1


def test_multiple_servers_no_default(detector):
    """Test 11: Có nhiều `server` nhưng không cái nào làm `default_server`."""
    out = _make_parser_output([_http_block([
        _server_block([_dir("listen", ["80"])]),
        _server_block([_dir("listen", ["443", "ssl"])])
    ])])
    assert len(detector.scan(out)) == 1


def test_server_80_no_default(detector):
    """Test 12: Có `server` nghe port 80 nhưng không có `default_server`."""
    out = _make_parser_output([_http_block([_server_block([
        _dir("listen", ["80", "ipv6only=on"])
    ])])])
    assert len(detector.scan(out)) == 1


def test_https_missing_catch_all(detector):
    """Test 13: Cấu hình HTTPS nhưng thiếu khối bắt lỗi HTTPS."""
    out = _make_parser_output([_http_block([
        _server_block([
            _dir("listen", ["80", "default_server"]),
            _dir("return", ["444"])
        ]),
        _server_block([
            _dir("listen", ["443", "ssl"]),
            _dir("server_name", ["example.com"])
        ])
    ])])
    # Expectation: Missing HTTPS catch-all when HTTPS is used
    assert len(detector.scan(out)) == 1


def test_syntax_error_block(detector):
    """Test 14: Chỉ có `listen default_server` trong block lỗi ngữ pháp."""
    out = _make_parser_output([_http_block([_server_block([
        _dir("listen", ["default_server"]),
        # Missing return statement, essentially misconfigured/missing proper catch-all logic
    ])])])
    assert len(detector.scan(out)) == 1


def test_empty_ast(detector):
    """Test 15: Không có cấu hình Nginx (AST rỗng)."""
    out = _make_parser_output([])
    assert len(detector.scan(out)) == 1


def test_empty_http_block(detector):
    """Test 16: Khối `http` rỗng."""
    out = _make_parser_output([_http_block([])])
    assert len(detector.scan(out)) == 1


def test_multi_file_missing_all(detector):
    """Test 17: File cấu hình phụ không có `default_server` và file chính cũng không."""
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
                "parsed": [_server_block([_dir("listen", ["80"])])]
            }
        ]
    }
    assert len(detector.scan(out)) == 1


def test_commented_catch_all(detector):
    """Test 18: Có khối catch-all nhưng bị comment (Crossplane bỏ qua -> Thiếu)."""
    # Crossplane ignores comments, so AST will just have a normal server block without default_server
    out = _make_parser_output([_http_block([
        _server_block([_dir("listen", ["80"])])
    ])])
    assert len(detector.scan(out)) == 1

# --- Không hợp lệ - Catch-All cấu hình sai (Misconfigured Catch-All) ---


def test_misconfigured_missing_return(detector):
    """Test 19: Có `default_server` nhưng không có `return 444` hoặc `4xx`."""
    out = _make_parser_output([_http_block([_server_block([
        _dir("listen", ["80", "default_server"])
    ])])])
    assert len(detector.scan(out)) == 1


def test_misconfigured_return_200(detector):
    """Test 20: Có `default_server` trả về `200`."""
    out = _make_parser_output([_http_block([_server_block([
        _dir("listen", ["80", "default_server"]),
        _dir("return", ["200", "OK"])
    ])])])
    assert len(detector.scan(out)) == 1


def test_misconfigured_return_301(detector):
    """Test 21: Có `default_server` trả về `301` (redirect rủi ro)."""
    out = _make_parser_output([_http_block([_server_block([
        _dir("listen", ["80", "default_server"]),
        _dir("return", ["301", "https://example.com"])
    ])])])
    assert len(detector.scan(out)) == 1


def test_misconfigured_https_missing_reject(detector):
    """Test 22: HTTPS `default_server` thiếu `ssl_reject_handshake on`."""
    out = _make_parser_output([_http_block([_server_block([
        _dir("listen", ["443", "ssl", "default_server"]),
        _dir("return", ["444"])
    ])])])
    assert len(detector.scan(out)) == 1


def test_misconfigured_https_reject_off(detector):
    """Test 23: HTTPS `default_server` có `ssl_reject_handshake off`."""
    out = _make_parser_output([_http_block([_server_block([
        _dir("listen", ["443", "ssl", "default_server"]),
        _dir("ssl_reject_handshake", ["off"]),
        _dir("return", ["444"])
    ])])])
    assert len(detector.scan(out)) == 1


def test_misconfigured_https_return_200(detector):
    """Test 24: HTTP có `return 444`, nhưng HTTPS `default_server` trả về `200`."""
    out = _make_parser_output([_http_block([
        _server_block([
            _dir("listen", ["80", "default_server"]),
            _dir("return", ["444"])
        ]),
        _server_block([
            _dir("listen", ["443", "ssl", "default_server"]),
            _dir("ssl_reject_handshake", ["on"]),
            _dir("return", ["200"])
        ])
    ])])
    assert len(detector.scan(out)) == 1


def test_misconfigured_return_no_default(detector):
    """Test 25: Có `return 444` nhưng thiếu `default_server` trong `listen`."""
    out = _make_parser_output([_http_block([_server_block([
        _dir("listen", ["80"]),
        _dir("return", ["444"])
    ])])])
    assert len(detector.scan(out)) == 1


def test_misconfigured_server_name_underscore(detector):
    """Test 26: Có `server_name _` nhưng không có `return 4xx` chặn lại."""
    out = _make_parser_output([_http_block([_server_block([
        _dir("listen", ["80", "default_server"]),
        _dir("server_name", ["_"])
    ])])])
    assert len(detector.scan(out)) == 1


def test_misconfigured_return_500(detector):
    """Test 27: Trả về `return 500` (không an toàn bằng 4xx/444)."""
    out = _make_parser_output([_http_block([_server_block([
        _dir("listen", ["80", "default_server"]),
        _dir("return", ["500"])
    ])])])
    assert len(detector.scan(out)) == 1


def test_misconfigured_quic_missing_return(detector):
    """Test 28: Có `default_server` HTTP3/QUIC thiếu `return 444`."""
    out = _make_parser_output([_http_block([_server_block([
        _dir("listen", ["443", "quic", "default_server"])
    ])])])
    assert len(detector.scan(out)) == 1

# --- HTTP vs HTTPS vs HTTP3 (Protocols) ---


def test_protocol_missing_http(detector):
    """Test 29: Thiếu block catch-all cho HTTP."""
    out = _make_parser_output([_http_block([
        _server_block([_dir("listen", ["80"])]),
        _server_block([
            _dir("listen", ["443", "ssl", "default_server"]),
            _dir("ssl_reject_handshake", ["on"]),
            _dir("return", ["444"])
        ])
    ])])
    assert len(detector.scan(out)) == 1


def test_protocol_missing_https(detector):
    """Test 30: Thiếu block catch-all cho HTTPS."""
    out = _make_parser_output([_http_block([
        _server_block([
            _dir("listen", ["80", "default_server"]),
            _dir("return", ["444"])
        ]),
        _server_block([_dir("listen", ["443", "ssl"])])
    ])])
    assert len(detector.scan(out)) == 1


def test_protocol_missing_quic(detector):
    """Test 31: Thiếu block catch-all cho QUIC/HTTP3."""
    out = _make_parser_output([_http_block([
        _server_block([
            _dir("listen", ["80", "default_server"]),
            _dir("return", ["444"])
        ]),
        _server_block([
            _dir("listen", ["443", "ssl", "default_server"]),
            _dir("ssl_reject_handshake", ["on"]),
            _dir("return", ["444"])
        ]),
        _server_block([_dir("listen", ["443", "quic"])])
    ])])
    assert len(detector.scan(out)) == 1


def test_protocol_valid_all_three(detector):
    """Test 32: Hợp lệ: Catch-all phủ sóng HTTP, HTTPS, QUIC."""
    out = _make_parser_output([_http_block([_server_block([
        _dir("listen", ["80", "default_server"]),
        _dir("listen", ["443", "ssl", "default_server"]),
        _dir("listen", ["443", "quic", "default_server"]),
        _dir("ssl_reject_handshake", ["on"]),
        _dir("return", ["444"])
    ])])])
    assert detector.scan(out) == []


def test_protocol_has_http_missing_https(detector):
    """Test 33: Lỗi: Có HTTP catch-all, thiếu HTTPS."""
    out = _make_parser_output([_http_block([
        _server_block([
            _dir("listen", ["80", "default_server"]),
            _dir("return", ["444"])
        ]),
        _server_block([
            _dir("listen", ["443", "ssl"])
        ])
    ])])
    assert len(detector.scan(out)) == 1


def test_protocol_has_https_missing_http(detector):
    """Test 34: Lỗi: Có HTTPS catch-all, thiếu HTTP."""
    out = _make_parser_output([_http_block([
        _server_block([
            _dir("listen", ["80"])
        ]),
        _server_block([
            _dir("listen", ["443", "ssl", "default_server"]),
            _dir("ssl_reject_handshake", ["on"]),
            _dir("return", ["444"])
        ])
    ])])
    assert len(detector.scan(out)) == 1


def test_protocol_https_missing_cert(detector):
    """Test 35: Cấu hình HTTPS thiếu ssl_certificate trong block catch-all giả (nếu không dùng reject_handshake)."""
    # CIS requirement generally wants ssl_reject_handshake on to avoid cert leakage.
    # If not present, it's considered uncompliant.
    out = _make_parser_output([_http_block([_server_block([
        _dir("listen", ["443", "ssl", "default_server"]),
        _dir("return", ["444"])
    ])])])
    assert len(detector.scan(out)) == 1

# --- Cấu hình đa tệp (Multi-file configurations) ---


def test_multi_valid_in_main(detector):
    """Test 36: Catch-all nằm ở `nginx.conf`, các file `conf.d/*.conf` không có -> Hợp lệ."""
    out = {
        "status": "ok",
        "errors": [],
        "config": [
            {
                "file": "/etc/nginx/nginx.conf",
                "status": "ok",
                "errors": [],
                "parsed": [_http_block([
                    _server_block([
                        _dir("listen", ["80", "default_server"]),
                        _dir("return", ["444"])
                    ])
                ])]
            },
            {
                "file": "/etc/nginx/conf.d/app.conf",
                "status": "ok",
                "errors": [],
                "parsed": [_server_block([_dir("listen", ["80"])])]
            }
        ]
    }
    assert detector.scan(out) == []


def test_multi_valid_in_child(detector):
    """Test 37: Catch-all nằm ở `conf.d/default.conf`, `nginx.conf` include nó -> Hợp lệ."""
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
                "parsed": [_server_block([
                    _dir("listen", ["80", "default_server"]),
                    _dir("return", ["444"])
                ])]
            }
        ]
    }
    assert detector.scan(out) == []


def test_multi_missing_all(detector):
    """Test 38: Không file nào có catch-all -> Báo lỗi tại `nginx.conf` khối `http`."""
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
                "parsed": [_server_block([_dir("listen", ["80"])])]
            }
        ]
    }
    res = detector.scan(out)
    assert len(res) == 1
    assert res[0]["file"].endswith(
        "nginx.conf") or res[0]["file"].endswith("default.conf")
    assert len(res[0]["remediations"]) > 0


def test_multi_duplicate_default_servers(detector):
    """Test 39: Hai file đều định nghĩa `default_server` -> Vi phạm hoặc cảnh báo trùng lặp."""
    # Depending on implementation, multiple default_servers might be an error or just checked for return 444
    # Assume we check if ALL default_servers properly return 444
    out = {
        "status": "ok",
        "errors": [],
        "config": [
            {
                "file": "/etc/nginx/conf.d/def1.conf",
                "status": "ok",
                "errors": [],
                "parsed": [_server_block([
                    _dir("listen", ["80", "default_server"]),
                    _dir("return", ["200"])  # Fail
                ])]
            },
            {
                "file": "/etc/nginx/conf.d/def2.conf",
                "status": "ok",
                "errors": [],
                "parsed": [_server_block([
                    _dir("listen", ["80", "default_server"]),
                    _dir("return", ["444"])  # Pass
                ])]
            }
        ]
    }
    res = detector.scan(out)
    assert len(res) >= 1


def test_multi_empty_main(detector):
    """Test 40: `nginx.conf` rỗng, chỉ có `conf.d/*.conf` thiếu catch-all -> Báo lỗi vào file `http` chính."""
    out = {
        "status": "ok",
        "errors": [],
        "config": [
            {
                "file": "/etc/nginx/nginx.conf",
                "status": "ok",
                "errors": [],
                "parsed": []
            },
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

# --- Cấu trúc lồng nhau và ngoại lệ (Nested structures & edge cases) ---


def test_nested_location_return(detector):
    """Test 41: `return 444` nằm sâu trong `location /` của `default_server` -> Hợp lệ."""
    out = _make_parser_output([_http_block([_server_block([
        _dir("listen", ["80", "default_server"]),
        _location_block(["/"], [
            _dir("return", ["444"])
        ])
    ])])])
    assert detector.scan(out) == []


def test_nested_if_condition(detector):
    """Test 42: `return 444` có điều kiện `if` -> Thường vi phạm (yêu cầu không có if)."""
    out = _make_parser_output([_http_block([_server_block([
        _dir("listen", ["80", "default_server"]),
        _dir("if", ["($host)"], [
            _dir("return", ["444"])
        ])
    ])])])
    assert len(detector.scan(out)) == 1


def test_edge_no_http_block(detector):
    """Test 43: Lỗi cấu trúc AST: Không có khối `http` ở file gốc -> Báo lỗi thiếu `http`."""
    out = _make_parser_output([_dir("events", [], [])])
    res = detector.scan(out)
    assert len(res) == 1


def test_edge_action_add_payload(detector):
    """Test 44: Kiểm tra `exact_path` và `action: add` sinh ra đúng payload json để Auto-Remediate chèn block vào cuối `http`."""
    out = _make_parser_output([_http_block([
        _server_block([_dir("listen", ["80"])])
    ])])
    res = detector.scan(out)
    rem = res[0]["remediations"][0]
    assert rem["action"] == "add"
    assert "exact_path" in rem


def test_edge_add_block_content(detector):
    """Test 45: Đảm bảo payload thêm khối catch-all chuẩn (port 80 & 443 ssl_reject_handshake)."""
    out = _make_parser_output([_http_block([
        _server_block([_dir("listen", ["80"])])
    ])])
    res = detector.scan(out)
    rem = res[0]["remediations"][0]
    assert "block" in rem
    block_dirs = [d["directive"] for d in rem["block"]]
    assert "listen" in block_dirs
    assert "return" in block_dirs
