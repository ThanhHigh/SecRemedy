import pytest
from core.scannerEng.recommendations.detector_34 import Detector34


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
    return Detector34()

# =====================================================================
# 1. Kiểm tra Siêu dữ liệu (Metadata Sanity Checks) - 3 Test Cases
# =====================================================================


def test_metadata_id(detector):
    """Test 1: ID = '3.4'"""
    assert detector.id == "3.4"


def test_metadata_title(detector):
    """Test 2: Tiêu đề phản ánh đúng chuẩn CIS"""
    assert detector.title == "Đảm bảo các proxy chuyển tiếp thông tin IP nguồn"


def test_metadata_attributes(detector):
    """Test 3: Có các thuộc tính bắt buộc"""
    assert hasattr(detector, "description")
    assert hasattr(detector, "audit_procedure")
    assert hasattr(detector, "impact")
    assert hasattr(detector, "remediation")

# =====================================================================
# 2. Kiểm thử hàm scan(): Toàn bộ đường ống (Full Pipeline Integration) - 42 Test Cases
# =====================================================================

# --- Hợp lệ - Cấu hình Proxy đúng chuẩn (Valid Configuration) ---


def test_valid_proxy_headers_in_location(detector):
    """Test 4: location với proxy_pass và đủ 2 header."""
    out = _make_parser_output([_http_block([
        _server_block([
            _location_block(["/"], [
                _dir("proxy_pass", ["http://backend"]),
                _dir("proxy_set_header", [
                     "X-Forwarded-For", "$proxy_add_x_forwarded_for"]),
                _dir("proxy_set_header", ["X-Real-IP", "$remote_addr"])
            ])
        ])
    ])])
    assert detector.scan(out) == []


def test_valid_proxy_headers_inherited_from_server(detector):
    """Test 5: Kế thừa từ server."""
    out = _make_parser_output([_http_block([
        _server_block([
            _dir("proxy_set_header", [
                 "X-Forwarded-For", "$proxy_add_x_forwarded_for"]),
            _dir("proxy_set_header", ["X-Real-IP", "$remote_addr"]),
            _location_block(["/"], [
                _dir("proxy_pass", ["http://backend"])
            ])
        ])
    ])])
    assert detector.scan(out) == []


def test_valid_proxy_headers_inherited_from_http(detector):
    """Test 6: Kế thừa từ http."""
    out = _make_parser_output([_http_block([
        _dir("proxy_set_header", ["X-Forwarded-For",
             "$proxy_add_x_forwarded_for"]),
        _dir("proxy_set_header", ["X-Real-IP", "$remote_addr"]),
        _server_block([
            _location_block(["/"], [
                _dir("proxy_pass", ["http://backend"])
            ])
        ])
    ])])
    assert detector.scan(out) == []


def test_valid_fastcgi_pass(detector):
    """Test 7: fastcgi_pass hợp lệ."""
    out = _make_parser_output([_http_block([
        _server_block([
            _location_block(["~", "\\.php$"], [
                _dir("fastcgi_pass", ["127.0.0.1:9000"]),
                _dir("fastcgi_param", ["X-Forwarded-For",
                     "$proxy_add_x_forwarded_for"]),
                _dir("fastcgi_param", ["X-Real-IP", "$remote_addr"])
            ])
        ])
    ])])
    assert detector.scan(out) == []


def test_valid_grpc_pass(detector):
    """Test 8: grpc_pass hợp lệ."""
    out = _make_parser_output([_http_block([
        _server_block([
            _location_block(["/"], [
                _dir("grpc_pass", ["grpc://backend"]),
                _dir("grpc_set_header", [
                     "X-Forwarded-For", "$proxy_add_x_forwarded_for"]),
                _dir("grpc_set_header", ["X-Real-IP", "$remote_addr"])
            ])
        ])
    ])])
    assert detector.scan(out) == []


def test_valid_multiple_locations(detector):
    """Test 9: Nhiều location proxy hợp lệ."""
    out = _make_parser_output([_http_block([
        _server_block([
            _location_block(["/a"], [
                _dir("proxy_pass", ["http://backend_a"]),
                _dir("proxy_set_header", [
                     "X-Forwarded-For", "$proxy_add_x_forwarded_for"]),
                _dir("proxy_set_header", ["X-Real-IP", "$remote_addr"])
            ]),
            _location_block(["/b"], [
                _dir("proxy_pass", ["http://backend_b"]),
                _dir("proxy_set_header", [
                     "X-Forwarded-For", "$proxy_add_x_forwarded_for"]),
                _dir("proxy_set_header", ["X-Real-IP", "$remote_addr"])
            ])
        ])
    ])])
    assert detector.scan(out) == []


def test_valid_headers_with_valid_variables(detector):
    """Test 10: Biến header hợp lệ ($remote_addr)."""
    out = _make_parser_output([_http_block([
        _server_block([
            _location_block(["/"], [
                _dir("proxy_pass", ["http://backend"]),
                _dir("proxy_set_header", ["X-Forwarded-For", "$remote_addr"]),
                _dir("proxy_set_header", ["X-Real-IP", "$remote_addr"])
            ])
        ])
    ])])
    assert detector.scan(out) == []


def test_valid_no_proxy(detector):
    """Test 11: location tĩnh, không có proxy."""
    out = _make_parser_output([_http_block([
        _server_block([
            _location_block(["/"], [
                _dir("return", ["200", "OK"])
            ])
        ])
    ])])
    assert detector.scan(out) == []


def test_valid_mixed_inheritance(detector):
    """Test 12: Kế thừa hỗn hợp (1 từ cha, 1 ở local)."""
    out = _make_parser_output([_http_block([
        _dir("proxy_set_header", ["X-Forwarded-For",
             "$proxy_add_x_forwarded_for"]),
        _server_block([
            _location_block(["/"], [
                _dir("proxy_pass", ["http://backend"]),
                _dir("proxy_set_header", ["X-Real-IP", "$remote_addr"])
            ])
        ])
    ])])
    assert detector.scan(out) == []


def test_valid_proxy_pass_in_if(detector):
    """Test 13: proxy_pass trong if."""
    out = _make_parser_output([_http_block([
        _server_block([
            _location_block(["/"], [
                _dir("if", ["($test)"], [
                    _dir("proxy_pass", ["http://backend"])
                ]),
                _dir("proxy_set_header", [
                     "X-Forwarded-For", "$proxy_add_x_forwarded_for"]),
                _dir("proxy_set_header", ["X-Real-IP", "$remote_addr"])
            ])
        ])
    ])])
    assert detector.scan(out) == []

# --- Không hợp lệ - Thiếu thông tin IP nguồn (Missing Proxy Headers) ---


def test_invalid_missing_both(detector):
    """Test 14: location thiếu cả 2 header."""
    out = _make_parser_output([_http_block([
        _server_block([
            _location_block(["/"], [
                _dir("proxy_pass", ["http://backend"])
            ])
        ])
    ])])
    res = detector.scan(out)
    assert len(res) == 1


def test_invalid_missing_real_ip(detector):
    """Test 15: Thiếu X-Real-IP."""
    out = _make_parser_output([_http_block([
        _server_block([
            _location_block(["/"], [
                _dir("proxy_pass", ["http://backend"]),
                _dir("proxy_set_header", [
                     "X-Forwarded-For", "$proxy_add_x_forwarded_for"])
            ])
        ])
    ])])
    res = detector.scan(out)
    assert len(res) == 1


def test_invalid_missing_forwarded_for(detector):
    """Test 16: Thiếu X-Forwarded-For."""
    out = _make_parser_output([_http_block([
        _server_block([
            _location_block(["/"], [
                _dir("proxy_pass", ["http://backend"]),
                _dir("proxy_set_header", ["X-Real-IP", "$remote_addr"])
            ])
        ])
    ])])
    res = detector.scan(out)
    assert len(res) == 1


def test_invalid_fastcgi_missing(detector):
    """Test 17: fastcgi_pass thiếu tham số chuyển tiếp."""
    out = _make_parser_output([_http_block([
        _server_block([
            _location_block(["~", "\\.php$"], [
                _dir("fastcgi_pass", ["127.0.0.1:9000"])
            ])
        ])
    ])])
    res = detector.scan(out)
    assert len(res) == 1


def test_invalid_grpc_missing(detector):
    """Test 18: grpc_pass thiếu header chuyển tiếp."""
    out = _make_parser_output([_http_block([
        _server_block([
            _location_block(["/"], [
                _dir("grpc_pass", ["grpc://backend"])
            ])
        ])
    ])])
    res = detector.scan(out)
    assert len(res) == 1


def test_invalid_misspelled_real_ip(detector):
    """Test 19: X-Real-IP sai chính tả."""
    out = _make_parser_output([_http_block([
        _server_block([
            _location_block(["/"], [
                _dir("proxy_pass", ["http://backend"]),
                _dir("proxy_set_header", [
                     "X-Forwarded-For", "$proxy_add_x_forwarded_for"]),
                _dir("proxy_set_header", ["X-RealIP", "$remote_addr"])
            ])
        ])
    ])])
    res = detector.scan(out)
    assert len(res) == 1


def test_invalid_one_location_missing(detector):
    """Test 20: 1 trong 2 location bị thiếu header."""
    out = _make_parser_output([_http_block([
        _server_block([
            _location_block(["/a"], [
                _dir("proxy_pass", ["http://backend"]),
                _dir("proxy_set_header", [
                     "X-Forwarded-For", "$proxy_add_x_forwarded_for"]),
                _dir("proxy_set_header", ["X-Real-IP", "$remote_addr"])
            ]),
            _location_block(["/b"], [
                _dir("proxy_pass", ["http://backend"])
            ])
        ])
    ])])
    res = detector.scan(out)
    assert len(res) == 1


def test_invalid_override_server(detector):
    """Test 21: Mất kế thừa từ server do khai báo đè."""
    out = _make_parser_output([_http_block([
        _server_block([
            _dir("proxy_set_header", [
                 "X-Forwarded-For", "$proxy_add_x_forwarded_for"]),
            _dir("proxy_set_header", ["X-Real-IP", "$remote_addr"]),
            _location_block(["/"], [
                _dir("proxy_pass", ["http://backend"]),
                _dir("proxy_set_header", ["Host", "$host"])
            ])
        ])
    ])])
    res = detector.scan(out)
    assert len(res) == 1


def test_invalid_override_http(detector):
    """Test 22: Mất kế thừa từ http do khai báo đè."""
    out = _make_parser_output([_http_block([
        _dir("proxy_set_header", ["X-Forwarded-For",
             "$proxy_add_x_forwarded_for"]),
        _dir("proxy_set_header", ["X-Real-IP", "$remote_addr"]),
        _server_block([
            _location_block(["/"], [
                _dir("proxy_pass", ["http://backend"]),
                _dir("proxy_set_header", ["Host", "$host"])
            ])
        ])
    ])])
    res = detector.scan(out)
    assert len(res) == 1


def test_invalid_nested_location(detector):
    """Test 23: Khối nested location thiếu."""
    out = _make_parser_output([_http_block([
        _server_block([
            _location_block(["/"], [
                _location_block(["/api"], [
                    _dir("proxy_pass", ["http://backend"])
                ])
            ])
        ])
    ])])
    res = detector.scan(out)
    assert len(res) == 1


def test_invalid_server_proxy_pass(detector):
    """Test 24: proxy_pass ở server block."""
    out = _make_parser_output([_http_block([
        _server_block([
            _dir("proxy_pass", ["http://backend"])
        ])
    ])])
    res = detector.scan(out)
    assert len(res) == 1


def test_invalid_disabled_explicit(detector):
    """Test 25: X-Forwarded-For bị vô hiệu hóa rõ ràng."""
    out = _make_parser_output([_http_block([
        _server_block([
            _location_block(["/"], [
                _dir("proxy_pass", ["http://backend"]),
                _dir("proxy_set_header", ["X-Forwarded-For", "\"\""]),
                _dir("proxy_set_header", ["X-Real-IP", "$remote_addr"])
            ])
        ])
    ])])
    res = detector.scan(out)
    assert len(res) == 1


def test_invalid_multiple_proxy_in_if(detector):
    """Test 26: Nhiều nhánh if có proxy_pass đều thiếu header."""
    out = _make_parser_output([_http_block([
        _server_block([
            _location_block(["/"], [
                _dir("if", ["($test)"], [
                    _dir("proxy_pass", ["http://backend1"])
                ]),
                _dir("if", ["($test2)"], [
                    _dir("proxy_pass", ["http://backend2"])
                ])
            ])
        ])
    ])])
    res = detector.scan(out)
    assert len(res) == 1


def test_invalid_shared_mistake(detector):
    """Test 27: Cả 2 header sai lỗi chính tả phổ biến."""
    out = _make_parser_output([_http_block([
        _server_block([
            _location_block(["/"], [
                _dir("proxy_pass", ["http://backend"]),
                _dir("proxy_set_header", ["X-Forward-For", "$remote_addr"]),
                _dir("proxy_set_header", ["X-RealIP", "$remote_addr"])
            ])
        ])
    ])])
    res = detector.scan(out)
    assert len(res) == 1


def test_invalid_empty_args(detector):
    """Test 28: Khai báo có nhưng args rỗng."""
    out = _make_parser_output([_http_block([
        _server_block([
            _location_block(["/"], [
                _dir("proxy_pass", ["http://backend"]),
                _dir("proxy_set_header", [])
            ])
        ])
    ])])
    res = detector.scan(out)
    assert len(res) == 1

# --- Cấu hình đa tệp (Multi-file configurations) ---


def test_multifile_app_missing(detector):
    """Test 29: nginx.conf include app.conf, app.conf thiếu."""
    out = {
        "status": "ok", "errors": [], "config": [
            {"file": "nginx.conf", "status": "ok", "errors": [], "parsed": [
                _http_block([_dir("include", ["conf.d/*.conf"])])]},
            {"file": "app.conf", "status": "ok", "errors": [], "parsed": [
                _server_block([_location_block(["/"], [_dir("proxy_pass", ["http://b"])])])]}
        ]
    }
    res = detector.scan(out)
    assert len(res) == 1
    assert res[0]["filepath"] == "app.conf"


def test_multifile_inherited_from_nginx(detector):
    """Test 30: app.conf proxy_pass kế thừa từ http trong nginx.conf."""
    out = {
        "status": "ok", "errors": [], "config": [
            {"file": "nginx.conf", "status": "ok", "errors": [], "parsed": [_http_block([
                _dir("proxy_set_header", [
                     "X-Forwarded-For", "$proxy_add_x_forwarded_for"]),
                _dir("proxy_set_header", ["X-Real-IP", "$remote_addr"]),
                _dir("include", ["conf.d/*.conf"])
            ])]},
            {"file": "app.conf", "status": "ok", "errors": [], "parsed": [
                _server_block([_location_block(["/"], [_dir("proxy_pass", ["http://b"])])])]}
        ]
    }
    res = detector.scan(out)
    assert len(res) == 0


def test_multifile_override_in_app(detector):
    """Test 31: app.conf khai báo đè làm mất kế thừa."""
    out = {
        "status": "ok", "errors": [], "config": [
            {"file": "nginx.conf", "status": "ok", "errors": [], "parsed": [_http_block([
                _dir("proxy_set_header", [
                     "X-Forwarded-For", "$proxy_add_x_forwarded_for"]),
                _dir("proxy_set_header", ["X-Real-IP", "$remote_addr"]),
                _dir("include", ["conf.d/*.conf"])
            ])]},
            {"file": "app.conf", "status": "ok", "errors": [], "parsed": [_server_block([_location_block(["/"], [
                _dir("proxy_pass", ["http://b"]),
                _dir("proxy_set_header", ["Host", "$host"])
            ])])]}
        ]
    }
    res = detector.scan(out)
    assert len(res) == 1
    assert res[0]["filepath"] == "app.conf"


def test_multifile_one_missing(detector):
    """Test 32: Có nhiều file conf, 1 file bị thiếu header."""
    out = {
        "status": "ok", "errors": [], "config": [
            {"file": "1.conf", "status": "ok", "errors": [], "parsed": [_server_block([_location_block(["/"], [
                _dir("proxy_pass", ["http://b"]),
                _dir("proxy_set_header", [
                     "X-Forwarded-For", "$proxy_add_x_forwarded_for"]),
                _dir("proxy_set_header", ["X-Real-IP", "$remote_addr"])
            ])])]},
            {"file": "2.conf", "status": "ok", "errors": [], "parsed": [
                _server_block([_location_block(["/"], [_dir("proxy_pass", ["http://b"])])])]}
        ]
    }
    res = detector.scan(out)
    assert len(res) == 1
    assert res[0]["filepath"] == "2.conf"


def test_multifile_location_include(detector):
    """Test 33: File include ở location thiếu header."""
    out = {
        "status": "ok", "errors": [], "config": [
            {"file": "app.conf", "status": "ok", "errors": [], "parsed": [_server_block([
                _location_block(["/"], [_dir("include", ["loc.conf"])])
            ])]},
            {"file": "loc.conf", "status": "ok", "errors": [], "parsed": [
                _dir("proxy_pass", ["http://b"])
            ]}
        ]
    }
    res = detector.scan(out)
    assert len(res) == 1
    assert res[0]["filepath"] == "loc.conf"


def test_multifile_inherited_from_server_in_same(detector):
    """Test 34: Kế thừa hợp lệ trong cùng 1 file phụ."""
    out = {
        "status": "ok", "errors": [], "config": [
            {"file": "app.conf", "status": "ok", "errors": [], "parsed": [_server_block([
                _dir("proxy_set_header", [
                     "X-Forwarded-For", "$proxy_add_x_forwarded_for"]),
                _dir("proxy_set_header", ["X-Real-IP", "$remote_addr"]),
                _location_block(["/"], [_dir("proxy_pass", ["http://b"])])
            ])]}
        ]
    }
    res = detector.scan(out)
    assert len(res) == 0


def test_multifile_correct_identifier(detector):
    """Test 35: Lỗi định danh đúng file."""
    out = {
        "status": "ok", "errors": [], "config": [
            {"file": "nginx.conf", "status": "ok", "errors": [], "parsed": [
                _http_block([_dir("include", ["conf.d/*.conf"])])]},
            {"file": "app.conf", "status": "ok", "errors": [], "parsed": [
                _server_block([_location_block(["/"], [_dir("proxy_pass", ["http://b"])])])]}
        ]
    }
    res = detector.scan(out)
    assert len(res) == 1
    assert res[0]["filepath"] == "app.conf"


def test_multifile_missing_in_included_params(detector):
    """Test 36: Include file proxy_params thiếu 1 header."""
    out = {
        "status": "ok", "errors": [], "config": [
            {"file": "app.conf", "status": "ok", "errors": [], "parsed": [_server_block([_location_block(["/"], [
                _dir("proxy_pass", ["http://b"]),
                _dir("include", ["proxy_params.conf"])
            ])])]},
            {"file": "proxy_params.conf", "status": "ok", "errors": [], "parsed": [
                _dir("proxy_set_header", [
                     "X-Forwarded-For", "$proxy_add_x_forwarded_for"])
            ]}
        ]
    }
    res = detector.scan(out)
    assert len(res) == 1


def test_multifile_level2_include(detector):
    """Test 37: Include level 2 thiếu header."""
    out = {
        "status": "ok", "errors": [], "config": [
            {"file": "nginx.conf", "status": "ok", "errors": [],
                "parsed": [_http_block([_dir("include", ["app.conf"])])]},
            {"file": "app.conf", "status": "ok", "errors": [], "parsed": [
                _server_block([_dir("include", ["api.conf"])])]},
            {"file": "api.conf", "status": "ok", "errors": [], "parsed": [
                _location_block(["/"], [_dir("proxy_pass", ["http://b"])])]}
        ]
    }
    res = detector.scan(out)
    assert len(res) == 1
    assert res[0]["filepath"] == "api.conf"


def test_multifile_two_includes_missing(detector):
    """Test 38: 2 file include khác nhau cùng thiếu header."""
    out = {
        "status": "ok", "errors": [], "config": [
            {"file": "app1.conf", "status": "ok", "errors": [], "parsed": [
                _server_block([_location_block(["/1"], [_dir("proxy_pass", ["http://b1"])])])]},
            {"file": "app2.conf", "status": "ok", "errors": [], "parsed": [
                _server_block([_location_block(["/2"], [_dir("proxy_pass", ["http://b2"])])])]}
        ]
    }
    res = detector.scan(out)
    assert len(res) == 2

# --- Kiểm tra Payload Remediation và Ngoại lệ cấu trúc ---


def test_edge_payload_missing_both(detector):
    """Test 39: Payload trả về thêm 2 action add."""
    out = _make_parser_output([_http_block([
        _server_block([
            _location_block(["/"], [
                _dir("proxy_pass", ["http://backend"])
            ])
        ])
    ])])
    res = detector.scan(out)
    rems = res[0]["remediations"]
    assert len(rems) == 2
    assert all(r["action"] == "add" for r in rems)


def test_edge_payload_missing_one(detector):
    """Test 40: Payload trả về thêm 1 action add."""
    out = _make_parser_output([_http_block([
        _server_block([
            _location_block(["/"], [
                _dir("proxy_pass", ["http://backend"]),
                _dir("proxy_set_header", ["X-Real-IP", "$remote_addr"])
            ])
        ])
    ])])
    res = detector.scan(out)
    rems = res[0]["remediations"]
    assert len(rems) == 1
    assert rems[0]["directive"] == "proxy_set_header"


def test_edge_exact_path_block(detector):
    """Test 41: Exact path chỉ định đúng block location."""
    out = _make_parser_output([_http_block([
        _server_block([
            _location_block(["/"], [
                _dir("proxy_pass", ["http://backend"])
            ])
        ])
    ])])
    res = detector.scan(out)
    rem = res[0]["remediations"][0]
    assert rem["exact_path"][-1] == "block"


def test_edge_empty_ast(detector):
    """Test 42: AST rỗng -> Pass."""
    out = _make_parser_output([])
    assert detector.scan(out) == []


def test_edge_comments_ignored(detector):
    """Test 43: Comment bị bỏ qua (không có trong AST)."""
    out = _make_parser_output([_http_block([
        _server_block([
            _location_block(["/"], [
                _dir("proxy_pass", ["http://backend"])
            ])
        ])
    ])])
    res = detector.scan(out)
    assert len(res) == 1


def test_edge_logical_context(detector):
    """Test 44: Trả về payload logical_context hợp lý."""
    out = _make_parser_output([_http_block([
        _server_block([
            _location_block(["/"], [
                _dir("proxy_pass", ["http://backend"])
            ])
        ])
    ])])
    res = detector.scan(out)
    rem = res[0]["remediations"][0]
    assert "location" in rem["logical_context"]


def test_edge_grouping(detector):
    """Test 45: Nhóm gom nhiều action delete vào cùng file."""
    out = _make_parser_output([_http_block([
        _server_block([
            _location_block(["/a"], [_dir("proxy_pass", ["http://backend"])]),
            _location_block(["/b"], [_dir("proxy_pass", ["http://backend"])])
        ])
    ])])
    res = detector.scan(out)
    assert len(res) == 1
    assert len(res[0]["remediations"]) == 4
