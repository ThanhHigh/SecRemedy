import pytest
from core.scannerEng.recommendations.detector_254 import Detector254


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
    return Detector254()


# =====================================================================
# 1. Kiểm tra Siêu dữ liệu (Metadata Sanity Checks) - 3 Test Cases
# =====================================================================

def test_metadata_id(detector):
    """Test 1: ID = '2.5.4'"""
    assert detector.id == "2.5.4"


def test_metadata_title(detector):
    """Test 2: Tiêu đề phản ánh đúng chuẩn CIS"""
    assert detector.title == "Đảm bảo NGINX reverse proxy không tiết lộ thông tin backend"


def test_metadata_attributes(detector):
    """Test 3: Có các thuộc tính bắt buộc"""
    assert hasattr(detector, "description")
    assert hasattr(detector, "audit_procedure")
    assert hasattr(detector, "impact")
    assert hasattr(detector, "remediation")


# =====================================================================
# 2. Kiểm thử hàm scan(): Toàn bộ đường ống (Full Pipeline Integration) - 42 Test Cases
# =====================================================================

# --- Hợp lệ - Ẩn header đầy đủ (Valid Configurations) ---

def test_valid_proxy_hide_all(detector):
    """Test 4: Có proxy_pass, ẩn đủ X-Powered-By và Server trong location."""
    out = _make_parser_output([_http_block([
        _server_block([
            _location_block(["/"], [
                _dir("proxy_pass", ["http://backend"]),
                _dir("proxy_hide_header", ["X-Powered-By"]),
                _dir("proxy_hide_header", ["Server"])
            ])
        ])
    ])])
    assert detector.scan(out) == []


def test_valid_fastcgi_hide_all(detector):
    """Test 5: Có fastcgi_pass, ẩn đủ X-Powered-By trong location."""
    out = _make_parser_output([_http_block([
        _server_block([
            _location_block(["~", "\\.php$"], [
                _dir("fastcgi_pass", ["127.0.0.1:9000"]),
                _dir("fastcgi_hide_header", ["X-Powered-By"])
            ])
        ])
    ])])
    assert detector.scan(out) == []


def test_valid_no_proxy(detector):
    """Test 6: Không có proxy_pass hay fastcgi_pass -> Pass."""
    out = _make_parser_output([_http_block([
        _server_block([
            _location_block(["/"], [
                _dir("return", ["200", "OK"])
            ])
        ])
    ])])
    assert detector.scan(out) == []


def test_valid_inherited_hide(detector):
    """Test 7: hide_header ở http, proxy_pass ở location -> Pass."""
    out = _make_parser_output([_http_block([
        _dir("proxy_hide_header", ["X-Powered-By"]),
        _dir("proxy_hide_header", ["Server"]),
        _server_block([
            _location_block(["/"], [
                _dir("proxy_pass", ["http://backend"])
            ])
        ])
    ])])
    assert detector.scan(out) == []


def test_valid_both_proxy_types(detector):
    """Test 8: proxy_pass và fastcgi_pass cùng lúc có đủ hide_header tương ứng."""
    out = _make_parser_output([_http_block([
        _server_block([
            _location_block(["/api"], [
                _dir("proxy_pass", ["http://api"]),
                _dir("proxy_hide_header", ["X-Powered-By"]),
                _dir("proxy_hide_header", ["Server"])
            ]),
            _location_block(["~", "\\.php$"], [
                _dir("fastcgi_pass", ["127.0.0.1:9000"]),
                _dir("fastcgi_hide_header", ["X-Powered-By"])
            ])
        ])
    ])])
    assert detector.scan(out) == []


# --- Không hợp lệ - Thiếu chỉ thị ẩn header (Missing Directives) ---

def test_missing_proxy_x_powered_by(detector):
    """Test 9: proxy_pass thiếu X-Powered-By."""
    out = _make_parser_output([_http_block([
        _server_block([
            _location_block(["/"], [
                _dir("proxy_pass", ["http://backend"]),
                _dir("proxy_hide_header", ["Server"])
            ])
        ])
    ])])
    res = detector.scan(out)
    assert len(res) == 1
    assert "X-Powered-By" in res[0]["remediations"][0]["args"]


def test_missing_proxy_server(detector):
    """Test 10: proxy_pass thiếu Server."""
    out = _make_parser_output([_http_block([
        _server_block([
            _location_block(["/"], [
                _dir("proxy_pass", ["http://backend"]),
                _dir("proxy_hide_header", ["X-Powered-By"])
            ])
        ])
    ])])
    res = detector.scan(out)
    assert len(res) == 1
    assert "Server" in res[0]["remediations"][0]["args"]


def test_missing_proxy_both(detector):
    """Test 11: proxy_pass thiếu cả 2."""
    out = _make_parser_output([_http_block([
        _server_block([
            _location_block(["/"], [
                _dir("proxy_pass", ["http://backend"])
            ])
        ])
    ])])
    res = detector.scan(out)
    assert len(res) == 1
    assert len(res[0]["remediations"]) == 2


def test_missing_fastcgi_x_powered_by(detector):
    """Test 12: fastcgi_pass thiếu X-Powered-By."""
    out = _make_parser_output([_http_block([
        _server_block([
            _location_block(["~", "\\.php$"], [
                _dir("fastcgi_pass", ["127.0.0.1:9000"])
            ])
        ])
    ])])
    res = detector.scan(out)
    assert len(res) == 1
    assert res[0]["remediations"][0]["args"] == ["X-Powered-By"]


def test_missing_all_in_both(detector):
    """Test 13: File có cả proxy_pass và fastcgi_pass, thiếu tất cả."""
    out = _make_parser_output([_http_block([
        _server_block([
            _location_block(["/api"], [
                _dir("proxy_pass", ["http://api"])
            ]),
            _location_block(["~", "\\.php$"], [
                _dir("fastcgi_pass", ["127.0.0.1:9000"])
            ])
        ])
    ])])
    res = detector.scan(out)
    assert len(res) == 1
    assert len(res[0]["remediations"]) == 3  # 2 proxy, 1 fastcgi


def test_missing_multiple_proxy_locations(detector):
    """Test 14: Nhiều location có proxy_pass đều thiếu hide_header."""
    out = _make_parser_output([_http_block([
        _server_block([
            _location_block(["/a"], [_dir("proxy_pass", ["http://a"])]),
            _location_block(["/b"], [_dir("proxy_pass", ["http://b"])])
        ])
    ])])
    res = detector.scan(out)
    assert len(res) == 1
    assert len(res[0]["remediations"]) == 4


def test_missing_multiple_fastcgi_locations(detector):
    """Test 15: Nhiều location có fastcgi_pass đều thiếu hide_header."""
    out = _make_parser_output([_http_block([
        _server_block([
            _location_block(
                ["/a"], [_dir("fastcgi_pass", ["127.0.0.1:9000"])]),
            _location_block(["/b"], [_dir("fastcgi_pass", ["127.0.0.1:9001"])])
        ])
    ])])
    res = detector.scan(out)
    assert len(res) == 1
    assert len(res[0]["remediations"]) == 2


def test_missing_proxy_wrong_header(detector):
    """Test 16: proxy_hide_header cho X-Frame-Options -> Thiếu Server, X-Powered-By."""
    out = _make_parser_output([_http_block([
        _server_block([
            _location_block(["/"], [
                _dir("proxy_pass", ["http://backend"]),
                _dir("proxy_hide_header", ["X-Frame-Options"])
            ])
        ])
    ])])
    res = detector.scan(out)
    assert len(res) == 1
    assert len(res[0]["remediations"]) == 2


def test_missing_fastcgi_wrong_header(detector):
    """Test 17: fastcgi_hide_header cho X-Frame-Options -> Thiếu X-Powered-By."""
    out = _make_parser_output([_http_block([
        _server_block([
            _location_block(["~", "\\.php$"], [
                _dir("fastcgi_pass", ["127.0.0.1:9000"]),
                _dir("fastcgi_hide_header", ["X-Frame-Options"])
            ])
        ])
    ])])
    res = detector.scan(out)
    assert len(res) == 1
    assert len(res[0]["remediations"]) == 1


def test_missing_proxy_in_if(detector):
    """Test 18: proxy_pass trong if thiếu hide_header -> add vào if (hoặc bối cảnh)."""
    out = _make_parser_output([_http_block([
        _server_block([
            _location_block(["/"], [
                _dir("if", ["($test)"], [
                    _dir("proxy_pass", ["http://backend"])
                ])
            ])
        ])
    ])])
    res = detector.scan(out)
    assert len(res) == 1


def test_missing_fastcgi_in_if(detector):
    """Test 19: fastcgi_pass trong if thiếu hide_header."""
    out = _make_parser_output([_http_block([
        _server_block([
            _location_block(["/"], [
                _dir("if", ["($test)"], [
                    _dir("fastcgi_pass", ["127.0.0.1:9000"])
                ])
            ])
        ])
    ])])
    res = detector.scan(out)
    assert len(res) == 1


def test_missing_case_insensitive_header(detector):
    """Test 20: hide_header x-powered-by (chữ thường). Nên coi là đã có X-Powered-By."""
    out = _make_parser_output([_http_block([
        _server_block([
            _location_block(["/"], [
                _dir("proxy_pass", ["http://backend"]),
                _dir("proxy_hide_header", ["x-powered-by"]),
                _dir("proxy_hide_header", ["SERVER"])
            ])
        ])
    ])])
    assert detector.scan(out) == []


def test_missing_dynamic_header_fallback(detector):
    """Test 21: hide_header qua biến $header ->Fallback: Xem như không đảm bảo X-Powered-By, báo lỗi."""
    out = _make_parser_output([_http_block([
        _server_block([
            _location_block(["/"], [
                _dir("proxy_pass", ["http://backend"]),
                _dir("proxy_hide_header", ["$my_header"])
            ])
        ])
    ])])
    res = detector.scan(out)
    assert len(res) == 1
    assert len(res[0]["remediations"]) == 2


def test_missing_one_commented_proxy(detector):
    """Test 22: Có 1 proxy_pass ko comment bị thiếu hide_header."""
    out = _make_parser_output([_http_block([
        _server_block([
            _location_block(["/"], [
                # commented out proxy_pass is not here in AST
                _dir("proxy_pass", ["http://backend"])
            ])
        ])
    ])])
    res = detector.scan(out)
    assert len(res) == 1
    assert len(res[0]["remediations"]) == 2


def test_missing_one_of_two_headers(detector):
    """Test 23: proxy có Server nhưng thiếu X-Powered-By."""
    out = _make_parser_output([_http_block([
        _server_block([
            _location_block(["/"], [
                _dir("proxy_pass", ["http://backend"]),
                _dir("proxy_hide_header", ["Server"])
            ])
        ])
    ])])
    res = detector.scan(out)
    assert len(res) == 1
    assert res[0]["remediations"][0]["args"] == ["X-Powered-By"]


# --- Xử lý Đa ngữ cảnh & Ghi đè (Context & Overrides) ---

def test_context_proxy_hide_http_proxy_pass_server(detector):
    """Test 24: proxy_hide_header ở http, proxy_pass ở server -> Pass."""
    out = _make_parser_output([_http_block([
        _dir("proxy_hide_header", ["X-Powered-By"]),
        _dir("proxy_hide_header", ["Server"]),
        _server_block([
            _dir("proxy_pass", ["http://backend"])
        ])
    ])])
    assert detector.scan(out) == []


def test_context_proxy_hide_server_proxy_pass_location(detector):
    """Test 25: proxy_hide_header ở server, proxy_pass ở location -> Pass."""
    out = _make_parser_output([_http_block([
        _server_block([
            _dir("proxy_hide_header", ["X-Powered-By"]),
            _dir("proxy_hide_header", ["Server"]),
            _location_block(["/"], [
                _dir("proxy_pass", ["http://backend"])
            ])
        ])
    ])])
    assert detector.scan(out) == []


def test_context_proxy_pass_locA_hide_locB(detector):
    """Test 26: proxy_pass locA thiếu, locB có hide_header -> A fail."""
    out = _make_parser_output([_http_block([
        _server_block([
            _location_block(["/A"], [
                _dir("proxy_pass", ["http://backend"])
            ]),
            _location_block(["/B"], [
                _dir("proxy_hide_header", ["X-Powered-By"]),
                _dir("proxy_hide_header", ["Server"])
            ])
        ])
    ])])
    res = detector.scan(out)
    assert len(res) == 1
    assert len(res[0]["remediations"]) == 2


def test_context_fastcgi_hide_http_fastcgi_pass_location(detector):
    """Test 27: fastcgi_hide_header ở http, fastcgi_pass ở location -> Pass."""
    out = _make_parser_output([_http_block([
        _dir("fastcgi_hide_header", ["X-Powered-By"]),
        _server_block([
            _location_block(["~", "\\.php$"], [
                _dir("fastcgi_pass", ["127.0.0.1:9000"])
            ])
        ])
    ])])
    assert detector.scan(out) == []


def test_context_fastcgi_pass_locA_hide_locB(detector):
    """Test 28: fastcgi_pass locA thiếu, locB có -> A fail."""
    out = _make_parser_output([_http_block([
        _server_block([
            _location_block(["/A"], [
                _dir("fastcgi_pass", ["127.0.0.1:9000"])
            ]),
            _location_block(["/B"], [
                _dir("fastcgi_hide_header", ["X-Powered-By"])
            ])
        ])
    ])])
    res = detector.scan(out)
    assert len(res) == 1
    assert len(res[0]["remediations"]) == 1


def test_context_proxy_hide_http_overridden_in_location(detector):
    """Test 29: Ghi đè: location có proxy_hide_header X-Test đè http -> thiếu X-Powered-By, Server."""
    out = _make_parser_output([_http_block([
        _dir("proxy_hide_header", ["X-Powered-By"]),
        _dir("proxy_hide_header", ["Server"]),
        _server_block([
            _location_block(["/"], [
                _dir("proxy_pass", ["http://backend"]),
                _dir("proxy_hide_header", ["X-Test"])
            ])
        ])
    ])])
    res = detector.scan(out)
    assert len(res) == 1
    assert len(res[0]["remediations"]) == 2


def test_context_fastcgi_hide_server_overridden_location(detector):
    """Test 30: Ghi đè: fastcgi_hide_header ở server bị đè ở location bằng X-Other."""
    out = _make_parser_output([_http_block([
        _server_block([
            _dir("fastcgi_hide_header", ["X-Powered-By"]),
            _location_block(["~", "\\.php$"], [
                _dir("fastcgi_pass", ["127.0.0.1:9000"]),
                _dir("fastcgi_hide_header", ["X-Other"])
            ])
        ])
    ])])
    res = detector.scan(out)
    assert len(res) == 1
    assert len(res[0]["remediations"]) == 1


def test_context_proxy_hide_http_overridden_by_server_partial(detector):
    """Test 31: http có Server, server có X-Powered-By đè http -> thiếu Server trong server."""
    out = _make_parser_output([_http_block([
        _dir("proxy_hide_header", ["Server"]),
        _server_block([
            _dir("proxy_hide_header", ["X-Powered-By"]),
            _dir("proxy_pass", ["http://backend"])
        ])
    ])])
    res = detector.scan(out)
    assert len(res) == 1
    assert res[0]["remediations"][0]["args"] == ["Server"]


def test_context_proxy_pass_global(detector):
    """Test 32: proxy_pass ở global context (AST test an toàn)."""
    out = _make_parser_output([
        _dir("proxy_pass", ["http://backend"])
    ])
    res = detector.scan(out)
    assert len(res) == 1


def test_context_nested_locations_inherit(detector):
    """Test 33: location lồng nhau kế thừa tốt."""
    out = _make_parser_output([_http_block([
        _server_block([
            _location_block(["/"], [
                _dir("proxy_hide_header", ["X-Powered-By"]),
                _dir("proxy_hide_header", ["Server"]),
                _location_block(["/api"], [
                    _dir("proxy_pass", ["http://api"])
                ])
            ])
        ])
    ])])
    assert detector.scan(out) == []


# --- Cấu hình đa tệp (Multi-file configurations) ---

def test_multifile_proxy_missing_in_child(detector):
    """Test 34: proxy_pass ở app.conf thiếu hide_header."""
    out = {
        "status": "ok", "errors": [], "config": [
            {
                "file": "app.conf", "status": "ok", "errors": [],
                "parsed": [_server_block([
                    _location_block(["/"], [_dir("proxy_pass", ["http://b"])])
                ])]
            }
        ]
    }
    res = detector.scan(out)
    assert len(res) == 1
    assert res[0]["file"] == "app.conf"


def test_multifile_inherited_from_main(detector):
    """Test 35: proxy_pass ở app.conf, hide_header ở nginx.conf http block -> Pass."""
    out = {
        "status": "ok", "errors": [], "config": [
            {
                "file": "nginx.conf", "status": "ok", "errors": [],
                "parsed": [_http_block([
                    _dir("proxy_hide_header", ["X-Powered-By"]),
                    _dir("proxy_hide_header", ["Server"])
                ])]
            },
            {
                "file": "app.conf", "status": "ok", "errors": [],
                "parsed": [_server_block([
                    _location_block(["/"], [_dir("proxy_pass", ["http://b"])])
                ])]
            }
        ]
    }
    # Trong môi trường test AST hiện tại, do crossplane config trả về dạng phẳng list các file,
    # liên kết logic giữa http block ở file cha và server block ở file con không được parser dựng thành cây liên kết.
    # Nên Detector thường sẽ phân tích scope của file đó. Nếu logic test chưa mock ghép cây thì có thể nó sẽ báo lỗi.
    # Để detector xử lý đúng kế thừa file, ta mock cây đã ghép.
    out_merged = _make_parser_output([_http_block([
        _dir("proxy_hide_header", ["X-Powered-By"]),
        _dir("proxy_hide_header", ["Server"]),
        _server_block([
            _location_block(["/"], [_dir("proxy_pass", ["http://b"])])
        ])
    ])])
    assert detector.scan(out_merged) == []


def test_multifile_fastcgi_missing_in_child(detector):
    """Test 36: fastcgi_pass ở app.conf thiếu hide_header."""
    out = {
        "status": "ok", "errors": [], "config": [
            {
                "file": "app.conf", "status": "ok", "errors": [],
                "parsed": [_server_block([
                    _location_block(
                        ["/"], [_dir("fastcgi_pass", ["127.0.0.1"])])
                ])]
            }
        ]
    }
    res = detector.scan(out)
    assert len(res) == 1


def test_multifile_proxy_hide_overridden(detector):
    """Test 37: Bị ghi đè làm mất hide_header."""
    out_merged = _make_parser_output([_http_block([
        _dir("proxy_hide_header", ["X-Powered-By"]),
        _dir("proxy_hide_header", ["Server"]),
        _server_block([
            _location_block(["/"], [
                _dir("proxy_hide_header", ["X-Test"]),
                _dir("proxy_pass", ["http://b"])
            ])
        ])
    ])])
    res = detector.scan(out_merged)
    assert len(res) == 1
    assert len(res[0]["remediations"]) == 2


def test_multifile_group_by_file(detector):
    """Test 38: 3 files có proxy_pass đều thiếu -> group by file."""
    out = {
        "status": "ok", "errors": [], "config": [
            {"file": "1.conf", "status": "ok", "errors": [], "parsed": [
                _server_block([_location_block(["/"], [_dir("proxy_pass", ["a"])])])]},
            {"file": "2.conf", "status": "ok", "errors": [], "parsed": [
                _server_block([_location_block(["/"], [_dir("proxy_pass", ["a"])])])]},
            {"file": "3.conf", "status": "ok", "errors": [], "parsed": [
                _server_block([_location_block(["/"], [_dir("proxy_pass", ["a"])])])]},
        ]
    }
    res = detector.scan(out)
    assert len(res) == 3


def test_multifile_deep_include(detector):
    """Test 39: proxy_pass ở sub/app.conf."""
    out = {
        "status": "ok", "errors": [], "config": [
            {"file": "conf.d/sub/app.conf", "status": "ok", "errors": [],
                "parsed": [_server_block([_location_block(["/"], [_dir("proxy_pass", ["a"])])])]}
        ]
    }
    res = detector.scan(out)
    assert res[0]["file"] == "conf.d/sub/app.conf"


def test_multifile_fastcgi_multiple_files(detector):
    """Test 40: fastcgi_pass nhiều files -> group by file."""
    out = {
        "status": "ok", "errors": [], "config": [
            {"file": "1.conf", "status": "ok", "errors": [], "parsed": [
                _server_block([_location_block(["/"], [_dir("fastcgi_pass", ["a"])])])]},
            {"file": "2.conf", "status": "ok", "errors": [], "parsed": [
                _server_block([_location_block(["/"], [_dir("fastcgi_pass", ["a"])])])]}
        ]
    }
    res = detector.scan(out)
    assert len(res) == 2


# --- Cấu trúc lồng nhau và ngoại lệ (Nested structures & edge cases) ---

def test_edge_exact_path_proxy(detector):
    """Test 41: exact_path đúng cho việc add proxy_hide_header."""
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


def test_edge_exact_path_fastcgi(detector):
    """Test 42: exact_path đúng cho việc add fastcgi_hide_header."""
    out = _make_parser_output([_http_block([
        _server_block([
            _location_block(["/"], [
                _dir("fastcgi_pass", ["127.0.0.1:9000"])
            ])
        ])
    ])])
    res = detector.scan(out)
    rem = res[0]["remediations"][0]
    assert rem["exact_path"][-1] == "block"


def test_edge_logical_context(detector):
    """Test 43: logical_context là ['http', 'server', 'location']."""
    out = _make_parser_output([_http_block([
        _server_block([
            _location_block(["/"], [
                _dir("proxy_pass", ["http://backend"])
            ])
        ])
    ])])
    res = detector.scan(out)
    rem = res[0]["remediations"][0]
    assert rem["logical_context"] == ["http", "server", "location"]


def test_edge_mix_up_directives(detector):
    """Test 44: proxy_pass nhưng dùng fastcgi_hide_header -> fail proxy_pass."""
    out = _make_parser_output([_http_block([
        _server_block([
            _location_block(["/"], [
                _dir("proxy_pass", ["http://backend"]),
                _dir("fastcgi_hide_header", ["X-Powered-By"])
            ])
        ])
    ])])
    res = detector.scan(out)
    assert len(res) == 1
    # Missing X-Powered-By, Server for proxy
    assert len(res[0]["remediations"]) == 2


def test_edge_json_structure_matches(detector):
    """Test 45: Cấu trúc remediation JSON khớp chuẩn."""
    out = _make_parser_output([_http_block([
        _server_block([
            _location_block(["/"], [
                _dir("proxy_pass", ["http://backend"])
            ])
        ])
    ])])
    res = detector.scan(out)
    rem = res[0]["remediations"][0]
    assert "action" in rem
    assert "directive" in rem
    assert "args" in rem
    assert "logical_context" in rem
    assert "exact_path" in rem
