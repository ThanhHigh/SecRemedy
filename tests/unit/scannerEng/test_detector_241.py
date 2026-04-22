import pytest
from core.scannerEng.recommendations.detector_241 import Detector241


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
    return Detector241()

# =====================================================================
# 1. Kiểm tra Siêu dữ liệu (Metadata Sanity Checks)
# =====================================================================


def test_metadata_id(detector):
    """Test 1: ID phải là '2.4.1'"""
    assert detector.id == "2.4.1"


def test_metadata_title(detector):
    """Test 2: Tiêu đề phải đúng"""
    assert detector.title == "Đảm bảo NGINX chỉ lắng nghe kết nối mạng trên các cổng được ủy quyền"


def test_metadata_attributes(detector):
    """Test 3: Thuộc tính bắt buộc"""
    assert hasattr(detector, "description")
    assert hasattr(detector, "audit_procedure")
    assert hasattr(detector, "impact")
    assert hasattr(detector, "remediation")

# =====================================================================
# 2. Kiểm thử hàm scan()
# =====================================================================

# --- Hợp lệ - Cổng tiêu chuẩn ---


def test_valid_port_80(detector):
    """Test 4: Chỉ chứa listen 80"""
    out = _make_parser_output(
        [_http_block([_server_block([_dir("listen", ["80"])])])])
    assert detector.scan(out) == []


def test_valid_port_443(detector):
    """Test 5: Chỉ chứa listen 443"""
    out = _make_parser_output(
        [_http_block([_server_block([_dir("listen", ["443"])])])])
    assert detector.scan(out) == []


def test_valid_port_8080(detector):
    """Test 6: Chỉ chứa listen 8080"""
    out = _make_parser_output(
        [_http_block([_server_block([_dir("listen", ["8080"])])])])
    assert detector.scan(out) == []


def test_valid_port_80_and_443(detector):
    """Test 7: 80 và 443 cùng block"""
    out = _make_parser_output([_http_block([_server_block([
        _dir("listen", ["80"]),
        _dir("listen", ["443", "ssl"])
    ])])])
    assert detector.scan(out) == []


def test_valid_port_8443_and_9000(detector):
    """Test 8: 8443 và 9000"""
    out = _make_parser_output([_http_block([_server_block([
        _dir("listen", ["8443", "ssl"]),
        _dir("listen", ["9000"])
    ])])])
    assert detector.scan(out) == []

# --- Không hợp lệ - Cổng trái phép ---


def test_invalid_port_8000(detector):
    """Test 9: listen 8000 -> delete"""
    out = _make_parser_output(
        [_http_block([_server_block([_dir("listen", ["8000"])])])])
    res = detector.scan(out)
    assert len(res) == 1
    assert len(res[0]["remediations"]) == 1
    assert res[0]["remediations"][0]["action"] == "delete"
    assert res[0]["remediations"][0]["directive"] == "listen"


def test_invalid_port_8001(detector):
    """Test 10: listen 8001"""
    out = _make_parser_output(
        [_http_block([_server_block([_dir("listen", ["8001"])])])])
    assert len(detector.scan(out)[0]["remediations"]) == 1


def test_invalid_port_8444(detector):
    """Test 11: listen 8444"""
    out = _make_parser_output(
        [_http_block([_server_block([_dir("listen", ["8444"])])])])
    assert len(detector.scan(out)[0]["remediations"]) == 1


def test_invalid_port_21(detector):
    """Test 12: listen 21"""
    out = _make_parser_output(
        [_http_block([_server_block([_dir("listen", ["21"])])])])
    assert len(detector.scan(out)[0]["remediations"]) == 1


def test_invalid_port_22(detector):
    """Test 13: listen 22"""
    out = _make_parser_output(
        [_http_block([_server_block([_dir("listen", ["22"])])])])
    assert len(detector.scan(out)[0]["remediations"]) == 1


def test_mixed_valid_invalid_80_8081(detector):
    """Test 14: 80 (OK) và 8081 (Fail)"""
    out = _make_parser_output([_http_block([_server_block([
        _dir("listen", ["80"]),
        _dir("listen", ["8081"])
    ])])])
    res = detector.scan(out)
    assert len(res[0]["remediations"]) == 1
    # index 1 là 8081
    assert res[0]["remediations"][0]["exact_path"] == [
        "config", 0, "parsed", 0, "block", 0, "block", 1]


def test_mixed_3ports_2fail_1ok(detector):
    """Test 15: 3 cổng, 2 sai 1 đúng"""
    out = _make_parser_output([_http_block([_server_block([
        _dir("listen", ["443"]),
        _dir("listen", ["8000"]),
        _dir("listen", ["9001"])
    ])])])
    assert len(detector.scan(out)[0]["remediations"]) == 2


def test_invalid_port_4444(detector):
    """Test 16: listen 4444"""
    out = _make_parser_output(
        [_http_block([_server_block([_dir("listen", ["4444"])])])])
    assert len(detector.scan(out)[0]["remediations"]) == 1


def test_invalid_port_6379(detector):
    """Test 17: listen 6379"""
    out = _make_parser_output(
        [_http_block([_server_block([_dir("listen", ["6379"])])])])
    assert len(detector.scan(out)[0]["remediations"]) == 1


def test_invalid_port_27017(detector):
    """Test 18: listen 27017"""
    out = _make_parser_output(
        [_http_block([_server_block([_dir("listen", ["27017"])])])])
    assert len(detector.scan(out)[0]["remediations"]) == 1

# --- Xử lý địa chỉ IP và Cổng ---


def test_valid_ip_127_0_0_1_80(detector):
    """Test 19: 127.0.0.1:80"""
    out = _make_parser_output(
        [_http_block([_server_block([_dir("listen", ["127.0.0.1:80"])])])])
    assert detector.scan(out) == []


def test_valid_ip_192_168_1_1_443(detector):
    """Test 20: 192.168.1.1:443"""
    out = _make_parser_output(
        [_http_block([_server_block([_dir("listen", ["192.168.1.1:443"])])])])
    assert detector.scan(out) == []


def test_valid_ip_0_0_0_0_8080(detector):
    """Test 21: 0.0.0.0:8080"""
    out = _make_parser_output(
        [_http_block([_server_block([_dir("listen", ["0.0.0.0:8080"])])])])
    assert detector.scan(out) == []


def test_invalid_ip_127_0_0_1_8000(detector):
    """Test 22: 127.0.0.1:8000"""
    out = _make_parser_output(
        [_http_block([_server_block([_dir("listen", ["127.0.0.1:8000"])])])])
    assert len(detector.scan(out)[0]["remediations"]) == 1


def test_invalid_ip_10_0_0_1_8081(detector):
    """Test 23: 10.0.0.1:8081"""
    out = _make_parser_output(
        [_http_block([_server_block([_dir("listen", ["10.0.0.1:8081"])])])])
    assert len(detector.scan(out)[0]["remediations"]) == 1


def test_invalid_ip_0_0_0_0_22(detector):
    """Test 24: 0.0.0.0:22"""
    out = _make_parser_output(
        [_http_block([_server_block([_dir("listen", ["0.0.0.0:22"])])])])
    assert len(detector.scan(out)[0]["remediations"]) == 1


def test_valid_ip_no_port(detector):
    """Test 25: 127.0.0.1 (mặc định 80)"""
    out = _make_parser_output(
        [_http_block([_server_block([_dir("listen", ["127.0.0.1"])])])])
    assert detector.scan(out) == []

# --- Xử lý IPv6 ---


def test_valid_ipv6_80(detector):
    """Test 26: [::]:80"""
    out = _make_parser_output(
        [_http_block([_server_block([_dir("listen", ["[::]:80"])])])])
    assert detector.scan(out) == []


def test_valid_ipv6_443(detector):
    """Test 27: [::]:443"""
    out = _make_parser_output(
        [_http_block([_server_block([_dir("listen", ["[::]:443"])])])])
    assert detector.scan(out) == []


def test_invalid_ipv6_8444(detector):
    """Test 28: [::]:8444"""
    out = _make_parser_output(
        [_http_block([_server_block([_dir("listen", ["[::]:8444"])])])])
    assert len(detector.scan(out)[0]["remediations"]) == 1


def test_invalid_ipv6_specific_8002(detector):
    """Test 29: [2001:db8::1]:8002"""
    out = _make_parser_output(
        [_http_block([_server_block([_dir("listen", ["[2001:db8::1]:8002"])])])])
    assert len(detector.scan(out)[0]["remediations"]) == 1


def test_valid_ipv4_ipv6_80(detector):
    """Test 30: 80 và [::]:80"""
    out = _make_parser_output([_http_block([_server_block([
        _dir("listen", ["80"]),
        _dir("listen", ["[::]:80"])
    ])])])
    assert detector.scan(out) == []

# --- Tham số đi kèm ---


def test_valid_args_443_ssl_http2(detector):
    """Test 31: 443 ssl http2"""
    out = _make_parser_output(
        [_http_block([_server_block([_dir("listen", ["443", "ssl", "http2"])])])])
    assert detector.scan(out) == []


def test_valid_args_80_default_server(detector):
    """Test 32: 80 default_server"""
    out = _make_parser_output(
        [_http_block([_server_block([_dir("listen", ["80", "default_server"])])])])
    assert detector.scan(out) == []


def test_valid_args_443_quic_reuseport(detector):
    """Test 33: 443 quic reuseport"""
    out = _make_parser_output(
        [_http_block([_server_block([_dir("listen", ["443", "quic", "reuseport"])])])])
    assert detector.scan(out) == []


def test_invalid_args_8444_ssl_http2(detector):
    """Test 34: 8444 ssl http2"""
    out = _make_parser_output(
        [_http_block([_server_block([_dir("listen", ["8444", "ssl", "http2"])])])])
    assert len(detector.scan(out)[0]["remediations"]) == 1


def test_invalid_args_ipv6_8000_default(detector):
    """Test 35: [::]:8000 default_server"""
    out = _make_parser_output(
        [_http_block([_server_block([_dir("listen", ["[::]:8000", "default_server"])])])])
    assert len(detector.scan(out)[0]["remediations"]) == 1

# --- Cấu hình đa tệp ---


def test_multi_file_1ok_1fail(detector):
    """Test 36: File 1 đúng, File 2 sai"""
    out = {
        "status": "ok",
        "errors": [],
        "config": [
            {
                "file": "file1.conf",
                "status": "ok", "errors": [],
                "parsed": [_http_block([_server_block([_dir("listen", ["80"])])])]
            },
            {
                "file": "file2.conf",
                "status": "ok", "errors": [],
                "parsed": [_http_block([_server_block([_dir("listen", ["8000"])])])]
            }
        ]
    }
    res = detector.scan(out)
    assert len(res) == 1
    assert res[0]["file"] == "file2.conf"


def test_multi_file_2fail(detector):
    """Test 37: 2 File sai"""
    out = {
        "status": "ok",
        "errors": [],
        "config": [
            {
                "file": "file1.conf",
                "status": "ok", "errors": [],
                "parsed": [_http_block([_server_block([_dir("listen", ["8001"])])])]
            },
            {
                "file": "file2.conf",
                "status": "ok", "errors": [],
                "parsed": [_http_block([_server_block([_dir("listen", ["8002"])])])]
            }
        ]
    }
    res = detector.scan(out)
    assert len(res) == 2


def test_multi_file_3ok(detector):
    """Test 38: 3 File đúng"""
    out = {
        "status": "ok",
        "errors": [],
        "config": [
            {
                "file": f"file{i}.conf",
                "status": "ok", "errors": [],
                "parsed": [_http_block([_server_block([_dir("listen", ["80"])])])]
            } for i in range(3)
        ]
    }
    assert detector.scan(out) == []


def test_multi_file_3_with_2fail_in_one(detector):
    """Test 39: 3 files, file 2 có 2 block sai"""
    out = {
        "status": "ok",
        "errors": [],
        "config": [
            {
                "file": "file1.conf",
                "status": "ok", "errors": [],
                "parsed": [_http_block([_server_block([_dir("listen", ["80"])])])]
            },
            {
                "file": "file2.conf",
                "status": "ok", "errors": [],
                "parsed": [_http_block([
                    _server_block([_dir("listen", ["8001"])]),
                    _server_block([_dir("listen", ["8002"])])
                ])]
            },
            {
                "file": "file3.conf",
                "status": "ok", "errors": [],
                "parsed": [_http_block([_server_block([_dir("listen", ["443"])])])]
            }
        ]
    }
    res = detector.scan(out)
    assert len(res) == 1
    assert res[0]["file"] == "file2.conf"
    assert len(res[0]["remediations"]) == 2


def test_multi_file_nginx_conf_includes(detector):
    """Test 40: nginx.conf include conf.d/*.conf, lỗi phân tán"""
    out = {
        "status": "ok",
        "errors": [],
        "config": [
            {
                "file": "nginx.conf",
                "status": "ok", "errors": [],
                "parsed": [_http_block([
                    _server_block([_dir("listen", ["80"])]),
                    _dir("include", ["conf.d/*.conf"])
                ])]
            },
            {
                "file": "conf.d/fail1.conf",
                "status": "ok", "errors": [],
                # Lưu ý file con có thể không cần bọc http
                "parsed": [_server_block([_dir("listen", ["8001"])])]
            }
        ]
    }
    res = detector.scan(out)
    assert len(res) == 1
    assert res[0]["file"] == "conf.d/fail1.conf"

# --- Lồng nhau và ngoại lệ ---


def test_nested_multiple_servers(detector):
    """Test 41: Nhiều server trong 1 http"""
    out = _make_parser_output([_http_block([
        _server_block([_dir("listen", ["80"])]),
        _server_block([_dir("listen", ["8000"])]),
        _server_block([_dir("listen", ["443"])])
    ])])
    res = detector.scan(out)
    assert len(res[0]["remediations"]) == 1


def test_nested_no_listen(detector):
    """Test 42: Thiếu listen -> hợp lệ (mặc định 80)"""
    out = _make_parser_output(
        [_http_block([_server_block([_dir("server_name", ["localhost"])])])])
    assert detector.scan(out) == []


def test_nested_unix_socket(detector):
    """Test 43: unix socket"""
    out = _make_parser_output(
        [_http_block([_server_block([_dir("listen", ["unix:/var/run/nginx.sock"])])])])
    assert detector.scan(out) == []


def test_nested_exact_path(detector):
    """Test 44: Exact path đúng"""
    out = _make_parser_output([_http_block([_server_block([
        _dir("server_name", ["localhost"]),
        _dir("listen", ["8000"])
    ])])])
    res = detector.scan(out)
    assert res[0]["remediations"][0]["exact_path"] == [
        "config", 0, "parsed", 0, "block", 0, "block", 1]


def test_nested_logical_context(detector):
    """Test 45: Logical context đúng"""
    out = _make_parser_output(
        [_http_block([_server_block([_dir("listen", ["8000"])])])])
    res = detector.scan(out)
    assert res[0]["remediations"][0]["logical_context"] == ["http", "server"]
