import pytest
from core.scannerEng.recommendations.detector_242 import Detector242

def _dir(directive: str, args: list = None, block: list = None) -> dict:
    d = {
        "directive": directive,
        "args": args or [],
    }
    if block is not None:
        d["block"] = block
    return d

def _server_block(directives: list) -> dict:
    return _dir("server", block=directives)

def _http_block(directives: list) -> dict:
    return _dir("http", block=directives)

def _location_block(args: list, directives: list) -> dict:
    return _dir("location", args=args, block=directives)

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

def _make_multi_file_parser_output(files_content: list) -> dict:
    config = []
    for filepath, parsed_directives in files_content:
        config.append({
            "file": filepath,
            "status": "ok",
            "errors": [],
            "parsed": parsed_directives
        })
    return {
        "status": "ok",
        "errors": [],
        "config": config
    }

COMPLIANT_CASES = [
    (
        "compliant_80_return_444",
        _make_parser_output([_http_block([_server_block([_dir("listen", ["80", "default_server"]), _dir("return", ["444"])])])]),
        0
    ),
    (
        "compliant_443_ssl_reject",
        _make_parser_output([_http_block([_server_block([_dir("listen", ["443", "ssl", "default_server"]), _dir("ssl_reject_handshake", ["on"])])])]),
        0
    ),
    (
        "compliant_80_return_403",
        _make_parser_output([_http_block([_server_block([_dir("listen", ["80", "default_server"]), _dir("return", ["403"])])])]),
        0
    ),
    (
        "compliant_80_return_404",
        _make_parser_output([_http_block([_server_block([_dir("listen", ["80", "default_server"]), _dir("return", ["404"])])])]),
        0
    ),
    (
        "compliant_80_return_400",
        _make_parser_output([_http_block([_server_block([_dir("listen", ["80", "default_server"]), _dir("return", ["400"])])])]),
        0
    ),
    (
        "compliant_ipv6_80_return_444",
        _make_parser_output([_http_block([_server_block([_dir("listen", ["[::]:80", "default_server"]), _dir("return", ["444"])])])]),
        0
    ),
    (
        "compliant_quic_443_ssl_reject",
        _make_parser_output([_http_block([_server_block([_dir("listen", ["443", "quic", "default_server"]), _dir("ssl_reject_handshake", ["on"])])])]),
        0
    ),
    (
        "compliant_with_server_name",
        _make_parser_output([_http_block([_server_block([_dir("listen", ["80", "default_server"]), _dir("server_name", ["_"]), _dir("return", ["444"])])])]),
        0
    ),
    (
        "compliant_443_ssl_return_444",
        _make_parser_output([_http_block([_server_block([_dir("listen", ["443", "ssl", "default_server"]), _dir("return", ["444"])])])]),
        0
    ),
    (
        "compliant_8080_return_444",
        _make_parser_output([_http_block([_server_block([_dir("listen", ["8080", "default_server"]), _dir("return", ["444"])])])]),
        0
    ),
]

NON_COMPLIANT_CASES = [
    (
        "non_compliant_no_default_server",
        _make_parser_output([_http_block([_server_block([_dir("listen", ["80"])])])]),
        1
    ),
    (
        "non_compliant_default_server_no_reject",
        _make_parser_output([_http_block([_server_block([_dir("listen", ["80", "default_server"])])])]),
        1
    ),
    (
        "non_compliant_default_server_return_200",
        _make_parser_output([_http_block([_server_block([_dir("listen", ["80", "default_server"]), _dir("return", ["200"])])])]),
        1
    ),
    (
        "non_compliant_default_server_ssl_reject_off",
        _make_parser_output([_http_block([_server_block([_dir("listen", ["443", "ssl", "default_server"]), _dir("ssl_reject_handshake", ["off"])])])]),
        1
    ),
    (
        "non_compliant_default_server_return_301",
        _make_parser_output([_http_block([_server_block([_dir("listen", ["80", "default_server"]), _dir("return", ["301", "https://$host$request_uri"])])])]),
        1
    ),
    (
        "non_compliant_default_server_return_302",
        _make_parser_output([_http_block([_server_block([_dir("listen", ["80", "default_server"]), _dir("return", ["302"])])])]),
        1
    ),
    (
        "non_compliant_default_server_return_500",
        _make_parser_output([_http_block([_server_block([_dir("listen", ["80", "default_server"]), _dir("return", ["500"])])])]),
        1
    ),
    (
        "non_compliant_default_server_return_502",
        _make_parser_output([_http_block([_server_block([_dir("listen", ["80", "default_server"]), _dir("return", ["502"])])])]),
        1
    ),
    (
        "non_compliant_default_server_return_503",
        _make_parser_output([_http_block([_server_block([_dir("listen", ["80", "default_server"]), _dir("return", ["503"])])])]),
        1
    ),
    (
        "non_compliant_default_server_return_text",
        _make_parser_output([_http_block([_server_block([_dir("listen", ["80", "default_server"]), _dir("return", ["Hello"])])])]),
        1
    ),
    (
        "non_compliant_default_server_ssl_off_return_200",
        _make_parser_output([_http_block([_server_block([_dir("listen", ["443", "ssl", "default_server"]), _dir("ssl_reject_handshake", ["off"]), _dir("return", ["200"])])])]),
        1
    ),
    (
        "non_compliant_default_server_return_in_location",
        _make_parser_output([_http_block([_server_block([_dir("listen", ["80", "default_server"]), _location_block(["/"], [_dir("return", ["444"])])])])]),
        1
    ),
    (
        "non_compliant_multiple_servers_no_default",
        _make_parser_output([_http_block([_server_block([_dir("listen", ["80"])]), _server_block([_dir("listen", ["443", "ssl"])])])]),
        1
    ),
    (
        "non_compliant_normal_server_with_default",
        _make_parser_output([_http_block([_server_block([_dir("listen", ["80", "default_server"]), _dir("server_name", ["example.com"]), _dir("root", ["/var/www/html"])])])]),
        1
    ),
    (
        "non_compliant_default_server_empty_return",
        _make_parser_output([_http_block([_server_block([_dir("listen", ["80", "default_server"]), _dir("return", [])])])]),
        1
    ),
]

EDGE_CASES = [
    (
        "edge_empty_config",
        _make_parser_output([]),
        1
    ),
    (
        "edge_no_http_block",
        _make_parser_output([_dir("events", block=[])]),
        1
    ),
    (
        "edge_default_server_in_included_file",
        _make_multi_file_parser_output([
            ("/etc/nginx/nginx.conf", [_http_block([_dir("include", ["conf.d/*.conf"])])]),
            ("/etc/nginx/conf.d/default.conf", [_server_block([_dir("listen", ["80", "default_server"]), _dir("return", ["444"])])])
        ]),
        0
    ),
    (
        "edge_multiple_files_no_default_server",
        _make_multi_file_parser_output([
            ("/etc/nginx/nginx.conf", [_http_block([_dir("include", ["conf.d/*.conf"])])]),
            ("/etc/nginx/conf.d/app.conf", [_server_block([_dir("listen", ["80"])])])
        ]),
        1
    ),
    (
        "edge_complex_listen_compliant",
        _make_parser_output([_http_block([_server_block([_dir("listen", ["80", "default_server", "proxy_protocol", "ipv6only=on"]), _dir("return", ["444"])])])]),
        0
    ),
    (
        "edge_multiple_listen_one_default_compliant",
        _make_parser_output([_http_block([_server_block([_dir("listen", ["80", "default_server"]), _dir("listen", ["443", "ssl"]), _dir("return", ["444"])])])]),
        0
    ),
    (
        "edge_multiple_listen_none_default",
        _make_parser_output([_http_block([_server_block([_dir("listen", ["80"]), _dir("listen", ["443", "ssl"]), _dir("return", ["444"])])])]),
        1
    ),
    (
        "edge_default_server_garbage_directives",
        _make_parser_output([_http_block([_server_block([_dir("listen", ["80", "default_server"]), _dir("foo", ["bar"]), _dir("return", ["444"])])])]),
        0
    ),
    (
        "edge_default_server_is_second",
        _make_parser_output([_http_block([_server_block([_dir("listen", ["80"])]), _server_block([_dir("listen", ["80", "default_server"]), _dir("return", ["444"])])])]),
        0
    ),
    (
        "edge_default_server_is_third",
        _make_parser_output([_http_block([_server_block([_dir("listen", ["80"])]), _server_block([_dir("listen", ["443"])]), _server_block([_dir("listen", ["8080", "default_server"]), _dir("return", ["444"])])])]),
        0
    ),
    (
        "edge_ssl_reject_no_default_server",
        _make_parser_output([_http_block([_server_block([_dir("listen", ["443", "ssl"]), _dir("ssl_reject_handshake", ["on"])])])]),
        1
    ),
    (
        "edge_return_444_no_default_server",
        _make_parser_output([_http_block([_server_block([_dir("listen", ["80"]), _dir("return", ["444"])])])]),
        1
    ),
    (
        "edge_return_4xx_in_http_block",
        _make_parser_output([_http_block([_dir("return", ["444"]), _server_block([_dir("listen", ["80", "default_server"])])])]),
        1
    ),
    (
        "edge_two_default_servers_one_invalid",
        _make_parser_output([_http_block([_server_block([_dir("listen", ["80", "default_server"]), _dir("return", ["444"])]), _server_block([_dir("listen", ["443", "ssl", "default_server"]), _dir("return", ["200"])])])]),
        1
    ),
    (
        "edge_default_server_return_401",
        _make_parser_output([_http_block([_server_block([_dir("listen", ["80", "default_server"]), _dir("return", ["401"])])])]),
        0
    ),
    (
        "edge_default_server_return_405",
        _make_parser_output([_http_block([_server_block([_dir("listen", ["80", "default_server"]), _dir("return", ["405"])])])]),
        0
    ),
    (
        "edge_default_server_return_429",
        _make_parser_output([_http_block([_server_block([_dir("listen", ["80", "default_server"]), _dir("return", ["429"])])])]),
        0
    ),
]

ALL_CASES = COMPLIANT_CASES + NON_COMPLIANT_CASES + EDGE_CASES

class TestDetector242Metadata:
    def test_detector_id(self):
        detector = Detector242()
        assert detector.id == "2.4.2"

    def test_detector_title(self):
        detector = Detector242()
        assert detector.title == "Đảm bảo các yêu cầu đến tên máy chủ không xác định bị từ chối"

    def test_detector_attributes(self):
        detector = Detector242()
        assert hasattr(detector, "description")
        assert hasattr(detector, "audit_procedure")
        assert hasattr(detector, "impact")
        assert hasattr(detector, "remediation")


class TestDetector242Pipeline:
    @pytest.fixture
    def detector(self):
        return Detector242()

    @pytest.mark.parametrize("test_id, parser_output, expected_count", ALL_CASES)
    def test_scan(self, detector, test_id, parser_output, expected_count):
        uncompliances = detector.scan(parser_output)
        
        if expected_count > 0:
            assert len(uncompliances) == expected_count, f"[{test_id}] Expected {expected_count} uncompliances, got {len(uncompliances)}"
        else:
            assert len(uncompliances) == 0, f"[{test_id}] Expected compliant, but got uncompliances: {uncompliances}"
