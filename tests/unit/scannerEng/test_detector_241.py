import pytest
from typing import List, Dict, Any
from core.scannerEng.recommendations.detector_241 import Detector241

# --- Helper Functions ---

def _dir(directive: str, args: List[str] = None, block: List[Dict[str, Any]] = None, line: int = 1) -> Dict[str, Any]:
    res = {
        "directive": directive,
        "line": line,
        "args": args or []
    }
    if block is not None:
        res["block"] = block
    return res

def _server_block(directives: List[Dict[str, Any]], line: int = 1) -> Dict[str, Any]:
    return _dir("server", [], directives, line=line)

def _http_block(directives: List[Dict[str, Any]], line: int = 1) -> Dict[str, Any]:
    return _dir("http", [], directives, line=line)

def _location_block(args: List[str], directives: List[Dict[str, Any]], line: int = 1) -> Dict[str, Any]:
    return _dir("location", args, directives, line=line)

def _make_parser_output(parsed_directives: List[Dict[str, Any]], filepath: str = "/etc/nginx/nginx.conf") -> Dict[str, Any]:
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

# --- 1. Metadata Sanity Checks (3 Test Cases) ---

def test_metadata_id(detector):
    assert detector.id == "2.4.1"

def test_metadata_title(detector):
    assert detector.title == "Đảm bảo NGINX chỉ lắng nghe kết nối mạng trên các cổng được ủy quyền"

def test_metadata_attributes(detector):
    assert hasattr(detector, "description")
    assert hasattr(detector, "audit_procedure")
    assert hasattr(detector, "impact")
    assert hasattr(detector, "remediation")
    assert detector.description
    assert detector.audit_procedure
    assert detector.impact
    assert detector.remediation

# --- 2. Full Pipeline Integration (42 Test Cases) ---

# Group 1: Authorized Ports (10 Test Cases)
@pytest.mark.parametrize("args, desc", [
    (["80"], "listen 80;"),
    (["443"], "listen 443;"),
    (["8080"], "listen 8080;"),
    (["8443"], "listen 8443;"),
    (["9000"], "listen 9000;"),
    (["443", "ssl"], "listen 443 ssl;"),
    (["443", "quic", "reuseport"], "listen 443 quic reuseport;"),
    (["[::]:80"], "IPv6 listen [::]:80;"),
    (["192.168.1.100:443"], "IPv4 with port listen 192.168.1.100:443;"),
])
def test_authorized_ports(detector, args, desc):
    ast = _make_parser_output([
        _http_block([
            _server_block([
                _dir("listen", args)
            ])
        ])
    ])
    result = detector.scan(ast)
    assert len(result) == 0, f"Failed on {desc}"

def test_authorized_ports_multiple_in_one_server(detector):
    ast = _make_parser_output([
        _http_block([
            _server_block([
                _dir("listen", ["80"]),
                _dir("listen", ["443"])
            ])
        ])
    ])
    result = detector.scan(ast)
    assert len(result) == 0

# Group 2: Unauthorized Ports (10 Test Cases)
@pytest.mark.parametrize("args, expected_port, desc", [
    (["81"], "81", "listen 81;"),
    (["8081"], "8081", "listen 8081;"),
    (["22"], "22", "listen 22;"),
    (["21"], "21", "listen 21;"),
    (["4444"], "4444", "listen 4444;"),
    (["6379"], "6379", "listen 6379;"),
    (["[::]:81"], "81", "IPv6 listen [::]:81;"),
    (["10.0.0.1:22"], "22", "IPv4 specific IP listen 10.0.0.1:22;"),
    (["localhost:8081"], "8081", "Hostname with port localhost:8081;"),
])
def test_unauthorized_ports(detector, args, expected_port, desc):
    ast = _make_parser_output([
        _http_block([
            _server_block([
                _dir("listen", args)
            ])
        ])
    ])
    result = detector.scan(ast)
    assert len(result) == 1
    assert len(result[0]["remediations"]) == 1
    assert expected_port in result[0]["remediations"][0]["details"]

def test_mixed_authorized_and_unauthorized_in_one_server(detector):
    ast = _make_parser_output([
        _http_block([
            _server_block([
                _dir("listen", ["80"], line=2),
                _dir("listen", ["8081"], line=3)
            ])
        ])
    ])
    result = detector.scan(ast)
    assert len(result) == 1
    assert len(result[0]["remediations"]) == 1
    assert result[0]["remediations"][0]["line"] == 3

# Group 3: Complex Arguments (10 Test Cases)
@pytest.mark.parametrize("args, is_uncompliant, desc", [
    (["unix:/var/run/nginx.sock"], False, "Unix domain socket"),
    (["80", "default_server", "proxy_protocol"], False, "Multiple flags"),
    (["443", "ssl", "http2", "default_server"], False, "Multiple ssl flags"),
    (["8080", "bind"], False, "Bind flag"),
    (["127.0.0.1"], False, "IP without port implies 80"),
    (["[::1]"], False, "IPv6 without port implies 80"),
    (["$port"], True, "Variable as port is invalid/unauthorized statically"),
    (["99999"], True, "Port out of range > 65535"),
    (["0"], True, "Port 0"),
    ([], True, "Empty args for listen"),
])
def test_complex_arguments(detector, args, is_uncompliant, desc):
    ast = _make_parser_output([
        _http_block([
            _server_block([
                _dir("listen", args)
            ])
        ])
    ])
    result = detector.scan(ast)
    if is_uncompliant:
        assert len(result) == 1, f"Failed on {desc}"
        assert len(result[0]["remediations"]) == 1
    else:
        assert len(result) == 0, f"Failed on {desc}"

# Group 4: Multiple Files/Blocks (12 Test Cases)
def test_multiple_server_blocks_one_file(detector):
    ast = _make_parser_output([
        _http_block([
            _server_block([_dir("listen", ["80"])]),
            _server_block([_dir("listen", ["81"])])
        ])
    ])
    result = detector.scan(ast)
    assert len(result) == 1
    assert len(result[0]["remediations"]) == 1

def test_main_file_valid_included_file_invalid(detector):
    ast = {
        "status": "ok",
        "config": [
            {
                "file": "/etc/nginx/nginx.conf",
                "parsed": [_http_block([_server_block([_dir("listen", ["80"])])])]
            },
            {
                "file": "/etc/nginx/conf.d/bad.conf",
                "parsed": [_server_block([_dir("listen", ["22"])])]
            }
        ]
    }
    result = detector.scan(ast)
    assert len(result) == 1
    assert result[0]["file"] == "/etc/nginx/conf.d/bad.conf"
    assert len(result[0]["remediations"]) == 1

def test_main_file_invalid_included_file_invalid(detector):
    ast = {
        "config": [
            {
                "file": "/etc/nginx/nginx.conf",
                "parsed": [_http_block([_server_block([_dir("listen", ["8081"])])])]
            },
            {
                "file": "/etc/nginx/conf.d/bad.conf",
                "parsed": [_server_block([_dir("listen", ["22"])])]
            }
        ]
    }
    result = detector.scan(ast)
    assert len(result) == 2
    files = [r["file"] for r in result]
    assert "/etc/nginx/nginx.conf" in files
    assert "/etc/nginx/conf.d/bad.conf" in files

def test_multiple_invalid_in_multiple_includes(detector):
    ast = {
        "config": [
            {"file": "a.conf", "parsed": [_server_block([_dir("listen", ["22"])])]},
            {"file": "b.conf", "parsed": [_server_block([_dir("listen", ["23"])])]},
            {"file": "c.conf", "parsed": [_server_block([_dir("listen", ["24"])])]}
        ]
    }
    result = detector.scan(ast)
    assert len(result) == 3

def test_server_block_outside_http(detector):
    ast = _make_parser_output([
        _server_block([_dir("listen", ["81"])])
    ])
    result = detector.scan(ast)
    assert len(result) == 1

def test_commented_listen_is_ignored(detector):
    ast = _make_parser_output([
        _http_block([
            _server_block([
                _dir("#listen", ["8081"])
            ])
        ])
    ])
    result = detector.scan(ast)
    assert len(result) == 0

def test_ignore_non_conf_files(detector):
    ast = {
        "config": [
            {
                "file": "/etc/nginx/bad.txt",
                "parsed": [_server_block([_dir("listen", ["22"])])]
            }
        ]
    }
    result = detector.scan(ast)
    assert len(result) == 0

def test_ignore_bak_files(detector):
    ast = {
        "config": [
            {
                "file": "/etc/nginx/nginx.conf.bak",
                "parsed": [_server_block([_dir("listen", ["22"])])]
            }
        ]
    }
    result = detector.scan(ast)
    assert len(result) == 0

def test_empty_server_block(detector):
    ast = _make_parser_output([
        _http_block([
            _server_block([])
        ])
    ])
    result = detector.scan(ast)
    assert len(result) == 0

def test_empty_ast(detector):
    ast = _make_parser_output([])
    result = detector.scan(ast)
    assert len(result) == 0

def test_two_invalid_listens_in_one_block(detector):
    ast = _make_parser_output([
        _http_block([
            _server_block([
                _dir("listen", ["81"]),
                _dir("listen", ["82"])
            ])
        ])
    ])
    result = detector.scan(ast)
    assert len(result) == 1
    assert len(result[0]["remediations"]) == 2

def test_five_server_blocks_each_with_invalid_port(detector):
    ast = _make_parser_output([
        _http_block([
            _server_block([_dir("listen", ["81"])]),
            _server_block([_dir("listen", ["82"])]),
            _server_block([_dir("listen", ["83"])]),
            _server_block([_dir("listen", ["84"])]),
            _server_block([_dir("listen", ["85"])])
        ])
    ])
    result = detector.scan(ast)
    assert len(result) == 1
    assert len(result[0]["remediations"]) == 5
