import pytest
from core.scannerEng.recommendations.detector_241 import Detector241
from core.recom_registry import RecomID

# --- Helper Functions ---

def _dir(directive: str, args: list = None, block: list = None) -> dict:
    d = {"directive": directive, "line": 1, "args": args or []}
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

@pytest.fixture
def detector():
    return Detector241()

# =====================================================================
# 1. Metadata Sanity Checks (3 Test Cases)
# =====================================================================

def test_metadata_id(detector):
    assert detector.id == "2.4.1"

def test_metadata_title(detector):
    assert detector.title == "Đảm bảo NGINX chỉ lắng nghe kết nối mạng trên các cổng được ủy quyền"

def test_metadata_attributes(detector):
    assert hasattr(detector, "description") and detector.description
    assert hasattr(detector, "audit_procedure") and detector.audit_procedure
    assert hasattr(detector, "impact") and detector.impact
    assert hasattr(detector, "remediation") and detector.remediation

# =====================================================================
# 2. Full Pipeline Integration (42 Test Cases)
# =====================================================================

# --- 2.1. Valid Standard Ports (5 Test Cases) ---
@pytest.mark.parametrize("listen_args", [
    (["80"]),
    (["443"]),
    (["8080"]),
    (["80"], ["443"]),
    (["8443"], ["9000"])
])
def test_valid_standard_ports(detector, listen_args):
    # Handle single or multiple listen directives
    if isinstance(listen_args[0], list):
        directives = [_dir("listen", args=arg) for arg in listen_args]
    else:
        directives = [_dir("listen", args=listen_args)]
        
    parser_output = _make_parser_output([_http_block([_server_block(directives)])])
    uncompliances = detector.scan(parser_output)
    assert len(uncompliances) == 0


# --- 2.2. Invalid Unauthorized Ports (10 Test Cases) ---
@pytest.mark.parametrize("listen_args, expected_violations", [
    ([["8000"]], 1),
    ([["8001"]], 1),
    ([["8444"]], 1),
    ([["21"]], 1),
    ([["22"]], 1),
    ([["80"], ["8081"]], 1),  # 80 is valid, 8081 is invalid
    ([["8080"], ["8002"], ["8003"]], 2),  # 8080 valid, 8002 & 8003 invalid
    ([["4444"]], 1),
    ([["6379"]], 1),
    ([["27017"]], 1),
])
def test_invalid_unauthorized_ports(detector, listen_args, expected_violations):
    directives = [_dir("listen", args=arg) for arg in listen_args]
    parser_output = _make_parser_output([_http_block([_server_block(directives)])])
    uncompliances = detector.scan(parser_output)
    
    assert len(uncompliances) == 1  # Grouped by 1 file
    assert len(uncompliances[0]["remediations"]) == expected_violations
    for rem in uncompliances[0]["remediations"]:
        assert rem["action"] == "delete"
        assert rem["directive"] == "listen"


# --- 2.3. IP bindings (7 Test Cases) ---
@pytest.mark.parametrize("listen_arg, is_valid", [
    (["127.0.0.1:80"], True),
    (["192.168.1.1:443"], True),
    (["0.0.0.0:8080"], True),
    (["127.0.0.1:8000"], False),
    (["10.0.0.1:8081"], False),
    (["0.0.0.0:22"], False),
    (["127.0.0.1"], True),  # IP without port implies 80, which is valid
])
def test_ip_bindings(detector, listen_arg, is_valid):
    parser_output = _make_parser_output([_http_block([_server_block([_dir("listen", args=listen_arg)])])])
    uncompliances = detector.scan(parser_output)
    
    if is_valid:
        assert len(uncompliances) == 0
    else:
        assert len(uncompliances) == 1
        assert len(uncompliances[0]["remediations"]) == 1


# --- 2.4. IPv6 bindings (5 Test Cases) ---
@pytest.mark.parametrize("listen_args, is_valid", [
    ([["[::]:80"]], True),
    ([["[::]:443"]], True),
    ([["[::]:8444"]], False),
    ([["[2001:db8::1]:8002"]], False),
    ([["80"], ["[::]:80"]], True),
])
def test_ipv6_bindings(detector, listen_args, is_valid):
    directives = [_dir("listen", args=arg) for arg in listen_args]
    parser_output = _make_parser_output([_http_block([_server_block(directives)])])
    uncompliances = detector.scan(parser_output)
    
    if is_valid:
        assert len(uncompliances) == 0
    else:
        assert len(uncompliances) == 1


# --- 2.5. Ports with arguments (5 Test Cases) ---
@pytest.mark.parametrize("listen_arg, is_valid", [
    (["443", "ssl", "http2"], True),
    (["80", "default_server"], True),
    (["443", "quic", "reuseport"], True),
    (["8444", "ssl", "http2"], False),
    (["[::]:8000", "default_server"], False),
])
def test_ports_with_arguments(detector, listen_arg, is_valid):
    parser_output = _make_parser_output([_http_block([_server_block([_dir("listen", args=listen_arg)])])])
    uncompliances = detector.scan(parser_output)
    
    if is_valid:
        assert len(uncompliances) == 0
    else:
        assert len(uncompliances) == 1
        assert len(uncompliances[0]["remediations"]) == 1


# --- 2.6. Multi-file configurations (5 Test Cases) ---
def test_multi_file_1_valid_1_invalid(detector):
    parser_output = {
        "config": [
            {"file": "file1.conf", "parsed": [_server_block([_dir("listen", args=["80"])])]},
            {"file": "file2.conf", "parsed": [_server_block([_dir("listen", args=["8000"])])]}
        ]
    }
    uncompliances = detector.scan(parser_output)
    assert len(uncompliances) == 1
    assert uncompliances[0]["file"] == "file2.conf"

def test_multi_file_both_invalid(detector):
    parser_output = {
        "config": [
            {"file": "file1.conf", "parsed": [_server_block([_dir("listen", args=["8001"])])]},
            {"file": "file2.conf", "parsed": [_server_block([_dir("listen", args=["8002"])])]}
        ]
    }
    uncompliances = detector.scan(parser_output)
    assert len(uncompliances) == 2
    files = [u["file"] for u in uncompliances]
    assert "file1.conf" in files and "file2.conf" in files

def test_multi_file_all_valid(detector):
    parser_output = {
        "config": [
            {"file": f"file{i}.conf", "parsed": [_server_block([_dir("listen", args=["80"])])]}
            for i in range(3)
        ]
    }
    uncompliances = detector.scan(parser_output)
    assert len(uncompliances) == 0

def test_multi_file_1_file_multiple_invalid_blocks(detector):
    parser_output = {
        "config": [
            {"file": "file1.conf", "parsed": [_server_block([_dir("listen", args=["80"])])]},
            {"file": "file2.conf", "parsed": [
                _server_block([_dir("listen", args=["8001"])]),
                _server_block([_dir("listen", args=["8002"])])
            ]},
            {"file": "file3.conf", "parsed": [_server_block([_dir("listen", args=["443"])])]}
        ]
    }
    uncompliances = detector.scan(parser_output)
    assert len(uncompliances) == 1
    assert uncompliances[0]["file"] == "file2.conf"
    assert len(uncompliances[0]["remediations"]) == 2

def test_multi_file_nginx_conf_includes_scattered_errors(detector):
    parser_output = {
        "config": [
            {"file": "nginx.conf", "parsed": [_http_block([
                _dir("include", args=["conf.d/*.conf"]),
                _server_block([_dir("listen", args=["8000"])])
            ])]},
            {"file": "conf.d/app1.conf", "parsed": [_server_block([_dir("listen", args=["80"])])]},
            {"file": "conf.d/app2.conf", "parsed": [_server_block([_dir("listen", args=["8081"])])]},
        ]
    }
    uncompliances = detector.scan(parser_output)
    assert len(uncompliances) == 2
    files = {u["file"]: len(u["remediations"]) for u in uncompliances}
    assert files["nginx.conf"] == 1
    assert files["conf.d/app2.conf"] == 1


# --- 2.7. Nested structures & edge cases (5 Test Cases) ---
def test_multiple_server_blocks_in_http(detector):
    parser_output = _make_parser_output([
        _http_block([
            _server_block([_dir("listen", args=["80"])]),
            _server_block([_dir("listen", args=["8444"])]),
            _server_block([_dir("listen", args=["443"])])
        ])
    ])
    uncompliances = detector.scan(parser_output)
    assert len(uncompliances) == 1
    assert len(uncompliances[0]["remediations"]) == 1
    rem = uncompliances[0]["remediations"][0]
    assert rem["exact_path"] == ["config", 0, "parsed", 0, "block", 1, "block", 0]

def test_missing_listen_directive(detector):
    parser_output = _make_parser_output([
        _http_block([
            _server_block([_dir("server_name", args=["localhost"])])
        ])
    ])
    uncompliances = detector.scan(parser_output)
    assert len(uncompliances) == 0

def test_listen_unix_socket(detector):
    parser_output = _make_parser_output([
        _http_block([
            _server_block([_dir("listen", args=["unix:/var/run/nginx.sock"])])
        ])
    ])
    uncompliances = detector.scan(parser_output)
    assert len(uncompliances) == 0

def test_exact_path_deeply_nested(detector):
    parser_output = _make_parser_output([
        _dir("events", block=[]),
        _http_block([
            _dir("upstream", args=["backend"], block=[]),
            _server_block([
                _dir("server_name", args=["_"]),
                _dir("listen", args=["8888"]) # Invalid
            ])
        ])
    ])
    uncompliances = detector.scan(parser_output)
    assert len(uncompliances) == 1
    rem = uncompliances[0]["remediations"][0]
    # http is at index 1, server is at index 1 inside http, listen is at index 1 inside server
    assert rem["exact_path"] == ["config", 0, "parsed", 1, "block", 1, "block", 1]

def test_logical_context_correctness(detector):
    parser_output = _make_parser_output([
        _http_block([
            _server_block([
                _dir("listen", args=["9999"])
            ])
        ])
    ])
    uncompliances = detector.scan(parser_output)
    assert len(uncompliances) == 1
    rem = uncompliances[0]["remediations"][0]
    assert rem["logical_context"] == ["http", "server"]
