import pytest
from core.scannerEng.recommendations.detector_241 import Detector241


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

# --- Metadata Sanity Checks (3 Test Cases) ---


def test_detector_id():
    detector = Detector241()
    assert detector.id == "2.4.1"


def test_detector_title():
    detector = Detector241()
    assert detector.title == "Đảm bảo NGINX chỉ lắng nghe các kết nối mạng trên các cổng được ủy quyền"


def test_detector_attributes():
    detector = Detector241()
    assert hasattr(detector, 'description')
    assert hasattr(detector, 'audit_procedure')
    assert hasattr(detector, 'impact')
    assert hasattr(detector, 'remediation')

# --- Full Pipeline Integration (42 Test Cases) ---


@pytest.mark.parametrize("args_list", [
    [["80"]],
    [["443"]],
    [["8080"]],
    [["8443"]],
    [["9000"]],
    [["80"], ["443"]],
    [["8080"], ["8443"]],
    [["9000"], ["80"]],
    [["80"], ["443"], ["8080"]],
    [["80"], ["443"], ["8080"], ["8443"], ["9000"]],
])
def test_valid_configurations(args_list):
    detector = Detector241()
    directives = [_dir("listen", args) for args in args_list]
    parser_output = _make_parser_output(
        [_http_block([_server_block(directives)])])

    result = detector.scan(parser_output)
    assert len(result) == 0


@pytest.mark.parametrize("args_list, num_violations", [
    ([["21"]], 1),
    ([["22"]], 1),
    ([["8000"]], 1),
    ([["80"], ["21"]], 1),
    ([["80"], ["443"], ["23"]], 1),
    ([["3306"]], 1),
    ([["5432"]], 1),
    ([["1111"]], 1),
    ([["22"], ["21"]], 2),
    ([["8081"]], 1),
])
def test_basic_violations(args_list, num_violations):
    detector = Detector241()
    directives = [_dir("listen", args) for args in args_list]
    parser_output = _make_parser_output(
        [_http_block([_server_block(directives)])])

    result = detector.scan(parser_output)
    if num_violations > 0:
        assert len(result) > 0
        assert len(result[0]["remediations"]) == num_violations
        for rem in result[0]["remediations"]:
            assert rem["action"] == "delete"
            assert "exact_path" in rem
    else:
        assert len(result) == 0


@pytest.mark.parametrize("listen_args, is_valid", [
    (["127.0.0.1:8080"], True),
    (["[::]:80"], True),
    (["0.0.0.0:443"], True),
    (["192.168.1.1:9000"], True),
    (["127.0.0.1:22"], False),
    (["[::]:21"], False),
    (["443", "ssl", "http2"], True),
    (["443", "quic", "reuseport"], True),
    (["80", "default_server"], True),
    (["8000", "default_server"], False),
    (["22", "ssl"], False),
    (["127.0.0.1:8443", "ssl"], True),
])
def test_complex_parameters(listen_args, is_valid):
    detector = Detector241()
    parser_output = _make_parser_output(
        [_http_block([_server_block([_dir("listen", listen_args)])])])

    result = detector.scan(parser_output)
    if is_valid:
        assert len(result) == 0
    else:
        assert len(result) == 1
        assert len(result[0]["remediations"]) == 1
        assert result[0]["remediations"][0]["action"] == "delete"


@pytest.mark.parametrize("file_configs, expected_files_with_violations", [
    ([{"file": "/etc/nginx/nginx.conf",
     "directives": [_server_block([_dir("listen", ["22"])])]}], 1),
    ([{"file": "/etc/nginx/nginx.conf", "directives": [_server_block([_dir("listen", ["80"])])]},
      {"file": "/etc/nginx/conf.d/bad.conf", "directives": [_server_block([_dir("listen", ["21"])])]}], 1),
    ([{"file": "/etc/nginx/nginx.conf", "directives": [_server_block([_dir("listen", ["22"])])]},
      {"file": "/etc/nginx/conf.d/bad.conf", "directives": [_server_block([_dir("listen", ["21"])])]}], 2),
    ([{"file": "1.conf", "directives": [_server_block([_dir("listen", ["80"])])]},
      {"file": "2.conf", "directives": [
          _server_block([_dir("listen", ["21"])])]},
      {"file": "3.conf", "directives": [_server_block([_dir("listen", ["22"])])]}], 2),
    ([{"file": "1.conf", "directives": [_server_block([_dir("listen", ["80"])])]},
      {"file": "2.conf", "directives": [
          _server_block([_dir("listen", ["443"])])]},
      {"file": "3.conf", "directives": [_server_block([_dir("listen", ["8080"])])]}], 0),
    ([{"file": "1.conf", "directives": [_server_block(
        [_dir("listen", ["21"])]), _server_block([_dir("listen", ["22"])])]}], 1),
    ([{"file": f"{i}.conf", "directives": [_server_block([_dir("listen", [str(port)])])]} for i, port in enumerate([80, 443, 8080])] +
     [{"file": "bad.conf", "directives": [_server_block([_dir("listen", ["21"])])]}], 1),
    ([{"file": f"{i}.conf", "directives": [_server_block(
        [_dir("listen", [str(21+i)])])]} for i in range(4)], 4),
    ([{"file": "1.conf", "directives": [_server_block(
        [_location_block(["/"], [_dir("listen", ["80"])])])]}], 0),
    ([{"file": "1.conf", "directives": [_server_block(
        [_location_block(["/"], [_dir("listen", ["21"])])])]}], 1),
])
def test_group_by_file(file_configs, expected_files_with_violations):
    detector = Detector241()
    config_array = []
    for fc in file_configs:
        config_array.append({
            "file": fc["file"],
            "status": "ok",
            "errors": [],
            "parsed": [_http_block(fc["directives"])]
        })

    parser_output = {"status": "ok", "errors": [], "config": config_array}
    result = detector.scan(parser_output)
    assert len(result) == expected_files_with_violations

    for uncompliance in result:
        assert "file" in uncompliance
        assert "remediations" in uncompliance
