import pytest

from core.remedyEng.base_remedy import BaseRemedy
from core.remedyEng.recommendations.remediate_242 import Remediate242


def _node(directive: str, args: list | None = None, block: list | None = None) -> dict:
    item = {"directive": directive, "args": args or []}
    if block is not None:
        item["block"] = block
    return item


def _http(block: list) -> dict:
    return _node("http", [], block)


def _server(block: list) -> dict:
    return _node("server", [], block)


def _make_ast(parsed: list) -> dict:
    return {"parsed": parsed}


@pytest.fixture
def remedy():
    return Remediate242()


def test_242_metadata_and_input_validation(remedy):
    assert isinstance(remedy, BaseRemedy)
    assert remedy.has_input is True
    assert remedy.id == "2.4.2"

    remedy.user_inputs = ["example.com"]
    is_valid, error = remedy._validate_user_inputs()
    assert is_valid is False
    assert "Use '_'" in error


def test_242_defaults_blank_input_to_wildcard(remedy):
    remedy.user_inputs = [""]

    is_valid, error = remedy._validate_user_inputs()

    assert is_valid is True
    assert error == ""
    assert remedy.user_inputs[0] == "_"


def test_242_builds_default_server_block_in_http_scope(remedy):
    file_path = "/etc/nginx/nginx.conf"

    remedy.user_inputs = ["_"]
    remedy.child_scan_result = {
        file_path: [
            {
                "action": "add_block",
                "directive": "server",
                "context": ["config", 0, "parsed"],
                "logical_context": "http",
                "position": 0,
            }
        ]
    }
    remedy.child_ast_config = {
        file_path: _make_ast([
            _http([
                _server([
                    _node("listen", ["80"]),
                ])
            ])
        ])
    }

    remedy.remediate()

    parsed = remedy.child_ast_modified[file_path]["parsed"]
    assert [node["directive"] for node in parsed] == ["http"]

    http_block = parsed[0]["block"]
    server_nodes = [node for node in http_block if node["directive"] == "server"]
    assert len(server_nodes) == 2

    default_server = server_nodes[-1]["block"]
    listen_args = [node["args"] for node in default_server if node["directive"] == "listen"]
    assert ["80", "default_server"] in listen_args
    assert ["[::]:80", "default_server"] in listen_args
    assert ["443", "ssl", "default_server"] in listen_args
    assert ["443", "quic", "default_server"] in listen_args
    assert [["_"]] == [node["args"] for node in default_server if node["directive"] == "server_name"]
    assert [["on"]] == [node["args"] for node in default_server if node["directive"] == "ssl_reject_handshake"]
    assert [["444"]] == [node["args"] for node in default_server if node["directive"] == "return"]


def test_242_places_block_first_when_strict_placement_is_enabled(remedy):
    file_path = "/etc/nginx/nginx.conf"

    remedy.strict_placement = True
    remedy.user_inputs = ["_"]
    remedy.child_scan_result = {
        file_path: [
            {
                "action": "add_block",
                "directive": "server",
                "context": ["config", 0, "parsed", 0, "block"],
                "logical_context": "http",
                "position": 0,
            }
        ]
    }
    remedy.child_ast_config = {
        file_path: _make_ast([
            _http([
                _node("map", ["$host", "$server_name"]),
                _server([
                    _node("listen", ["80"]),
                ])
            ])
        ])
    }

    remedy.remediate()

    http_block = remedy.child_ast_modified[file_path]["parsed"][0]["block"]
    assert http_block[0]["directive"] == "server"
    assert http_block[0]["block"][-1]["args"] == ["444"]
    assert http_block[1]["directive"] == "map"


def test_242_falls_back_from_root_context_to_http_block(remedy):
    file_path = "/etc/nginx/nginx.conf"

    remedy.user_inputs = ["_"]
    remedy.child_scan_result = {
        file_path: [
            {
                "action": "add_block",
                "directive": "server",
                "context": ["config", 0, "parsed"],
                "logical_context": "http",
            }
        ]
    }
    remedy.child_ast_config = {
        file_path: _make_ast([
            _node("worker_processes", ["auto"]),
            _http([]),
        ])
    }

    remedy.remediate()

    parsed = remedy.child_ast_modified[file_path]["parsed"]
    assert [node["directive"] for node in parsed] == ["worker_processes", "http"]
    assert any(node["directive"] == "server" for node in parsed[1]["block"])
