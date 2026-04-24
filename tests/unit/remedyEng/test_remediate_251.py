import pytest

from core.remedyEng.base_remedy import BaseRemedy
from core.remedyEng.recommendations.remediate_251 import Remediate251


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
    return Remediate251()


def test_251_metadata_and_contract(remedy):
    assert isinstance(remedy, BaseRemedy)
    assert remedy.has_input is False
    assert remedy.id == "2.5.1"


def test_251_defaults_missing_args_to_off(remedy):
    file_path = "/etc/nginx/nginx.conf"

    remedy.child_scan_result = {
        file_path: [
            {
                "action": "modify",
                "directive": "server_tokens",
                "context": ["config", 0, "parsed", 0, "block", 0],
            }
        ]
    }
    remedy.child_ast_config = {
        file_path: _make_ast([
            _http([
                _node("server_tokens", ["on"]),
                _node("server_name", ["example.com"]),
            ])
        ])
    }

    remedy.remediate()

    parsed = remedy.child_ast_modified[file_path]["parsed"]
    assert parsed[0]["block"][0]["args"] == ["off"]


def test_251_updates_all_server_tokens_when_context_missing(remedy):
    file_path = "/etc/nginx/nginx.conf"

    remedy.child_scan_result = {
        file_path: [
            {
                "action": "modify_directive",
                "directive": "server_tokens",
                "context": [],
            }
        ]
    }
    remedy.child_ast_config = {
        file_path: _make_ast([
            _http([
                _node("server_tokens", ["on"]),
                _server([
                    _node("server_tokens", ["on"]),
                    _node("server_name", ["example.com"]),
                ]),
                _server([
                    _node("server_tokens", ["on"]),
                ]),
            ])
        ])
    }

    remedy.remediate()

    parsed = remedy.child_ast_modified[file_path]["parsed"]
    http_block = parsed[0]["block"]
    assert http_block[0]["args"] == ["off"]
    assert http_block[1]["block"][0]["args"] == ["off"]
    assert http_block[2]["block"][0]["args"] == ["off"]


def test_251_ignores_unrelated_action_and_directive(remedy):
    file_path = "/etc/nginx/nginx.conf"
    original_ast = [_http([
        _node("server_tokens", ["on"]),
        _node("listen", ["80"]),
    ])]

    remedy.child_scan_result = {
        file_path: [
            {"action": "add", "directive": "server_tokens", "context": ["config", 0, "parsed", 0, "block", 0]},
            {"action": "modify", "directive": "listen", "context": ["config", 0, "parsed", 0, "block", 1]},
        ]
    }
    remedy.child_ast_config = {file_path: _make_ast(original_ast)}

    remedy.remediate()

    assert remedy.child_ast_modified[file_path]["parsed"] == original_ast


def test_251_replaces_server_tokens_using_direct_context_and_fallback(remedy):
    file_path = "/etc/nginx/nginx.conf"

    remedy.child_scan_result = {
        file_path: [
            {
                "action": "modify_directive",
                "directive": "server_tokens",
                "context": ["config", 0, "parsed", 0, "block", 0],
            }
        ]
    }
    remedy.child_ast_config = {
        file_path: _make_ast([
            _http([
                _node("server_tokens", ["on"]),
                _node("listen", ["80"]),
            ])
        ])
    }

    remedy.remediate()

    parsed = remedy.child_ast_modified[file_path]["parsed"]
    assert parsed[0]["block"][0]["args"] == ["off"]
    assert parsed[0]["block"][1]["args"] == ["80"]


def test_251_falls_back_to_search_when_context_missing(remedy):
    file_path = "/etc/nginx/nginx.conf"

    remedy.child_scan_result = {
        file_path: [
            {
                "action": "modify",
                "directive": "server_tokens",
                "context": [],
            }
        ]
    }
    remedy.child_ast_config = {
        file_path: _make_ast([
            _http([
                _node("server_tokens", ["on"]),
                _server([
                    _node("server_tokens", ["on"]),
                    _node("server_name", ["example.com"]),
                ]),
            ])
        ])
    }

    remedy.remediate()

    parsed = remedy.child_ast_modified[file_path]["parsed"]
    http_block = parsed[0]["block"]
    assert http_block[0]["args"] == ["off"]
    assert http_block[1]["block"][0]["args"] == ["off"]
    assert http_block[1]["block"][1]["args"] == ["example.com"]
