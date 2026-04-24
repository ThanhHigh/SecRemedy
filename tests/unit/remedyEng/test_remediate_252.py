import pytest

from core.remedyEng.base_remedy import BaseRemedy
from core.remedyEng.recommendations.remediate_252 import Remediate252


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
    return Remediate252()


def test_252_metadata_and_input_validation(remedy):
    assert isinstance(remedy, BaseRemedy)
    assert remedy.has_input is True
    assert remedy.id == "2.5.2"

    remedy.user_inputs = ["./404.html", "/50x.html", "/var/www/html/errors"]
    is_valid, error = remedy._validate_user_inputs()
    assert is_valid is False
    assert "Invalid 40x error_page URI" in error


def test_252_rejects_missing_error_page_paths(remedy):
    remedy.user_inputs = ["", "", "/var/www/html/errors"]

    is_valid, error = remedy._validate_user_inputs()

    assert is_valid is False
    assert "At least one error page path required" in error


def test_252_accepts_single_40x_page_without_location_root(remedy):
    file_path = "/etc/nginx/nginx.conf"

    remedy.user_inputs = ["/404.html", "", ""]
    remedy.child_scan_result = {
        file_path: [
            {
                "action": "add",
                "directive": "error_page",
                "args": ["404", "./404.html"],
                "context": ["config", 0, "parsed"],
                "logical_context": "http",
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

    http_block = remedy.child_ast_modified[file_path]["parsed"][0]["block"]
    error_pages = [node["args"] for node in http_block if node["directive"] == "error_page"]
    assert error_pages == [["404", "/404.html"]]
    assert not any(node["directive"] == "location" for node in http_block)


def test_252_accepts_single_50x_page_and_creates_location_only_with_root(remedy):
    file_path = "/etc/nginx/nginx.conf"

    remedy.user_inputs = ["", "/50x.html", "/var/www/html/errors"]
    remedy.child_scan_result = {
        file_path: [
            {
                "action": "add",
                "directive": "error_page",
                "args": ["500", "502", "503", "504", "./50x.html"],
                "context": ["config", 0, "parsed"],
                "logical_context": "http",
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

    http_block = remedy.child_ast_modified[file_path]["parsed"][0]["block"]
    assert [node["args"] for node in http_block if node["directive"] == "error_page"] == [["500", "502", "503", "504", "/50x.html"]]
    server_block = http_block[0]["block"]
    location_nodes = [node for node in server_block if node["directive"] == "location"]
    assert len(location_nodes) == 1
    assert location_nodes[0]["args"] == ["=", "/50x.html"]


def test_252_updates_existing_error_page_entries(remedy):
    file_path = "/etc/nginx/nginx.conf"

    remedy.user_inputs = ["/404.html", "/50x.html", "/var/www/html/errors"]
    remedy.child_scan_result = {
        file_path: [
            {
                "action": "add",
                "directive": "error_page",
                "args": ["404", "./old404.html"],
                "context": ["config", 0, "parsed", 0, "block"],
                "logical_context": "http",
            }
        ]
    }
    remedy.child_ast_config = {
        file_path: _make_ast([
            _http([
                _node("error_page", ["404", "/old404.html"]),
                _server([
                    _node("listen", ["80"]),
                ])
            ])
        ])
    }

    remedy.remediate()

    http_block = remedy.child_ast_modified[file_path]["parsed"][0]["block"]
    assert [node["args"] for node in http_block if node["directive"] == "error_page"] == [["404", "/404.html"]]


def test_252_adds_error_pages_and_location_under_server(remedy):
    file_path = "/etc/nginx/nginx.conf"

    remedy.user_inputs = ["/404.html", "/50x.html", "/var/www/html/errors"]
    remedy.child_scan_result = {
        file_path: [
            {
                "action": "add",
                "directive": "error_page",
                "args": ["404", "./404.html"],
                "context": ["config", 0, "parsed"],
                "logical_context": "http",
            },
            {
                "action": "add",
                "directive": "error_page",
                "args": ["500", "502", "503", "504", "./50x.html"],
                "context": ["config", 0, "parsed"],
                "logical_context": "http",
            },
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
    root_directives = [node["directive"] for node in parsed]
    assert "error_page" not in root_directives
    assert "location" not in root_directives

    http_block = parsed[0]["block"]
    assert ["404", "/404.html"] in [node["args"] for node in http_block if node["directive"] == "error_page"]
    assert ["500", "502", "503", "504", "/50x.html"] in [node["args"] for node in http_block if node["directive"] == "error_page"]

    server_block = http_block[0]["block"]
    location_nodes = [node for node in server_block if node["directive"] == "location"]
    assert len(location_nodes) == 1
    assert location_nodes[0]["args"] == ["=", "/50x.html"]
    assert [node["directive"] for node in location_nodes[0]["block"]] == ["root", "internal"]
    assert location_nodes[0]["block"][0]["args"] == ["/var/www/html/errors"]
