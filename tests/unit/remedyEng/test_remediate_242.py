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


def _directive_args(block: list, directive: str) -> list[list[str]]:
    return [node["args"] for node in block if node.get("directive") == directive]


def test_242_metadata_and_contract(remedy):
    assert isinstance(remedy, BaseRemedy)
    assert remedy.has_input is True
    assert remedy.id == "2.4.2"
    assert remedy.remedy_input_require == ["server_name (default: '_' for wildcard)"]
    assert "Catch-All" in remedy.remedy_guide_detail


def test_242_user_guidance_mentions_strict_placement_and_return_444(remedy):
    guidance = remedy.get_user_guidance()

    assert "strict-placement" in guidance
    assert "return 444" in guidance
    assert "ssl_reject_handshake" in guidance


@pytest.mark.parametrize(
    "user_inputs, expected_valid, expected_input0, expected_error",
    [
        ([], True, "_", ""),
        ([""], True, "_", ""),
        (["   "], True, "_", ""),
        (["_"], True, "_", ""),
        (["example.com"], False, "example.com", "not catch-all"),
        (["admin.local"], False, "admin.local", "not catch-all"),
        (["*.example.com"], False, "*.example.com", "not catch-all"),
        (["_ extra"], False, "_ extra", "not catch-all"),
        (["_ _"], False, "_ _", "not catch-all"),
        (["_;"], False, "_;", "not catch-all"),
        (["$host"], False, "$host", "not catch-all"),
        (["🔥"], False, "🔥", "not catch-all"),
        (["_\nexample.com"], False, "_\nexample.com", "not catch-all"),
    ],
)
def test_242_validate_user_inputs_matrix(remedy, user_inputs, expected_valid, expected_input0, expected_error):
    remedy.user_inputs = user_inputs

    is_valid, error = remedy._validate_user_inputs()

    assert is_valid is expected_valid
    assert remedy.user_inputs[0] == expected_input0
    if expected_error:
        assert expected_error in error
    else:
        assert error == ""


def test_242_validate_user_inputs_uses_first_token_when_multiple_user_inputs_provided(remedy):
    remedy.user_inputs = ["_", "example.com"]

    is_valid, error = remedy._validate_user_inputs()

    assert is_valid is True
    assert error == ""
    assert remedy.user_inputs[0] == "_"


@pytest.mark.parametrize("bad_server_name", ["_ extra", "_ _", "_;", "$host", "_\nexample.com"])
def test_242_remediate_noop_for_bad_server_name_tokens(remedy, bad_server_name):
    file_path = "/etc/nginx/nginx.conf"

    remedy.user_inputs = [bad_server_name]
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
    remedy.child_ast_config = {file_path: _make_ast([_http([])])}

    remedy.remediate()

    assert remedy.child_ast_modified == {}


def test_242_default_server_block_contains_full_cis_directives():
    server_block = Remediate242._build_default_server_block("_")
    block = server_block["block"]

    assert server_block["directive"] == "server"
    assert _directive_args(block, "listen") == [
        ["80", "default_server"],
        ["[::]:80", "default_server"],
        ["443", "ssl", "default_server"],
        ["[::]:443", "ssl", "default_server"],
        ["443", "quic", "default_server"],
        ["[::]:443", "quic", "default_server"],
    ]
    assert _directive_args(block, "server_name") == [["_"]]
    assert _directive_args(block, "ssl_reject_handshake") == [["on"]]
    assert _directive_args(block, "return") == [["444"]]


def test_242_remediate_stops_when_user_input_invalid(remedy):
    file_path = "/etc/nginx/nginx.conf"

    remedy.user_inputs = ["example.com"]

    remedy.child_scan_result = {
        file_path: [{"action": "add_block", "directive": "server", "context": ["config", 0, "parsed"]}]
    }
    remedy.child_ast_config = {file_path: _make_ast([_http([])])}

    remedy.remediate()

    assert remedy.child_ast_modified == {}


def test_242_remediate_noop_with_invalid_ast_payload(remedy):
    remedy.user_inputs = ["_"]
    remedy.child_scan_result = {"/etc/nginx/nginx.conf": [{"action": "add_block", "directive": "server", "context": ["config", 0, "parsed"]}]}
    remedy.child_ast_config = []

    remedy.remediate()

    assert remedy.child_ast_modified == {}

def test_242_add_block_inserts_server_into_http_block(remedy):
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
    assert ["80", "default_server"] in _directive_args(default_server, "listen")
    assert ["[::]:80", "default_server"] in _directive_args(default_server, "listen")
    assert ["443", "ssl", "default_server"] in _directive_args(default_server, "listen")
    assert ["[::]:443", "ssl", "default_server"] in _directive_args(default_server, "listen")
    assert ["443", "quic", "default_server"] in _directive_args(default_server, "listen")
    assert ["[::]:443", "quic", "default_server"] in _directive_args(default_server, "listen")
    assert _directive_args(default_server, "server_name") == [["_"]]
    assert _directive_args(default_server, "ssl_reject_handshake") == [["on"]]
    assert _directive_args(default_server, "return") == [["444"]]


def test_242_add_block_appends_when_strict_placement_is_disabled(remedy):
    file_path = "/etc/nginx/nginx.conf"

    remedy.strict_placement = False
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
                ]),
            ])
        ])
    }

    remedy.remediate()

    http_block = remedy.child_ast_modified[file_path]["parsed"][0]["block"]
    assert http_block[0]["directive"] == "map"
    assert http_block[1]["directive"] == "server"
    assert http_block[2]["directive"] == "server"
    assert _directive_args(http_block[2]["block"], "return") == [["444"]]


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
                ]),
            ])
        ])
    }

    remedy.remediate()

    http_block = remedy.child_ast_modified[file_path]["parsed"][0]["block"]
    assert http_block[0]["directive"] == "server"
    assert _directive_args(http_block[0]["block"], "return") == [["444"]]
    assert http_block[1]["directive"] == "map"


def test_242_strict_placement_ignored_when_position_not_zero(remedy):
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
                "position": 2,
            }
        ]
    }
    remedy.child_ast_config = {
        file_path: _make_ast([
            _http([
                _node("map", ["$host", "$server_name"]),
                _server([
                    _node("listen", ["80"]),
                ]),
            ])
        ])
    }

    remedy.remediate()

    http_block = remedy.child_ast_modified[file_path]["parsed"][0]["block"]
    assert [node["directive"] for node in http_block] == ["map", "server", "server"]


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


def test_242_falls_back_to_http_when_context_points_to_server_directive(remedy):
    file_path = "/etc/nginx/nginx.conf"

    remedy.user_inputs = ["_"]
    remedy.child_scan_result = {
        file_path: [
            {
                "action": "add_block",
                "directive": "server",
                "context": ["config", 0, "parsed", 0, "block", 0],
                "logical_context": "server",
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

    http_block = remedy.child_ast_modified[file_path]["parsed"][0]["block"]
    server_nodes = [node for node in http_block if node["directive"] == "server"]
    assert len(server_nodes) == 2


def test_242_falls_back_to_http_when_scan_result_lacks_logical_context(remedy):
    file_path = "/etc/nginx/nginx.conf"

    remedy.user_inputs = ["_"]
    remedy.child_scan_result = {
        file_path: [
            {
                "action": "add_block",
                "directive": "server",
                "context": ["config", 0, "parsed"],
            }
        ]
    }
    remedy.child_ast_config = {
        file_path: _make_ast([_http([])])
    }

    remedy.remediate()

    assert any(
        node["directive"] == "server"
        for node in remedy.child_ast_modified[file_path]["parsed"][0]["block"]
    )


def test_242_does_not_insert_into_root_when_http_block_missing(remedy):
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
            _node("events", [], [_node("worker_connections", ["1024"])]),
        ])
    }

    remedy.remediate()

    parsed = remedy.child_ast_modified[file_path]["parsed"]
    assert [node["directive"] for node in parsed] == ["events"]
    assert not any(node["directive"] == "server" for node in parsed)


def test_242_add_block_uses_http_block_when_context_points_to_http_directive(remedy):
    file_path = "/etc/nginx/nginx.conf"

    remedy.user_inputs = ["_"]
    remedy.child_scan_result = {
        file_path: [
            {
                "action": "add_block",
                "directive": "server",
                "context": ["config", 0, "parsed", 0],
                "logical_context": "http",
                "position": 0,
            }
        ]
    }
    remedy.child_ast_config = {
        file_path: _make_ast([
            _http([
                _node("map", ["$host", "$target"]),
            ]),
        ])
    }

    remedy.remediate()

    http_block = remedy.child_ast_modified[file_path]["parsed"][0]["block"]
    assert [node["directive"] for node in http_block] == ["map", "server"]


def test_242_prefers_first_http_block_when_multiple_http_blocks_exist(remedy):
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
            _http([_node("map", ["$host", "$a"])]),
            _http([_node("map", ["$host", "$b"])]),
        ])
    }

    remedy.remediate()

    parsed = remedy.child_ast_modified[file_path]["parsed"]
    assert [node["directive"] for node in parsed[0]["block"]] == ["map", "server"]
    assert [node["directive"] for node in parsed[1]["block"]] == ["map"]


def test_242_add_directive_upserts_return_ssl_and_server_name_in_existing_server(remedy):
    file_path = "/etc/nginx/nginx.conf"

    remedy.user_inputs = ["_"]
    remedy.child_scan_result = {
        file_path: [
            {
                "action": "add_directive",
                "directive": "return",
                "args": ["444"],
                "context": ["config", 0, "parsed", 0, "block", 0, "block"],
            },
            {
                "action": "add",
                "directive": "ssl_reject_handshake",
                "args": ["on"],
                "context": ["config", 0, "parsed", 0, "block", 0, "block"],
            },
        ]
    }
    remedy.child_ast_config = {
        file_path: _make_ast([
            _http([
                _server([
                    _node("listen", ["80", "default_server"]),
                    _node("server_name", ["legacy.example"]),
                ])
            ])
        ])
    }

    remedy.remediate()

    server_block = remedy.child_ast_modified[file_path]["parsed"][0]["block"][0]["block"]
    assert _directive_args(server_block, "return") == [["444"]]
    assert _directive_args(server_block, "ssl_reject_handshake") == [["on"]]
    assert _directive_args(server_block, "server_name") == [["_"]]


def test_242_add_directive_updates_existing_return_args(remedy):
    file_path = "/etc/nginx/nginx.conf"

    remedy.user_inputs = ["_"]
    remedy.child_scan_result = {
        file_path: [
            {
                "action": "add_directive",
                "directive": "return",
                "args": ["444"],
                "context": ["config", 0, "parsed", 0, "block", 0, "block"],
            }
        ]
    }
    remedy.child_ast_config = {
        file_path: _make_ast([
            _http([
                _server([
                    _node("listen", ["80", "default_server"]),
                    _node("return", ["301", "https://example.com$request_uri"]),
                ])
            ])
        ])
    }

    remedy.remediate()

    server_block = remedy.child_ast_modified[file_path]["parsed"][0]["block"][0]["block"]
    assert _directive_args(server_block, "return") == [["444"]]


def test_242_add_directive_with_non_list_args_skips_return_but_still_upserts_server_name(remedy):
    file_path = "/etc/nginx/nginx.conf"
    original_ast = [_http([_server([_node("listen", ["80"])])])]

    remedy.user_inputs = ["_"]
    remedy.child_scan_result = {
        file_path: [
            {
                "action": "add_directive",
                "directive": "return",
                "args": "444",
                "context": ["config", 0, "parsed", 0, "block", 0, "block"],
            }
        ]
    }
    remedy.child_ast_config = {file_path: _make_ast(original_ast)}

    remedy.remediate()

    server_block = remedy.child_ast_modified[file_path]["parsed"][0]["block"][0]["block"]
    assert _directive_args(server_block, "return") == []
    assert _directive_args(server_block, "server_name") == [["_"]]


def test_242_skips_file_with_non_list_parsed_node(remedy):
    file_path = "/etc/nginx/nginx.conf"

    remedy.user_inputs = ["_"]
    remedy.child_scan_result = {
        file_path: [{"action": "add_block", "directive": "server", "context": ["config", 0, "parsed"]}]
    }
    remedy.child_ast_config = {
        file_path: {"parsed": {"directive": "http", "block": []}},
    }

    remedy.remediate()

    assert remedy.child_ast_modified == {}


def test_242_defaults_server_name_to_wildcard_during_remediate_when_blank_input(remedy):
    file_path = "/etc/nginx/nginx.conf"

    remedy.user_inputs = ["   "]
    remedy.child_scan_result = {
        file_path: [{"action": "add_block", "directive": "server", "context": ["config", 0, "parsed"]}]
    }
    remedy.child_ast_config = {
        file_path: _make_ast([_http([])]),
    }

    remedy.remediate()

    server_block = remedy.child_ast_modified[file_path]["parsed"][0]["block"][0]["block"]
    assert _directive_args(server_block, "server_name") == [["_"]]


def test_242_add_directive_uses_http_fallback_when_context_is_root(remedy):
    file_path = "/etc/nginx/nginx.conf"

    remedy.user_inputs = ["_"]
    remedy.child_scan_result = {
        file_path: [
            {
                "action": "add_directive",
                "directive": "return",
                "args": ["444"],
                "context": ["config", 0, "parsed"],
            }
        ]
    }
    remedy.child_ast_config = {
        file_path: _make_ast([
            _http([])
        ])
    }

    remedy.remediate()

    http_block = remedy.child_ast_modified[file_path]["parsed"][0]["block"]
    assert _directive_args(http_block, "return") == [["444"]]
    assert _directive_args(http_block, "server_name") == [["_"]]


def test_242_multi_file_only_mutates_files_with_violations(remedy):
    file_target = "/etc/nginx/nginx.conf"
    file_untouched = "/etc/nginx/conf.d/app.conf"

    remedy.user_inputs = ["_"]
    remedy.child_scan_result = {
        file_target: [
            {
                "action": "add_block",
                "directive": "server",
                "context": ["config", 0, "parsed"],
            }
        ]
    }
    remedy.child_ast_config = {
        file_target: _make_ast([_http([])]),
        file_untouched: _make_ast([_http([_server([_node("listen", ["80"])])])]),
    }

    remedy.remediate()

    assert set(remedy.child_ast_modified.keys()) == {file_target}
    assert any(
        node["directive"] == "server"
        for node in remedy.child_ast_modified[file_target]["parsed"][0]["block"]
    )


def test_242_add_block_updates_existing_default_server_instead_of_duplicate(remedy):
    file_path = "/etc/nginx/nginx.conf"

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
                _server([
                    _node("listen", ["80", "default_server"]),
                    _node("server_name", ["_"]),
                    _node("return", ["400"]),
                ]),
            ])
        ])
    }

    remedy.remediate()

    http_block = remedy.child_ast_modified[file_path]["parsed"][0]["block"]
    server_nodes = [node for node in http_block if node["directive"] == "server"]
    assert len(server_nodes) == 1
    assert _directive_args(server_nodes[0]["block"], "return") == [["444"]]
    assert _directive_args(server_nodes[0]["block"], "ssl_reject_handshake") == [["on"]]


def test_242_remediate_is_idempotent_for_add_block(remedy):
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
        file_path: _make_ast([_http([])])
    }

    remedy.remediate()
    first_result = remedy.child_ast_modified[file_path]["parsed"]

    remedy.child_ast_config = {file_path: {"parsed": first_result}}
    remedy.remediate()

    second_http_block = remedy.child_ast_modified[file_path]["parsed"][0]["block"]
    server_nodes = [node for node in second_http_block if node["directive"] == "server"]
    assert len(server_nodes) == 1


def test_242_read_child_ast_config_matches_normalized_file_path(remedy):
    remedy.child_scan_result = {
        "./etc/nginx/nginx.conf": [
            {
                "action": "add_block",
                "directive": "server",
                "context": ["config", 0, "parsed"],
            }
        ]
    }

    ast_config = {
        "config": [
            {
                "file": "/etc/nginx/nginx.conf",
                "parsed": [_http([])],
            }
        ]
    }

    remedy.read_child_ast_config(ast_config)

    assert "./etc/nginx/nginx.conf" in remedy.child_ast_config
    assert isinstance(remedy.child_ast_config["./etc/nginx/nginx.conf"]["parsed"], list)


def test_242_build_file_diff_payload_contains_server_block_diff(remedy):
    file_path = "/etc/nginx/nginx.conf"

    before_parsed = [_http([])]
    after_parsed = [_http([Remediate242._build_default_server_block("_")])]

    remedy.child_ast_config = {file_path: {"parsed": before_parsed}}
    remedy.child_ast_modified = {file_path: {"parsed": after_parsed}}

    payload = remedy.build_file_diff_payload(file_path)

    assert payload["file_path"] == file_path
    assert payload["mode"] == "config"
    assert "listen 80 default_server;" in payload["diff_text"]
    assert "return 444;" in payload["diff_text"]


def test_242_ignores_non_dict_and_unrelated_remediation_entries(remedy):
    file_path = "/etc/nginx/nginx.conf"
    original_ast = [_http([_server([_node("listen", ["80"])])])]

    remedy.user_inputs = ["_"]
    remedy.child_scan_result = {
        file_path: [
            "invalid",
            {"action": "delete", "directive": "server", "context": ["config", 0, "parsed", 0, "block", 0]},
            {"action": "add", "directive": "listen", "args": ["443"], "context": ["config", 0, "parsed", 0, "block", 0, "block"]},
        ]
    }
    remedy.child_ast_config = {file_path: _make_ast(original_ast)}

    remedy.remediate()

    assert remedy.child_ast_modified[file_path]["parsed"] == original_ast
