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
    assert remedy.remedy_input_require == []
    assert "server_tokens off" in remedy.remedy_guide_detail


def test_251_user_guidance_mentions_automatic_behavior(remedy):
    guidance = remedy.get_user_guidance()

    assert "NO user input" in guidance
    assert "server_tokens off" in guidance
    assert "Impact" in guidance


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


@pytest.mark.parametrize("action", ["replace", "modify", "modify_directive"])
def test_251_accepts_action_aliases(action, remedy):
    file_path = "/etc/nginx/nginx.conf"

    remedy.child_scan_result = {
        file_path: [
            {
                "action": action,
                "directive": "server_tokens",
                "context": ["config", 0, "parsed", 0, "block", 0],
            }
        ]
    }
    remedy.child_ast_config = {
        file_path: _make_ast([_http([_node("server_tokens", ["on"])])])
    }

    remedy.remediate()

    assert remedy.child_ast_modified[file_path]["parsed"][0]["block"][0]["args"] == ["off"]


def test_251_uses_explicit_args_from_scan_payload(remedy):
    file_path = "/etc/nginx/nginx.conf"

    remedy.child_scan_result = {
        file_path: [
            {
                "action": "replace",
                "directive": "server_tokens",
                "args": ["build"],
                "context": ["config", 0, "parsed", 0, "block", 0],
            }
        ]
    }
    remedy.child_ast_config = {
        file_path: _make_ast([_http([_node("server_tokens", ["on"])])])
    }

    remedy.remediate()

    assert remedy.child_ast_modified[file_path]["parsed"][0]["block"][0]["args"] == ["build"]


def test_251_empty_args_normalize_to_off(remedy):
    file_path = "/etc/nginx/nginx.conf"

    remedy.child_scan_result = {
        file_path: [
            {
                "action": "replace",
                "directive": "server_tokens",
                "args": [],
                "context": ["config", 0, "parsed", 0, "block", 0],
            }
        ]
    }
    remedy.child_ast_config = {
        file_path: _make_ast([_http([_node("server_tokens", ["on"])])])
    }

    remedy.remediate()

    assert remedy.child_ast_modified[file_path]["parsed"][0]["block"][0]["args"] == ["off"]


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


def test_251_updates_nested_server_tokens_with_fallback_search(remedy):
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
                _server([
                    _node("location", ["/"], [_node("server_tokens", ["on"])]),
                    _node("listen", ["80"]),
                ]),
            ])
        ])
    }

    remedy.remediate()

    location_block = remedy.child_ast_modified[file_path]["parsed"][0]["block"][0]["block"][0]["block"]
    assert location_block[0]["directive"] == "server_tokens"
    assert location_block[0]["args"] == ["off"]


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


def test_251_skips_non_dict_violation_entries_safely(remedy):
    file_path = "/etc/nginx/nginx.conf"
    original_ast = [_http([_node("server_tokens", ["on"])])]

    remedy.child_scan_result = {
        file_path: [
            "invalid",
            42,
            None,
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


def test_251_context_points_to_other_directive_no_mutation(remedy):
    file_path = "/etc/nginx/nginx.conf"

    remedy.child_scan_result = {
        file_path: [
            {
                "action": "replace",
                "directive": "server_tokens",
                "context": ["config", 0, "parsed", 0, "block", 1],
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
    assert parsed[0]["block"][0]["args"] == ["on"]
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


def test_251_scan_result_empty_produces_no_mutation(remedy):
    file_path = "/etc/nginx/nginx.conf"

    remedy.child_scan_result = {}
    remedy.child_ast_config = {
        file_path: _make_ast([_http([_node("server_tokens", ["on"])])])
    }

    remedy.remediate()

    assert remedy.child_ast_modified == {}


def test_251_child_scan_result_without_file_produces_no_mutation(remedy):
    remedy.child_scan_result = {
        "/etc/nginx/other.conf": [
            {
                "action": "replace",
                "directive": "server_tokens",
                "context": ["config", 0, "parsed", 0, "block", 0],
            }
        ]
    }
    remedy.child_ast_config = {
        "/etc/nginx/nginx.conf": _make_ast([_http([_node("server_tokens", ["on"])])])
    }

    remedy.remediate()

    assert remedy.child_ast_modified == {}


def test_251_multi_file_mutates_only_target_files(remedy):
    file_a = "/etc/nginx/nginx.conf"
    file_b = "/etc/nginx/conf.d/app.conf"

    remedy.child_scan_result = {
        file_a: [
            {
                "action": "replace",
                "directive": "server_tokens",
                "context": ["config", 0, "parsed", 0, "block", 0],
            }
        ]
    }
    remedy.child_ast_config = {
        file_a: _make_ast([_http([_node("server_tokens", ["on"])])]),
        file_b: _make_ast([_http([_node("server_tokens", ["on"])])]),
    }

    remedy.remediate()

    assert set(remedy.child_ast_modified.keys()) == {file_a}
    assert remedy.child_ast_modified[file_a]["parsed"][0]["block"][0]["args"] == ["off"]


def test_251_child_ast_modified_is_deep_copy_not_alias(remedy):
    file_path = "/etc/nginx/nginx.conf"
    original_parsed = [_http([_node("server_tokens", ["on"])])]

    remedy.child_scan_result = {
        file_path: [
            {
                "action": "replace",
                "directive": "server_tokens",
                "context": ["config", 0, "parsed", 0, "block", 0],
            }
        ]
    }
    remedy.child_ast_config = {file_path: {"parsed": original_parsed}}

    remedy.remediate()

    assert original_parsed[0]["block"][0]["args"] == ["on"]
    assert remedy.child_ast_modified[file_path]["parsed"][0]["block"][0]["args"] == ["off"]


def test_251_remediate_is_idempotent(remedy):
    file_path = "/etc/nginx/nginx.conf"

    remedy.child_scan_result = {
        file_path: [
            {
                "action": "replace",
                "directive": "server_tokens",
                "context": [],
            }
        ]
    }
    remedy.child_ast_config = {
        file_path: _make_ast([_http([_node("server_tokens", ["on"])])])
    }

    remedy.remediate()
    first = remedy.child_ast_modified[file_path]["parsed"]

    remedy.child_ast_config = {file_path: {"parsed": first}}
    remedy.remediate()

    second = remedy.child_ast_modified[file_path]["parsed"]
    assert second[0]["block"][0]["args"] == ["off"]


def test_251_read_child_ast_config_matches_normalized_file_path(remedy):
    remedy.child_scan_result = {
        "./etc/nginx/nginx.conf": [
            {
                "action": "replace",
                "directive": "server_tokens",
                "context": ["config", 0, "parsed", 0, "block", 0],
            }
        ]
    }

    ast_config = {
        "config": [
            {
                "file": "/etc/nginx/nginx.conf",
                "parsed": [_http([_node("server_tokens", ["on"])])],
            }
        ]
    }

    remedy.read_child_ast_config(ast_config)

    assert "./etc/nginx/nginx.conf" in remedy.child_ast_config
    assert remedy.child_ast_config["./etc/nginx/nginx.conf"]["parsed"][0]["directive"] == "http"


def test_251_build_file_diff_payload_reflects_server_tokens_replacement(remedy):
    file_path = "/etc/nginx/nginx.conf"

    remedy.child_ast_config = {
        file_path: {"parsed": [_http([_node("server_tokens", ["on"])])]}
    }
    remedy.child_ast_modified = {
        file_path: {"parsed": [_http([_node("server_tokens", ["off"])])]}
    }

    payload = remedy.build_file_diff_payload(file_path)

    assert payload["file_path"] == file_path
    assert payload["mode"] == "config"
    assert "server_tokens off;" in payload["diff_text"]


def test_251_server_tokens_in_server_block_mutates_in_place(remedy):
    file_path = "/etc/nginx/nginx.conf"

    remedy.child_scan_result = {
        file_path: [
            {
                "action": "replace",
                "directive": "server_tokens",
                "context": ["config", 0, "parsed", 0, "block", 0, "block", 1],
            }
        ]
    }
    remedy.child_ast_config = {
        file_path: _make_ast([
            _http([
                _server([
                    _node("listen", ["80"]),
                    _node("server_tokens", ["on"]),
                    _node("server_name", ["example.com"]),
                ])
            ])
        ])
    }

    remedy.remediate()

    server_block = remedy.child_ast_modified[file_path]["parsed"][0]["block"][0]["block"]
    assert [item["directive"] for item in server_block] == ["listen", "server_tokens", "server_name"]
    assert server_block[1]["args"] == ["off"]


def test_251_multi_directive_block_only_server_tokens_mutates(remedy):
    file_path = "/etc/nginx/nginx.conf"

    remedy.child_scan_result = {
        file_path: [
            {
                "action": "replace",
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
                _node("server_name", ["example.com"]),
            ])
        ])
    }

    remedy.remediate()

    http_block = remedy.child_ast_modified[file_path]["parsed"][0]["block"]
    assert http_block[0]["args"] == ["off"]
    assert http_block[1]["args"] == ["80"]
    assert http_block[2]["args"] == ["example.com"]


def test_251_multiple_server_tokens_in_same_file_targets_one_by_context(remedy):
    file_path = "/etc/nginx/nginx.conf"

    remedy.child_scan_result = {
        file_path: [
            {
                "action": "replace",
                "directive": "server_tokens",
                "context": ["config", 0, "parsed", 0, "block", 2, "block", 0],
            }
        ]
    }
    remedy.child_ast_config = {
        file_path: _make_ast([
            _http([
                _node("server_tokens", ["on"]),
                _server([_node("server_tokens", ["on"])]),
                _server([_node("server_tokens", ["on"])]),
            ])
        ])
    }

    remedy.remediate()

    http_block = remedy.child_ast_modified[file_path]["parsed"][0]["block"]
    assert http_block[0]["args"] == ["on"]
    assert http_block[1]["block"][0]["args"] == ["on"]
    assert http_block[2]["block"][0]["args"] == ["off"]


def test_251_updates_targeted_one_when_http_and_server_both_have_server_tokens(remedy):
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
                _server([_node("server_tokens", ["on"])]),
            ])
        ])
    }

    remedy.remediate()

    http_block = remedy.child_ast_modified[file_path]["parsed"][0]["block"]
    assert http_block[0]["args"] == ["off"]
    assert http_block[1]["block"][0]["args"] == ["on"]


def test_251_no_server_tokens_in_ast_with_empty_context_is_noop(remedy):
    file_path = "/etc/nginx/nginx.conf"
    original_ast = [_http([_node("listen", ["80"]), _node("server_name", ["example.com"])])]

    remedy.child_scan_result = {
        file_path: [{"action": "modify", "directive": "server_tokens", "context": []}]
    }
    remedy.child_ast_config = {file_path: _make_ast(original_ast)}

    remedy.remediate()

    assert remedy.child_ast_modified[file_path]["parsed"] == original_ast


def test_251_ast_root_list_not_expanded_when_target_missing(remedy):
    file_path = "/etc/nginx/nginx.conf"

    remedy.child_scan_result = {
        file_path: [{"action": "replace", "directive": "server_tokens", "context": ["config", 0, "parsed", 5]}]
    }
    remedy.child_ast_config = {
        file_path: _make_ast([_node("events", [], [_node("worker_connections", ["1024"])])])
    }

    remedy.remediate()

    parsed = remedy.child_ast_modified[file_path]["parsed"]
    assert len(parsed) == 1
    assert parsed[0]["directive"] == "events"


def test_251_relative_context_conversion_deep_path():
    context = ["config", 0, "parsed", 0, "block", 1, "block", 0]
    relative = BaseRemedy._relative_context(context)

    assert relative == [0, "block", 1, "block", 0]


def test_251_relative_context_keeps_already_relative_context():
    context = [0, "block", 1, "block", 0]
    relative = BaseRemedy._relative_context(context)

    assert relative == [0, "block", 1, "block", 0]


def test_251_read_child_ast_config_matches_case_normalized_file_path(remedy):
    remedy.child_scan_result = {
        "ETC/NGINX/NGINX.CONF": [
            {
                "action": "replace",
                "directive": "server_tokens",
                "context": ["config", 0, "parsed", 0, "block", 0],
            }
        ]
    }

    ast_config = {
        "config": [
            {
                "file": "/etc/nginx/nginx.conf",
                "parsed": [_http([_node("server_tokens", ["on"])])],
            }
        ]
    }

    remedy.read_child_ast_config(ast_config)

    assert "ETC/NGINX/NGINX.CONF" in remedy.child_ast_config


def test_251_server_tokens_position_in_block_preserved_after_mutation(remedy):
    file_path = "/etc/nginx/nginx.conf"

    remedy.child_scan_result = {
        file_path: [
            {
                "action": "replace",
                "directive": "server_tokens",
                "context": ["config", 0, "parsed", 0, "block", 1],
            }
        ]
    }
    remedy.child_ast_config = {
        file_path: _make_ast([
            _http([
                _node("listen", ["80"]),
                _node("server_tokens", ["on"]),
                _node("server_name", ["example.com"]),
            ])
        ])
    }

    remedy.remediate()

    http_block = remedy.child_ast_modified[file_path]["parsed"][0]["block"]
    assert [item["directive"] for item in http_block] == ["listen", "server_tokens", "server_name"]
    assert http_block[1]["args"] == ["off"]


def test_251_already_off_remains_unchanged(remedy):
    file_path = "/etc/nginx/nginx.conf"
    original_ast = [_http([_node("server_tokens", ["off"])])]

    remedy.child_scan_result = {
        file_path: [
            {
                "action": "replace",
                "directive": "server_tokens",
                "context": ["config", 0, "parsed", 0, "block", 0],
            }
        ]
    }
    remedy.child_ast_config = {file_path: _make_ast(original_ast)}

    remedy.remediate()

    assert remedy.child_ast_modified[file_path]["parsed"] == original_ast


def test_251_server_block_already_off_remains_unchanged(remedy):
    file_path = "/etc/nginx/nginx.conf"
    original_ast = [_http([_server([_node("server_tokens", ["off"])])])]

    remedy.child_scan_result = {
        file_path: [
            {
                "action": "modify",
                "directive": "server_tokens",
                "context": ["config", 0, "parsed", 0, "block", 0, "block", 0],
            }
        ]
    }
    remedy.child_ast_config = {file_path: _make_ast(original_ast)}

    remedy.remediate()

    assert remedy.child_ast_modified[file_path]["parsed"] == original_ast


def test_251_multiple_server_tokens_same_block_targets_specific_index(remedy):
    file_path = "/etc/nginx/nginx.conf"

    remedy.child_scan_result = {
        file_path: [
            {
                "action": "replace",
                "directive": "server_tokens",
                "context": ["config", 0, "parsed", 0, "block", 2],
            }
        ]
    }
    remedy.child_ast_config = {
        file_path: _make_ast([
            _http([
                _node("server_tokens", ["on"]),
                _node("listen", ["80"]),
                _node("server_tokens", ["on"]),
            ])
        ])
    }

    remedy.remediate()

    http_block = remedy.child_ast_modified[file_path]["parsed"][0]["block"]
    assert http_block[0]["args"] == ["on"]
    assert http_block[2]["args"] == ["off"]


def test_251_mixed_valid_invalid_targets_only_valid_directive(remedy):
    file_path = "/etc/nginx/nginx.conf"

    remedy.child_scan_result = {
        file_path: [
            {"action": "replace", "directive": "server_tokens", "context": ["config", 0, "parsed", 0, "block", 0]},
            {"action": "replace", "directive": "server_tokens", "context": ["config", 0, "parsed", 0, "block", 1]},
        ]
    }
    remedy.child_ast_config = {
        file_path: _make_ast([_http([_node("server_tokens", ["on"]), _node("listen", ["80"])])])
    }

    remedy.remediate()

    http_block = remedy.child_ast_modified[file_path]["parsed"][0]["block"]
    assert http_block[0]["args"] == ["off"]
    assert http_block[1]["args"] == ["80"]


def test_251_non_list_file_violations_are_skipped(remedy):
    file_path = "/etc/nginx/nginx.conf"

    remedy.child_scan_result = {file_path: {"action": "replace"}}
    remedy.child_ast_config = {file_path: _make_ast([_http([_node("server_tokens", ["on"])])])}

    remedy.remediate()

    assert remedy.child_ast_modified == {}


def test_251_child_ast_config_entry_without_parsed_is_skipped(remedy):
    file_path = "/etc/nginx/nginx.conf"

    remedy.child_scan_result = {
        file_path: [{"action": "replace", "directive": "server_tokens", "context": ["config", 0, "parsed", 0, "block", 0]}]
    }
    remedy.child_ast_config = {file_path: {"file": file_path}}

    remedy.remediate()

    assert remedy.child_ast_modified == {}


def test_251_diff_focuses_on_server_tokens_change(remedy):
    file_path = "/etc/nginx/nginx.conf"

    before = [_http([_node("server_tokens", ["on"]), _node("listen", ["80"])])]
    after = [_http([_node("server_tokens", ["off"]), _node("listen", ["80"])])]

    remedy.child_ast_config = {file_path: {"parsed": before}}
    remedy.child_ast_modified = {file_path: {"parsed": after}}

    payload = remedy.build_file_diff_payload(file_path)

    assert "server_tokens off;" in payload["diff_text"]
    assert "listen 80;" in payload["diff_text"]


def test_251_remediate_accepts_already_relative_context_payload(remedy):
    file_path = "/etc/nginx/nginx.conf"

    remedy.child_scan_result = {
        file_path: [
            {
                "action": "replace",
                "directive": "server_tokens",
                "context": [0, "block", 0],
            }
        ]
    }
    remedy.child_ast_config = {
        file_path: _make_ast([_http([_node("server_tokens", ["on"]), _node("listen", ["80"])])])
    }

    remedy.remediate()

    http_block = remedy.child_ast_modified[file_path]["parsed"][0]["block"]
    assert http_block[0]["args"] == ["off"]
    assert http_block[1]["args"] == ["80"]
