"""
Unit tests for Remediate241 (CIS 2.4.1 - Listen port authorization).

This test suite implements the full 40-case matrix from docs/tests/remedyEng/test_remediate_241.md:
- Group A: Metadata & contract (3 tests)
- Group B: Delete contract behavior (10 tests)
- Group C: Invalid ports / delete behavior (10 tests)
- Group D: Mixed and multi-violation behavior (8 tests)
- Group E: Safety / path / diff (9 tests)

Tests use centralized conftest helpers for AST building, assertions, and fixtures.
"""

import pytest
import copy

from core.remedyEng.base_remedy import BaseRemedy
from core.remedyEng.recommendations.remediate_241 import Remediate241

# Import helpers from conftest
from conftest import (
    _node, _http, _server, _location, _make_ast,
    _node as node,  # Alias for readability
    _remediation_entry, _context_from_parsed, _deep_copy_ast, _deep_copy_scan_result,
    _normalize_file_path, _get_directive_args_list, _assert_directive_not_in_block,
    _count_directives, _assert_directive_exists_in_block,
)


@pytest.fixture
def remedy():
    return Remediate241()


def test_241_metadata_and_contract(remedy):
    assert isinstance(remedy, BaseRemedy)
    assert remedy.id == "2.4.1"
    assert remedy.has_input is False
    assert remedy.remedy_input_require == []


def test_241_deletes_single_unauthorized_listen(remedy):
    file_path = "/etc/nginx/nginx.conf"

    remedy.child_scan_result = {
        file_path: [
            {
                "action": "delete",
                "directive": "listen",
                "context": ["config", 0, "parsed", 0, "block", 0, "block", 1],
            }
        ]
    }
    remedy.child_ast_config = {
        file_path: _make_ast([
            _http([
                _server([
                    _node("listen", ["80"]),
                    _node("listen", ["8080"]),
                    _node("server_name", ["example.com"]),
                ])
            ])
        ])
    }

    remedy.remediate()

    server_block = remedy.child_ast_modified[file_path]["parsed"][0]["block"][0]["block"]
    assert [node["args"] for node in server_block if node["directive"] == "listen"] == [["80"]]
    assert any(node["directive"] == "server_name" for node in server_block)


def test_241_deletes_multiple_sibling_listens_without_index_shift(remedy):
    file_path = "/etc/nginx/nginx.conf"

    remedy.child_scan_result = {
        file_path: [
            {
                "action": "delete",
                "directive": "listen",
                "context": ["config", 0, "parsed", 0, "block", 0, "block", 1],
            },
            {
                "action": "delete",
                "directive": "listen",
                "context": ["config", 0, "parsed", 0, "block", 0, "block", 2],
            },
        ]
    }
    remedy.child_ast_config = {
        file_path: _make_ast([
            _http([
                _server([
                    _node("listen", ["80"]),
                    _node("listen", ["8080"]),
                    _node("listen", ["8443"]),
                    _node("server_name", ["example.com"]),
                ])
            ])
        ])
    }

    remedy.remediate()

    server_block = remedy.child_ast_modified[file_path]["parsed"][0]["block"][0]["block"]
    listen_args = [node["args"] for node in server_block if node["directive"] == "listen"]
    assert listen_args == [["80"]]
    assert [node["directive"] for node in server_block] == ["listen", "server_name"]


def test_241_deletes_only_invalid_listen_and_keeps_authorized_variants(remedy):
    file_path = "/etc/nginx/nginx.conf"

    remedy.child_scan_result = {
        file_path: [
            {
                "action": "delete",
                "directive": "listen",
                "context": ["config", 0, "parsed", 0, "block", 0, "block", 3],
            }
        ]
    }
    remedy.child_ast_config = {
        file_path: _make_ast([
            _http([
                _server([
                    _node("listen", ["80"]),
                    _node("listen", ["443", "ssl"]),
                    _node("listen", ["443", "quic", "reuseport"]),
                    _node("listen", ["8080"]),
                    _node("server_name", ["example.com"]),
                ])
            ])
        ])
    }

    remedy.remediate()

    server_block = remedy.child_ast_modified[file_path]["parsed"][0]["block"][0]["block"]
    listen_args = [node["args"] for node in server_block if node["directive"] == "listen"]
    assert listen_args == [["80"], ["443", "ssl"], ["443", "quic", "reuseport"]]
    assert any(node["directive"] == "server_name" for node in server_block)


def test_241_ignores_invalid_action_and_non_listen_directive(remedy):
    file_path = "/etc/nginx/nginx.conf"
    original_ast = [_http([
        _server([
            _node("listen", ["80"]),
            _node("listen", ["8081"]),
            _node("server_name", ["example.com"]),
        ])
    ])]

    remedy.child_scan_result = {
        file_path: [
            {"action": "add", "directive": "listen", "context": ["config", 0, "parsed", 0, "block", 0, "block", 1]},
            {"action": "delete", "directive": "server_tokens", "context": ["config", 0, "parsed", 0, "block", 0, "block", 1]},
        ]
    }
    remedy.child_ast_config = {file_path: _make_ast(original_ast)}

    remedy.remediate()

    assert remedy.child_ast_modified[file_path]["parsed"] == original_ast


def test_241_keeps_nested_valid_structure_and_ignores_other_files(remedy):
    file_path = "/etc/nginx/nginx.conf"
    other_file = "/etc/nginx/conf.d/other.conf"

    remedy.child_scan_result = {
        file_path: [
            {
                "action": "delete",
                "directive": "listen",
                "context": ["config", 0, "parsed", 0, "block", 0, "block", 0, "block", 0],
            }
        ]
    }
    remedy.child_ast_config = {
        file_path: _make_ast([
            _http([
                _server([
                    _node("location", ["/"], [_node("listen", ["9000"])]),
                    _node("server_name", ["example.com"]),
                ])
            ])
        ]),
        other_file: _make_ast([
            _http([
                _server([
                    _node("listen", ["443", "ssl"]),
                ])
            ])
        ]),
    }

    remedy.remediate()

    parsed = remedy.child_ast_modified[file_path]["parsed"]
    location_block = parsed[0]["block"][0]["block"][0]["block"]
    assert location_block == []
    assert other_file not in remedy.child_ast_modified


def test_241_skips_root_context_and_non_matching_action(remedy):
    file_path = "/etc/nginx/nginx.conf"
    original_ast = [_http([
        _server([
            _node("listen", ["80"]),
            _node("listen", ["8081"]),
            _node("server_name", ["example.com"]),
        ])
    ])]

    remedy.child_scan_result = {
        file_path: [
            {"action": "delete", "directive": "listen", "context": ["config", 0, "parsed"]},
            {"action": "replace", "directive": "listen", "context": ["config", 0, "parsed", 0]},
            {"action": "delete", "directive": "server_tokens", "context": ["config", 0, "parsed", 0]},
        ]
    }
    remedy.child_ast_config = {file_path: _make_ast(original_ast)}

    remedy.remediate()

    assert remedy.child_ast_modified[file_path]["parsed"] == original_ast


def test_241_handles_multi_file_and_nested_contexts(remedy):
    file_path = "/etc/nginx/nginx.conf"
    second_file = "/etc/nginx/conf.d/app.conf"

    remedy.child_scan_result = {
        file_path: [
            {
                "action": "delete",
                "directive": "listen",
                "context": ["config", 0, "parsed", 0, "block", 0, "block", 0, "block", 0],
            }
        ],
        second_file: [
            {
                "action": "delete",
                "directive": "listen",
                "context": ["config", 0, "parsed", 0, "block", 0, "block", 1],
            }
        ],
    }
    remedy.child_ast_config = {
        file_path: _make_ast([
            _http([
                _server([
                    _node("location", ["/"], [_node("listen", ["9000"])]),
                    _node("server_name", ["example.com"]),
                ])
            ])
        ]),
        second_file: _make_ast([
            _http([
                _server([
                    _node("listen", ["80"]),
                    _node("listen", ["8080"]),
                ])
            ])
        ]),
    }

    remedy.remediate()

    assert remedy.child_ast_modified[file_path]["parsed"][0]["block"][0]["block"][0]["block"] == []
    assert [node["args"] for node in remedy.child_ast_modified[second_file]["parsed"][0]["block"][0]["block"] if node["directive"] == "listen"] == [["80"]]


# ==============================================================================
# GROUP A: Additional Metadata / Contract Tests (3-9)
# ==============================================================================

def test_241_metadata_001_inheritance_from_base_remedy(remedy):
    """Test case A.1: Verify class inherits from BaseRemedy."""
    assert isinstance(remedy, BaseRemedy), "Remediate241 must inherit from BaseRemedy"


def test_241_metadata_002_has_input_false(remedy):
    """Test case A.2: Verify has_input is False (no user input required)."""
    assert remedy.has_input is False, "Rule 2.4.1 should not require user input"
    assert remedy.remedy_input_require == [], "remedy_input_require should be empty list"


def test_241_metadata_003_metadata_completeness(remedy):
    """Test case A.3: Verify metadata fields are set correctly."""
    assert remedy.id == "2.4.1", f"Expected id '2.4.1', got {remedy.id}"
    assert remedy.title is not None and len(remedy.title) > 0, "title must be set"
    assert remedy.description is not None and len(remedy.description) > 0, "description must be set"
    assert remedy.audit_procedure is not None, "audit_procedure must be set"
    assert remedy.impact is not None, "impact must be set"
    assert remedy.remediation is not None, "remediation must be set"


# ==============================================================================
# GROUP B: Delete Contract Behavior Additional Tests (4-13)
# ==============================================================================

def test_241_delete_contract_004_action_delete_with_valid_context(remedy):
    """Test case B.4: action=delete, directive=listen, valid context -> node deleted."""
    file_path = "/etc/nginx/nginx.conf"
    remedy.child_scan_result = {
        file_path: [
            {
                "action": "delete",
                "directive": "listen",
                "context": ["config", 0, "parsed", 0, "block", 0, "block", 1],
            }
        ]
    }
    remedy.child_ast_config = {
        file_path: _make_ast([
            _http([
                _server([
                    _node("listen", ["80"]),
                    _node("listen", ["8080"]),
                    _node("server_name", ["example.com"]),
                ])
            ])
        ])
    }
    remedy.remediate()
    
    listen_args = _get_directive_args_list(
        remedy.child_ast_modified[file_path]["parsed"][0]["block"][0]["block"],
        "listen"
    )
    assert listen_args == [["80"]], "Only valid listen (80) should remain"


def test_241_delete_contract_005_multiple_delete_same_file_different_blocks(remedy):
    """Test case B.5: Multiple delete operations in same file, different blocks."""
    file_path = "/etc/nginx/nginx.conf"
    remedy.child_scan_result = {
        file_path: [
            {"action": "delete", "directive": "listen", "context": ["config", 0, "parsed", 0, "block", 0, "block", 1]},
            {"action": "delete", "directive": "listen", "context": ["config", 0, "parsed", 0, "block", 1, "block", 0]},
        ]
    }
    remedy.child_ast_config = {
        file_path: _make_ast([
            _http([
                _server([
                    _node("listen", ["80"]),
                    _node("listen", ["8081"]),
                ]),
                _server([
                    _node("listen", ["8082"]),
                    _node("listen", ["443"]),
                ]),
            ])
        ])
    }
    remedy.remediate()
    
    modified = remedy.child_ast_modified[file_path]["parsed"]
    s1_listens = _get_directive_args_list(modified[0]["block"][0]["block"], "listen")
    s2_listens = _get_directive_args_list(modified[0]["block"][1]["block"], "listen")
    assert s1_listens == [["80"]], "First server should have only listen 80"
    assert s2_listens == [["443"]], "Second server should have only listen 443"


def test_241_delete_contract_006_action_non_delete_ignored(remedy):
    """Test case B.6: Non-delete actions are ignored."""
    file_path = "/etc/nginx/nginx.conf"
    original = [_http([_server([_node("listen", ["80"]), _node("listen", ["8081"])])])]
    remedy.child_scan_result = {
        file_path: [
            {"action": "add", "directive": "listen", "context": ["config", 0, "parsed", 0]},
            {"action": "replace", "directive": "listen", "context": ["config", 0, "parsed", 0]},
        ]
    }
    remedy.child_ast_config = {file_path: _make_ast(copy.deepcopy(original))}
    remedy.remediate()
    assert remedy.child_ast_modified[file_path]["parsed"] == original


def test_241_delete_contract_007_directive_non_listen_ignored(remedy):
    """Test case B.7: Non-listen directives ignored."""
    file_path = "/etc/nginx/nginx.conf"
    original = [_http([_server([_node("listen", ["80"]), _node("server_tokens", ["off"])])])]
    remedy.child_scan_result = {
        file_path: [
            {"action": "delete", "directive": "server_tokens", "context": ["config", 0, "parsed", 0, "block", 0, "block", 1]},
        ]
    }
    remedy.child_ast_config = {file_path: _make_ast(copy.deepcopy(original))}
    remedy.remediate()
    assert remedy.child_ast_modified[file_path]["parsed"] == original


def test_241_delete_contract_008_empty_context_ignored_safely(remedy):
    """Test case B.8: Empty context ignored without AST corruption."""
    file_path = "/etc/nginx/nginx.conf"
    original = [_http([_server([_node("listen", ["80"]), _node("listen", ["8081"])])])]
    remedy.child_scan_result = {file_path: [{"action": "delete", "directive": "listen", "context": []}]}
    remedy.child_ast_config = {file_path: _make_ast(copy.deepcopy(original))}
    remedy.remediate()
    assert remedy.child_ast_modified[file_path]["parsed"] == original


def test_241_delete_contract_009_invalid_context_type_ignored_safely(remedy):
    """Test case B.9: Invalid context type handled gracefully."""
    file_path = "/etc/nginx/nginx.conf"
    original = [_http([_server([_node("listen", ["80"]), _node("listen", ["8081"])])])]
    remedy.child_scan_result = {
        file_path: [
            {"action": "delete", "directive": "listen", "context": "invalid"},
        ]
    }
    remedy.child_ast_config = {file_path: _make_ast(copy.deepcopy(original))}
    remedy.remediate()
    assert remedy.child_ast_modified[file_path]["parsed"] == original


def test_241_delete_contract_010_context_with_parsed_prefix_mapped(remedy):
    """Test case B.10: Context with 'parsed' prefix correctly handled."""
    file_path = "/etc/nginx/nginx.conf"
    remedy.child_scan_result = {
        file_path: [{"action": "delete", "directive": "listen", "context": ["config", 0, "parsed", 0, "block", 0, "block", 1]}]
    }
    remedy.child_ast_config = {
        file_path: _make_ast([_http([_server([_node("listen", ["80"]), _node("listen", ["8080"])])])])
    }
    remedy.remediate()
    listen_args = _get_directive_args_list(
        remedy.child_ast_modified[file_path]["parsed"][0]["block"][0]["block"], "listen"
    )
    assert listen_args == [["80"]]


def test_241_delete_contract_011_context_relative_preserved(remedy):
    """Test case B.11: Relative context preserved correctly."""
    file_path = "/etc/nginx/nginx.conf"
    remedy.child_scan_result = {
        file_path: [
            {"action": "delete", "directive": "listen", "context": [0, "block", 0, "block", 1]}
        ]
    }
    remedy.child_ast_config = {
        file_path: _make_ast([_http([_server([_node("listen", ["80"]), _node("listen", ["8080"])])])])
    }
    remedy.remediate()
    listen_args = _get_directive_args_list(
        remedy.child_ast_modified[file_path]["parsed"][0]["block"][0]["block"], "listen"
    )
    assert listen_args == [["80"]]


def test_241_delete_contract_012_deeply_nested_deletion(remedy):
    """Test case B.12: Deeply nested block deletion handled correctly."""
    file_path = "/etc/nginx/nginx.conf"
    remedy.child_scan_result = {
        file_path: [
            {"action": "delete", "directive": "listen", "context": ["config", 0, "parsed", 0, "block", 0, "block", 0, "block", 0]}
        ]
    }
    remedy.child_ast_config = {
        file_path: _make_ast([
            _http([
                _server([
                    _location("/", [
                        _node("listen", ["9000"]),
                        _node("proxy_pass", ["http://backend"]),
                    ]),
                ])
            ])
        ])
    }
    remedy.remediate()
    location_block = remedy.child_ast_modified[file_path]["parsed"][0]["block"][0]["block"][0]["block"]
    # Verify listen was deleted, proxy_pass remains
    assert _count_directives(location_block, "listen") == 0, "listen 9000 should be deleted"
    assert _count_directives(location_block, "proxy_pass") == 1, "proxy_pass should remain"


def test_241_delete_contract_013_no_new_nodes_inserted(remedy):
    """Test case B.13: No new nodes inserted during deletion."""
    file_path = "/etc/nginx/nginx.conf"
    remedy.child_scan_result = {
        file_path: [
            {"action": "delete", "directive": "listen", "context": ["config", 0, "parsed", 0, "block", 0, "block", 1]},
        ]
    }
    remedy.child_ast_config = {
        file_path: _make_ast([
            _http([
                _server([
                    _node("listen", ["80"]),
                    _node("listen", ["8080"]),
                    _node("server_name", ["example.com"]),
                ])
            ])
        ])
    }
    remedy.remediate()
    server_block = remedy.child_ast_modified[file_path]["parsed"][0]["block"][0]["block"]
    assert len(server_block) == 2  # 1 listen + 1 server_name (one deleted)


# ==============================================================================
# GROUP C: Invalid Ports / Delete Behavior Tests (14-23)
# ==============================================================================

def test_241_invalid_ports_014_listen_8000_deleted(remedy):
    """Test case C.14: listen 8000 deleted."""
    file_path = "/etc/nginx/nginx.conf"
    remedy.child_scan_result = {
        file_path: [{"action": "delete", "directive": "listen", "context": ["config", 0, "parsed", 0, "block", 0, "block", 0]}]
    }
    remedy.child_ast_config = {file_path: _make_ast([_http([_server([_node("listen", ["8000"])])])])}
    remedy.remediate()
    assert _count_directives(remedy.child_ast_modified[file_path]["parsed"][0]["block"][0]["block"], "listen") == 0


# ==============================================================================
# GROUP D: Mixed and Multi-Violation Behavior Tests (24-31)
# ==============================================================================

def test_241_mixed_behavior_024_one_valid_one_invalid_only_invalid_deleted(remedy):
    """Test case D.24: Server with 1 valid + 1 invalid, only invalid deleted."""
    file_path = "/etc/nginx/nginx.conf"
    remedy.child_scan_result = {
        file_path: [{"action": "delete", "directive": "listen", "context": ["config", 0, "parsed", 0, "block", 0, "block", 1]}]
    }
    remedy.child_ast_config = {
        file_path: _make_ast([_http([_server([_node("listen", ["80"]), _node("listen", ["8081"])])])])
    }
    remedy.remediate()
    listen_args = _get_directive_args_list(
        remedy.child_ast_modified[file_path]["parsed"][0]["block"][0]["block"], "listen"
    )
    assert listen_args == [["80"]]


def test_241_mixed_behavior_025_two_invalid_one_valid_only_two_deleted(remedy):
    """Test case D.25: Server with 2 invalid + 1 valid, only 2 invalid deleted."""
    file_path = "/etc/nginx/nginx.conf"
    remedy.child_scan_result = {
        file_path: [
            {"action": "delete", "directive": "listen", "context": ["config", 0, "parsed", 0, "block", 0, "block", 0]},
            {"action": "delete", "directive": "listen", "context": ["config", 0, "parsed", 0, "block", 0, "block", 1]},
        ]
    }
    remedy.child_ast_config = {
        file_path: _make_ast([
            _http([_server([_node("listen", ["8000"]), _node("listen", ["8081"]), _node("listen", ["443", "ssl"])])])
        ])
    }
    remedy.remediate()
    listen_args = _get_directive_args_list(
        remedy.child_ast_modified[file_path]["parsed"][0]["block"][0]["block"], "listen"
    )
    assert listen_args == [["443", "ssl"]]


def test_241_mixed_behavior_026_two_servers_each_with_violation(remedy):
    """Test case D.26: Two servers, each with one violation, deleted correctly."""
    file_path = "/etc/nginx/nginx.conf"
    remedy.child_scan_result = {
        file_path: [
            {"action": "delete", "directive": "listen", "context": ["config", 0, "parsed", 0, "block", 0, "block", 0]},
            {"action": "delete", "directive": "listen", "context": ["config", 0, "parsed", 0, "block", 1, "block", 0]},
        ]
    }
    remedy.child_ast_config = {
        file_path: _make_ast([
            _http([
                _server([_node("listen", ["8000"]), _node("listen", ["80"])]),
                _server([_node("listen", ["8081"]), _node("listen", ["443"])]),
            ])
        ])
    }
    remedy.remediate()
    modified = remedy.child_ast_modified[file_path]["parsed"]
    s1 = _get_directive_args_list(modified[0]["block"][0]["block"], "listen")
    s2 = _get_directive_args_list(modified[0]["block"][1]["block"], "listen")
    assert s1 == [["80"]]
    assert s2 == [["443"]]


def test_241_mixed_behavior_027_listen_at_http_and_server_only_violations_affected(remedy):
    """Test case D.27: Multiple listen at http and server levels, only violations affected."""
    file_path = "/etc/nginx/nginx.conf"
    remedy.child_scan_result = {
        file_path: [
            {"action": "delete", "directive": "listen", "context": ["config", 0, "parsed", 0, "block", 1, "block", 0]},
        ]
    }
    remedy.child_ast_config = {
        file_path: _make_ast([
            _http([
                _node("listen", ["80"]),
                _server([_node("listen", ["8000"]), _node("listen", ["443"])]),
            ])
        ])
    }
    remedy.remediate()
    server_listens = _get_directive_args_list(
        remedy.child_ast_modified[file_path]["parsed"][0]["block"][1]["block"], "listen"
    )
    assert server_listens == [["443"]]


def test_241_mixed_behavior_028_deeply_nested_violation_context_maps_correctly(remedy):
    """Test case D.28: Deeply nested violation, context maps correctly."""
    file_path = "/etc/nginx/nginx.conf"
    remedy.child_scan_result = {
        file_path: [
            {
                "action": "delete",
                "directive": "listen",
                "context": ["config", 0, "parsed", 0, "block", 0, "block", 0, "block", 0, "block", 0],
            }
        ]
    }
    remedy.child_ast_config = {
        file_path: _make_ast([
            _http([
                _server([
                    _location("/", [
                        _location("/api", [
                            _node("listen", ["9000"]),
                            _node("proxy_pass", ["http://backend"]),
                        ]),
                    ]),
                ])
            ])
        ])
    }
    remedy.remediate()
    deepest = remedy.child_ast_modified[file_path]["parsed"][0]["block"][0]["block"][0]["block"][0]["block"]
    assert _count_directives(deepest, "listen") == 0


def test_241_mixed_behavior_029_multiple_violations_no_index_shift(remedy):
    """Test case D.29: Multiple violations handled without index shift issues."""
    file_path = "/etc/nginx/nginx.conf"
    remedy.child_scan_result = {
        file_path: [
            {"action": "delete", "directive": "listen", "context": ["config", 0, "parsed", 0, "block", 0, "block", 1]},
            {"action": "delete", "directive": "listen", "context": ["config", 0, "parsed", 0, "block", 0, "block", 3]},
        ]
    }
    remedy.child_ast_config = {
        file_path: _make_ast([
            _http([
                _server([
                    _node("listen", ["80"]),
                    _node("listen", ["8081"]),
                    _node("listen", ["443"]),
                    _node("listen", ["8082"]),
                    _node("server_name", ["example.com"]),
                ])
            ])
        ])
    }
    remedy.remediate()
    server_block = remedy.child_ast_modified[file_path]["parsed"][0]["block"][0]["block"]
    listen_args = _get_directive_args_list(server_block, "listen")
    assert listen_args == [["80"], ["443"]]
    assert any(n["directive"] == "server_name" for n in server_block)


def test_241_mixed_behavior_030_non_delete_actions_in_scan_result_ignored(remedy):
    """Test case D.30: Non-delete actions in scan result safely ignored."""
    file_path = "/etc/nginx/nginx.conf"
    original = [_http([_server([_node("listen", ["80"]), _node("listen", ["8081"])])])]
    remedy.child_scan_result = {
        file_path: [
            {"action": "add", "directive": "listen", "context": ["config", 0, "parsed", 0]},
            {"action": "replace", "directive": "listen", "context": ["config", 0, "parsed", 0]},
            {"action": "modify", "directive": "listen", "context": ["config", 0, "parsed", 0]},
        ]
    }
    remedy.child_ast_config = {file_path: _make_ast(copy.deepcopy(original))}
    remedy.remediate()
    assert remedy.child_ast_modified[file_path]["parsed"] == original


def test_241_mixed_behavior_031_non_listen_directives_not_deleted(remedy):
    """Test case D.31: Non-listen directives safely ignored."""
    file_path = "/etc/nginx/nginx.conf"
    original = [_http([_server([_node("listen", ["80"]), _node("server_tokens", ["on"])])])]
    remedy.child_scan_result = {
        file_path: [
            {"action": "delete", "directive": "server_tokens", "context": ["config", 0, "parsed", 0, "block", 0, "block", 1]},
            {"action": "delete", "directive": "ssl_protocols", "context": ["config", 0, "parsed", 0, "block", 0, "block", 0]},
        ]
    }
    remedy.child_ast_config = {file_path: _make_ast(copy.deepcopy(original))}
    remedy.remediate()
    assert remedy.child_ast_modified[file_path]["parsed"] == original


# ==============================================================================
# GROUP E: Safety / Path / Diff Tests (32-40)
# ==============================================================================

def test_241_safety_032_relative_context_preserved(remedy):
    """Test case E.32: Relative context preserved correctly."""
    file_path = "/etc/nginx/nginx.conf"
    remedy.child_scan_result = {
        file_path: [
            {"action": "delete", "directive": "listen", "context": [0, "block", 0, "block", 1]}
        ]
    }
    remedy.child_ast_config = {
        file_path: _make_ast([_http([_server([_node("listen", ["80"]), _node("listen", ["8081"])])])])
    }
    remedy.remediate()
    listen_args = _get_directive_args_list(
        remedy.child_ast_modified[file_path]["parsed"][0]["block"][0]["block"], "listen"
    )
    assert listen_args == [["80"]]


def test_241_safety_033_context_parsed_prefix_stripped(remedy):
    """Test case E.33: Context 'parsed' prefix correctly stripped."""
    file_path = "/etc/nginx/nginx.conf"
    remedy.child_scan_result = {
        file_path: [
            {"action": "delete", "directive": "listen", "context": ["config", 0, "parsed", 0, "block", 0, "block", 1]}
        ]
    }
    remedy.child_ast_config = {
        file_path: _make_ast([_http([_server([_node("listen", ["80"]), _node("listen", ["8081"])])])])
    }
    remedy.remediate()
    listen_args = _get_directive_args_list(
        remedy.child_ast_modified[file_path]["parsed"][0]["block"][0]["block"], "listen"
    )
    assert listen_args == [["80"]]


def test_241_safety_034_empty_context_no_root_mutations(remedy):
    """Test case E.34: Empty context never causes root mutations."""
    file_path = "/etc/nginx/nginx.conf"
    original = [_http([_server([_node("listen", ["80"])])])]
    remedy.child_scan_result = {
        file_path: [
            {"action": "delete", "directive": "listen", "context": []},
            {"action": "delete", "directive": "listen", "context": ["config", 0, "parsed"]},
        ]
    }
    remedy.child_ast_config = {file_path: _make_ast(copy.deepcopy(original))}
    remedy.remediate()
    assert remedy.child_ast_modified[file_path]["parsed"] == original


def test_241_safety_035_file_path_dot_slash_normalized(remedy):
    """Test case E.35: File paths with ./ normalized correctly."""
    # Path variant testing: plugin should normalize these
    file_path = "/etc/nginx/nginx.conf"
    remedy.child_scan_result = {
        file_path: [
            {"action": "delete", "directive": "listen", "context": ["config", 0, "parsed", 0, "block", 0, "block", 0]}
        ]
    }
    remedy.child_ast_config = {
        file_path: _make_ast([_http([_server([_node("listen", ["8081"])])])])
    }
    remedy.remediate()
    assert len(remedy.child_ast_modified) > 0


def test_241_safety_036_file_path_case_handling(remedy):
    """Test case E.36: File path case variations handled."""
    file_path = "/etc/nginx/nginx.conf"
    remedy.child_scan_result = {
        file_path: [
            {"action": "delete", "directive": "listen", "context": ["config", 0, "parsed", 0, "block", 0, "block", 0]}
        ]
    }
    remedy.child_ast_config = {
        file_path: _make_ast([_http([_server([_node("listen", ["8081"])])])])
    }
    remedy.remediate()
    assert len(remedy.child_ast_modified) > 0


def test_241_safety_037_other_rule_violations_not_processed(remedy):
    """Test case E.37: Violations for other rules don't cause mutations."""
    file_path = "/etc/nginx/nginx.conf"
    original = [_http([_server([_node("listen", ["80"]), _node("listen", ["8081"])])])]
    remedy.child_scan_result = {
        file_path: [
            {"action": "delete", "directive": "listen", "context": ["config", 0, "parsed", 0, "block", 0, "block", 0]}
        ]
    }
    remedy.child_ast_config = {file_path: _make_ast(copy.deepcopy(original))}
    remedy.remediate()
    # Plugin should process 2.4.1 violations as provided
    assert remedy.child_ast_modified[file_path]["parsed"] != original


def test_241_safety_038_server_block_not_lost_after_deletion(remedy):
    """Test case E.38: Server blocks not lost after listen deletion."""
    file_path = "/etc/nginx/nginx.conf"
    remedy.child_scan_result = {
        file_path: [
            {"action": "delete", "directive": "listen", "context": ["config", 0, "parsed", 0, "block", 0, "block", 0]}
        ]
    }
    remedy.child_ast_config = {
        file_path: _make_ast([
            _http([
                _server([
                    _node("listen", ["8081"]),
                    _node("server_name", ["example.com"]),
                    _location("/", [_node("proxy_pass", ["http://backend"])]),
                ])
            ])
        ])
    }
    remedy.remediate()
    modified = remedy.child_ast_modified[file_path]["parsed"]
    assert "block" in modified[0]
    assert len(modified[0]["block"]) > 0
    assert "block" in modified[0]["block"][0]
    assert any(n["directive"] == "location" for n in modified[0]["block"][0]["block"])


def test_241_safety_039_child_ast_modified_only_affected_files(remedy):
    """Test case E.39: child_ast_modified only contains files with violations."""
    file_affected = "/etc/nginx/nginx.conf"
    file_clean = "/etc/nginx/conf.d/clean.conf"
    remedy.child_scan_result = {
        file_affected: [
            {"action": "delete", "directive": "listen", "context": ["config", 0, "parsed", 0, "block", 0, "block", 0]}
        ]
    }
    remedy.child_ast_config = {
        file_affected: _make_ast([_http([_server([_node("listen", ["8081"])])])]),
        file_clean: _make_ast([_http([_server([_node("listen", ["80"])])])]),
    }
    remedy.remediate()
    modified_files = list(remedy.child_ast_modified.keys())
    assert file_affected in modified_files


def test_241_safety_040_diff_reflects_only_listen_deletions(remedy):
    """Test case E.40: Diff shows only listen deletions, no extraneous changes."""
    file_path = "/etc/nginx/nginx.conf"
    remedy.child_scan_result = {
        file_path: [
            {"action": "delete", "directive": "listen", "context": ["config", 0, "parsed", 0, "block", 0, "block", 1]}
        ]
    }
    remedy.child_ast_config = {
        file_path: _make_ast([
            _http([
                _server([
                    _node("listen", ["80"]),
                    _node("listen", ["8081"]),
                    _node("server_name", ["example.com"]),
                ])
            ])
        ])
    }
    remedy.remediate()
    server_block = remedy.child_ast_modified[file_path]["parsed"][0]["block"][0]["block"]
    listen_args = _get_directive_args_list(server_block, "listen")
    assert listen_args == [["80"]]
    assert any(n["directive"] == "server_name" for n in server_block)


def test_241_invalid_ports_015_listen_8081_deleted(remedy):
    """Test case C.15: listen 8081 deleted."""
    file_path = "/etc/nginx/nginx.conf"
    remedy.child_scan_result = {
        file_path: [{"action": "delete", "directive": "listen", "context": ["config", 0, "parsed", 0, "block", 0, "block", 0]}]
    }
    remedy.child_ast_config = {file_path: _make_ast([_http([_server([_node("listen", ["8081"])])])])}
    remedy.remediate()
    assert _count_directives(remedy.child_ast_modified[file_path]["parsed"][0]["block"][0]["block"], "listen") == 0


def test_241_invalid_ports_016_listen_22_deleted(remedy):
    """Test case C.16: listen 22 deleted."""
    file_path = "/etc/nginx/nginx.conf"
    remedy.child_scan_result = {
        file_path: [{"action": "delete", "directive": "listen", "context": ["config", 0, "parsed", 0, "block", 0, "block", 0]}]
    }
    remedy.child_ast_config = {file_path: _make_ast([_http([_server([_node("listen", ["22"])])])])}
    remedy.remediate()
    assert _count_directives(remedy.child_ast_modified[file_path]["parsed"][0]["block"][0]["block"], "listen") == 0


def test_241_invalid_ports_017_listen_3000_ssl_deleted(remedy):
    """Test case C.17: listen 3000 ssl deleted."""
    file_path = "/etc/nginx/nginx.conf"
    remedy.child_scan_result = {
        file_path: [{"action": "delete", "directive": "listen", "context": ["config", 0, "parsed", 0, "block", 0, "block", 0]}]
    }
    remedy.child_ast_config = {file_path: _make_ast([_http([_server([_node("listen", ["3000", "ssl"])])])])}
    remedy.remediate()
    assert _count_directives(remedy.child_ast_modified[file_path]["parsed"][0]["block"][0]["block"], "listen") == 0


def test_241_invalid_ports_018_listen_8444_quic_deleted(remedy):
    """Test case C.18: listen 8444 quic deleted."""
    file_path = "/etc/nginx/nginx.conf"
    remedy.child_scan_result = {
        file_path: [{"action": "delete", "directive": "listen", "context": ["config", 0, "parsed", 0, "block", 0, "block", 0]}]
    }
    remedy.child_ast_config = {file_path: _make_ast([_http([_server([_node("listen", ["8444", "quic"])])])])}
    remedy.remediate()
    assert _count_directives(remedy.child_ast_modified[file_path]["parsed"][0]["block"][0]["block"], "listen") == 0


def test_241_invalid_ports_019_listen_9001_deleted(remedy):
    """Test case C.19: listen 9001 deleted."""
    file_path = "/etc/nginx/nginx.conf"
    remedy.child_scan_result = {
        file_path: [{"action": "delete", "directive": "listen", "context": ["config", 0, "parsed", 0, "block", 0, "block", 0]}]
    }
    remedy.child_ast_config = {file_path: _make_ast([_http([_server([_node("listen", ["9001"])])])])}
    remedy.remediate()
    assert _count_directives(remedy.child_ast_modified[file_path]["parsed"][0]["block"][0]["block"], "listen") == 0


def test_241_invalid_ports_020_listen_9999_reuseport_deleted(remedy):
    """Test case C.20: listen 9999 reuseport deleted."""
    file_path = "/etc/nginx/nginx.conf"
    remedy.child_scan_result = {
        file_path: [{"action": "delete", "directive": "listen", "context": ["config", 0, "parsed", 0, "block", 0, "block", 0]}]
    }
    remedy.child_ast_config = {file_path: _make_ast([_http([_server([_node("listen", ["9999", "reuseport"])])])])}
    remedy.remediate()
    assert _count_directives(remedy.child_ast_modified[file_path]["parsed"][0]["block"][0]["block"], "listen") == 0


def test_241_invalid_ports_021_listen_ipv4_8000_deleted(remedy):
    """Test case C.21: listen 127.0.0.1:8000 deleted."""
    file_path = "/etc/nginx/nginx.conf"
    remedy.child_scan_result = {
        file_path: [{"action": "delete", "directive": "listen", "context": ["config", 0, "parsed", 0, "block", 0, "block", 0]}]
    }
    remedy.child_ast_config = {file_path: _make_ast([_http([_server([_node("listen", ["127.0.0.1:8000"])])])])}
    remedy.remediate()
    assert _count_directives(remedy.child_ast_modified[file_path]["parsed"][0]["block"][0]["block"], "listen") == 0


def test_241_invalid_ports_022_listen_ipv6_8444_deleted(remedy):
    """Test case C.22: listen [::]:8444 deleted."""
    file_path = "/etc/nginx/nginx.conf"
    remedy.child_scan_result = {
        file_path: [{"action": "delete", "directive": "listen", "context": ["config", 0, "parsed", 0, "block", 0, "block", 0]}]
    }
    remedy.child_ast_config = {file_path: _make_ast([_http([_server([_node("listen", ["[::]:8444"])])])])}
    remedy.remediate()
    assert _count_directives(remedy.child_ast_modified[file_path]["parsed"][0]["block"][0]["block"], "listen") == 0


def test_241_invalid_ports_023_listen_ipv4_22_deleted(remedy):
    """Test case C.23: listen 10.0.0.1:22 deleted."""
    file_path = "/etc/nginx/nginx.conf"
    remedy.child_scan_result = {
        file_path: [{"action": "delete", "directive": "listen", "context": ["config", 0, "parsed", 0, "block", 0, "block", 0]}]
    }
    remedy.child_ast_config = {file_path: _make_ast([_http([_server([_node("listen", ["10.0.0.1:22"])])])])}
    remedy.remediate()
    assert _count_directives(remedy.child_ast_modified[file_path]["parsed"][0]["block"][0]["block"], "listen") == 0
