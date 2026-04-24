from core.remedyEng.ast_editor import ASTEditor
from core.remedyEng.recommendations.remediate_242 import Remediate242
from core.remedyEng.recommendations.remediate_252 import Remediate252
from core.remedyEng.recommendations.remediate_251 import Remediate251
from core.remedyEng.recommendations.remediate_411 import Remediate411


def _find_first_block(parsed, directive_name):
    for node in parsed:
        if isinstance(node, dict) and node.get("directive") == directive_name:
            return node.get("block", [])
    return []


def test_rule_252_rejects_invalid_error_page_paths():
    remedy = Remediate252()
    remedy.user_inputs = ["./404.html", "/50x.html", "/var/www/html"]

    is_valid, error = remedy._validate_user_inputs()

    assert not is_valid
    assert "Invalid 40x error_page URI" in error


def test_rule_411_requires_request_uri_in_redirect_target():
    remedy = Remediate411()
    remedy.user_inputs = ["301", "https://example.com"]

    is_valid, error = remedy._validate_user_inputs()

    assert not is_valid
    assert "$request_uri" in error


def test_rule_242_requires_wildcard_server_name():
    remedy = Remediate242()
    remedy.user_inputs = ["test.name"]

    is_valid, error = remedy._validate_user_inputs()

    assert not is_valid
    assert "Use '_'" in error


def test_rule_252_inserts_error_page_in_http_not_root_and_location_in_server():
    remedy = Remediate252()
    remedy.user_inputs = ["/404.html", "/50x.html", "/var/www/html/errors"]
    file_path = "/etc/nginx/nginx.conf"

    # Context intentionally points to parsed root to emulate problematic scanner payload.
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
                "args": ["500", "502", "503", "504", "./502.html"],
                "context": ["config", 0, "parsed"],
                "logical_context": "http",
            },
        ]
    }
    remedy.child_ast_config = {
        file_path: {
            "parsed": [
                {
                    "directive": "http",
                    "args": [],
                    "block": [
                        {
                            "directive": "server",
                            "args": [],
                            "block": [],
                        }
                    ],
                }
            ]
        }
    }

    remedy.remediate()

    parsed = remedy.child_ast_modified[file_path]["parsed"]

    # Root-level parsed list should not directly receive error_page/location directives.
    root_directives = [node.get("directive") for node in parsed if isinstance(node, dict)]
    assert "error_page" not in root_directives
    assert "location" not in root_directives

    http_block = _find_first_block(parsed, "http")
    assert any(
        item.get("directive") == "error_page" and item.get("args") == ["404", "/404.html"]
        for item in http_block
        if isinstance(item, dict)
    )
    assert any(
        item.get("directive") == "error_page" and item.get("args") == ["500", "502", "503", "504", "/50x.html"]
        for item in http_block
        if isinstance(item, dict)
    )

    server_block = []
    for item in http_block:
        if isinstance(item, dict) and item.get("directive") == "server":
            server_block = item.get("block", [])
            break

    location_node = None
    for item in server_block:
        if isinstance(item, dict) and item.get("directive") == "location":
            location_node = item
            break

    assert location_node is not None
    assert location_node.get("args") == ["=", "/50x.html"]


def test_rule_411_places_return_in_server_not_root_when_context_is_root():
    remedy = Remediate411()
    remedy.user_inputs = ["301", "https://$host$request_uri"]
    file_path = "/etc/nginx/nginx.conf"

    remedy.child_scan_result = {
        file_path: [
            {
                "action": "add",
                "directive": "return",
                "context": ["config", 0, "parsed"],
            }
        ]
    }
    remedy.child_ast_config = {
        file_path: {
            "parsed": [
                {
                    "directive": "http",
                    "args": [],
                    "block": [
                        {
                            "directive": "server",
                            "args": [],
                            "block": [],
                        }
                    ],
                }
            ]
        }
    }

    remedy.remediate()
    parsed = remedy.child_ast_modified[file_path]["parsed"]

    root_directives = [node.get("directive") for node in parsed if isinstance(node, dict)]
    assert "return" not in root_directives

    http_block = _find_first_block(parsed, "http")
    server_block = []
    for item in http_block:
        if isinstance(item, dict) and item.get("directive") == "server":
            server_block = item.get("block", [])
            break

    assert any(
        item.get("directive") == "return" and item.get("args") == ["301", "https://$host$request_uri"]
        for item in server_block
        if isinstance(item, dict)
    )


def test_rule_242_places_default_server_in_http_not_root_when_context_is_root():
    remedy = Remediate242()
    remedy.user_inputs = ["_"]
    file_path = "/etc/nginx/nginx.conf"

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
        file_path: {
            "parsed": [
                {
                    "directive": "http",
                    "args": [],
                    "block": [],
                }
            ]
        }
    }

    remedy.remediate()
    parsed = remedy.child_ast_modified[file_path]["parsed"]

    # Root should still only contain http directive.
    root_directives = [node.get("directive") for node in parsed if isinstance(node, dict)]
    assert root_directives == ["http"]

    http_block = _find_first_block(parsed, "http")
    assert any(item.get("directive") == "server" for item in http_block if isinstance(item, dict))


def test_ast_editor_normalizes_new_scan_result_payload():
    file_path = "/etc/nginx/nginx.conf"
    exact_path = ["config", 0, "parsed", 5, "block", 2]
    scan_result = {
        "recommendations": [
            {
                "id": "2.5.1",
                "uncompliances": [
                    {
                        "file": file_path,
                        "remediations": [
                            {
                                "action": "replace",
                                "directive": "server_tokens",
                                "value": "off",
                                "logical_context": ["http"],
                                "exact_path": exact_path,
                            }
                        ],
                    }
                ],
            }
        ]
    }

    result = ASTEditor.to_context_scan(scan_result, "CIS_2_5_1")

    assert file_path in result
    remediation = result[file_path][0]
    assert remediation["context"] == exact_path
    assert remediation["exact_path"] == exact_path
    assert remediation["logical_context"] == "http"
    assert remediation["args"] == ["off"]


def test_rule_251_uses_normalized_value_only_payload():
    remedy = Remediate251()
    file_path = "/etc/nginx/nginx.conf"

    scan_result = {
        "recommendations": [
            {
                "id": "2.5.1",
                "uncompliances": [
                    {
                        "file": file_path,
                        "remediations": [
                            {
                                "action": "replace",
                                "directive": "server_tokens",
                                "value": "off",
                                "logical_context": ["http"],
                                "exact_path": ["config", 0, "parsed", 0, "block", 0],
                            }
                        ],
                    }
                ],
            }
        ]
    }

    remedy.read_child_scan_result(scan_result)
    remedy.child_ast_config = {
        file_path: {
            "parsed": [
                {
                    "directive": "http",
                    "args": [],
                    "block": [
                        {
                            "directive": "server_tokens",
                            "args": ["on"],
                        }
                    ],
                }
            ]
        }
    }

    remedy.remediate()

    parsed = remedy.child_ast_modified[file_path]["parsed"]
    http_block = _find_first_block(parsed, "http")
    assert any(
        item.get("directive") == "server_tokens" and item.get("args") == ["off"]
        for item in http_block
        if isinstance(item, dict)
    )


def test_rule_242_uses_new_add_block_payload():
    remedy = Remediate242()
    remedy.user_inputs = ["_"]
    file_path = "/etc/nginx/nginx.conf"

    scan_result = {
        "recommendations": [
            {
                "id": "2.4.2",
                "uncompliances": [
                    {
                        "file": file_path,
                        "remediations": [
                            {
                                "action": "add",
                                "directive": "server",
                                "block": [
                                    {"directive": "listen", "args": ["80", "default_server"]},
                                    {"directive": "server_name", "args": ["_"]},
                                    {"directive": "return", "args": ["444"]},
                                ],
                                "logical_context": ["http"],
                                "exact_path": ["config", 0, "parsed", 5, "block", 12],
                            }
                        ],
                    }
                ],
            }
        ]
    }

    remedy.read_child_scan_result(scan_result)
    remedy.child_ast_config = {
        file_path: {
            "parsed": [
                {
                    "directive": "http",
                    "args": [],
                    "block": [],
                }
            ]
        }
    }

    remedy.remediate()

    parsed = remedy.child_ast_modified[file_path]["parsed"]
    http_block = _find_first_block(parsed, "http")
    assert any(item.get("directive") == "server" for item in http_block if isinstance(item, dict))
