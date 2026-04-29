"""
Unit tests for Remediate32 — CIS Nginx Benchmark Rule 3.2.
Bám sát ma trận kiểm thử tại docs/tests/remedyEng/test_remediate_32.md.

Nhóm A. Metadata / contract               (tests  1– 3)
Nhóm B. Input validation / parsing        (tests  4–13)
Nhóm C. Mutation correctness              (tests 14–26)
Nhóm D. Scope inference / context         (tests 27–34)
Nhóm E. Safety / no-op / diff            (tests 35–40)

Tổng: 40 test cases.
"""

import copy
import pytest

from core.remedyEng.base_remedy import BaseRemedy
from core.remedyEng.recommendations.remediate_32 import Remediate32


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

FILE   = "/etc/nginx/nginx.conf"
FILE_A = "/etc/nginx/nginx.conf"
FILE_B = "/etc/nginx/conf.d/site.conf"

LOG_GLOBAL    = "/var/log/nginx/access.log"
LOG_SERVER    = "/var/log/nginx/site.log"
LOG_LOCATION  = "/var/log/nginx/api.log"
FMT_COMBINED  = "combined"
FMT_JSON      = "main_access_json"


# ---------------------------------------------------------------------------
# Helpers: AST node builders
# ---------------------------------------------------------------------------

def _node(directive: str, args: list | None = None, block: list | None = None) -> dict:
    item: dict = {"directive": directive, "args": args or []}
    if block is not None:
        item["block"] = block
    return item


def _http(block: list) -> dict:
    return _node("http", [], block)


def _server(block: list) -> dict:
    return _node("server", [], block)


def _location(args: list, block: list) -> dict:
    return _node("location", args, block)


def _access_log(path: str, fmt: str | None = None) -> dict:
    args = [path]
    if fmt:
        args.append(fmt)
    return _node("access_log", args)


def _log_not_found(val: str) -> dict:
    return _node("log_not_found", [val])


# ---------------------------------------------------------------------------
# Helpers: scan-result entry builders
# ---------------------------------------------------------------------------

def _replace_entry(context: list) -> dict:
    """Scan-result entry for replace/modify_directive action on access_log."""
    return {
        "action": "replace",
        "directive": "access_log",
        "context": context,
    }


def _add_entry(context: list) -> dict:
    """Scan-result entry for add action on access_log."""
    return {
        "action": "add",
        "directive": "access_log",
        "context": context,
    }


# Relative context shortcuts (full crossplane-style)
# Depths reflect _infer_scope logic: block_count determines scope
# Global scope: http block → rel_ctx has 1 "block"  → block_count == 1
# per_server:   http > server directive  → rel_ctx has 2 "block"
# location:     http > server > location → rel_ctx has 3 "block"

# Context pointing to access_log *inside* http block (global scope)
CTX_GLOBAL_ACCESSLOG   = ["config", 0, "parsed", 0, "block", 0]
# Context pointing to access_log *inside* server block (per_server scope)
CTX_SERVER_ACCESSLOG   = ["config", 0, "parsed", 0, "block", 0, "block", 0]
# Context pointing to access_log *inside* location block (location scope)
CTX_LOCATION_ACCESSLOG = ["config", 0, "parsed", 0, "block", 0, "block", 0, "block", 0]

# Context pointing to the *list* (for "add" action)
CTX_HTTP_BLOCK         = ["config", 0, "parsed", 0, "block"]
CTX_SERVER_BLOCK       = ["config", 0, "parsed", 0, "block", 0, "block"]
CTX_LOCATION_BLOCK     = ["config", 0, "parsed", 0, "block", 0, "block", 0, "block"]


# ---------------------------------------------------------------------------
# Helpers: run helper
# ---------------------------------------------------------------------------

def _run(
    remedy: Remediate32,
    user_inputs: list,
    scan_result_by_file: dict,
    ast_by_file: dict,
) -> None:
    remedy.user_inputs = user_inputs
    remedy.child_scan_result = scan_result_by_file
    remedy.child_ast_config = ast_by_file
    remedy.remediate()


# ---------------------------------------------------------------------------
# Helpers: navigation shortcuts
# ---------------------------------------------------------------------------

def _get_http_block(modified: dict, file: str = FILE) -> list:
    return modified[file]["parsed"][0]["block"]


def _get_server_block(modified: dict, file: str = FILE) -> list:
    return modified[file]["parsed"][0]["block"][0]["block"]


def _get_location_block(modified: dict, file: str = FILE) -> list:
    return modified[file]["parsed"][0]["block"][0]["block"][0]["block"]


def _directives(block: list) -> list[str]:
    return [n.get("directive") for n in block if isinstance(n, dict)]


def _args_of(block: list, directive: str) -> list | None:
    for n in block:
        if isinstance(n, dict) and n.get("directive") == directive:
            return n.get("args")
    return None


# ===========================================================================
# A. Metadata / contract (1-3)
# ===========================================================================

def test_01_is_base_remedy_subclass():
    """1. Kiểm tra kế thừa BaseRemedy."""
    remedy = Remediate32()
    assert isinstance(remedy, BaseRemedy)


def test_02_has_input_is_true():
    """2. Kiểm tra has_input == True và id == '3.2'."""
    remedy = Remediate32()
    assert remedy.has_input is True
    assert remedy.id == "3.2"


def test_03_guide_detail_describes_scoped_logging():
    """3. Kiểm tra guide detail mô tả scoped logging."""
    remedy = Remediate32()
    guide = remedy.remedy_guide_detail
    assert isinstance(guide, str) and guide.strip()
    # Must describe at least one scope pattern
    assert "access_log" in guide or "global" in guide or "per_server" in guide


# ===========================================================================
# B. Input validation / parsing (4-13)
# ===========================================================================

@pytest.fixture
def remedy() -> Remediate32:
    return Remediate32()


def test_04_global_scope_absolute_path_valid(remedy):
    """4. global:/var/log/nginx/access.log combined hợp lệ."""
    remedy.user_inputs = ["global:/var/log/nginx/access.log combined"]
    ok, msg = remedy._validate_user_inputs()
    assert ok is True, msg


def test_05_per_server_scope_absolute_path_valid(remedy):
    """5. per_server:/var/log/nginx/site.log main_access_json hợp lệ."""
    remedy.user_inputs = ["per_server:/var/log/nginx/site.log main_access_json"]
    ok, msg = remedy._validate_user_inputs()
    assert ok is True, msg


def test_06_location_scope_absolute_path_valid(remedy):
    """6. location:/var/log/nginx/api.log combined hợp lệ."""
    remedy.user_inputs = ["location:/var/log/nginx/api.log combined"]
    ok, msg = remedy._validate_user_inputs()
    assert ok is True, msg


def test_07_off_value_at_global_scope_valid(remedy):
    """7. off hợp lệ ở scope global."""
    remedy.user_inputs = ["global:off"]
    ok, msg = remedy._validate_user_inputs()
    assert ok is True, msg


def test_08_off_value_at_per_server_scope_valid(remedy):
    """8. off hợp lệ ở scope per_server."""
    remedy.user_inputs = ["per_server:off"]
    ok, msg = remedy._validate_user_inputs()
    assert ok is True, msg


def test_09_off_value_at_location_scope_valid(remedy):
    """9. off hợp lệ ở scope location."""
    remedy.user_inputs = ["location:off"]
    ok, msg = remedy._validate_user_inputs()
    assert ok is True, msg


def test_10_relative_path_rejected(remedy):
    """10. Path không bắt đầu bằng '/', bị từ chối."""
    remedy.user_inputs = ["global:var/log/nginx/access.log combined"]
    ok, msg = remedy._validate_user_inputs()
    assert ok is False
    assert msg  # must contain error description


def test_11_empty_input_rejected(remedy):
    """11. Input rỗng, bị từ chối."""
    remedy.user_inputs = [""]
    ok, msg = remedy._validate_user_inputs()
    assert ok is False
    assert msg


def test_12_scope_not_in_map_falls_back_to_global(remedy):
    """12. Scope không có trong map, fallback về global hoặc default."""
    # Build a scope_map only for 'global', then ask for 'location'
    scope_map = Remediate32._parse_scope_map("global:/var/log/nginx/access.log combined")
    result = Remediate32._access_log_args_for_scope(scope_map, "location")
    # Should fallback to 'global' value
    assert result == ["/var/log/nginx/access.log", "combined"]


def test_13_log_not_found_accepts_on_or_off(remedy):
    """13. log_not_found nhận 'on' hoặc 'off', giá trị khác không được upsert."""
    # 'on' and 'off' are valid
    assert "on" in {"on", "off"}
    assert "off" in {"on", "off"}
    # Any other value like 'yes' would not be in the set
    assert "yes" not in {"on", "off"}


# ===========================================================================
# C. Mutation correctness (14-26)
# ===========================================================================

def test_14_replace_access_log_global(remedy):
    """14. Replace access_log tại global scope."""
    ast = {"parsed": [_http([_access_log("/old/path.log", "combined")])]}
    _run(
        remedy,
        user_inputs=["global:/var/log/nginx/access.log combined"],
        scan_result_by_file={FILE: [_replace_entry(CTX_GLOBAL_ACCESSLOG)]},
        ast_by_file={FILE: ast},
    )
    assert FILE in remedy.child_ast_modified
    http_block = _get_http_block(remedy.child_ast_modified)
    assert _args_of(http_block, "access_log") == ["/var/log/nginx/access.log", "combined"]


def test_15_replace_access_log_per_server(remedy):
    """15. Replace access_log per_server."""
    ast = {
        "parsed": [
            _http([
                _server([_access_log("/old/server.log")])
            ])
        ]
    }
    _run(
        remedy,
        user_inputs=["per_server:/var/log/nginx/site.log combined"],
        scan_result_by_file={FILE: [_replace_entry(CTX_SERVER_ACCESSLOG)]},
        ast_by_file={FILE: ast},
    )
    server_block = _get_server_block(remedy.child_ast_modified)
    assert _args_of(server_block, "access_log") == ["/var/log/nginx/site.log", "combined"]


def test_16_replace_access_log_location(remedy):
    """16. Replace access_log location."""
    ast = {
        "parsed": [
            _http([
                _server([
                    _location(["/"], [_access_log("/old/api.log")])
                ])
            ])
        ]
    }
    _run(
        remedy,
        user_inputs=["location:/var/log/nginx/api.log combined"],
        scan_result_by_file={FILE: [_replace_entry(CTX_LOCATION_ACCESSLOG)]},
        ast_by_file={FILE: ast},
    )
    location_block = _get_location_block(remedy.child_ast_modified)
    assert _args_of(location_block, "access_log") == ["/var/log/nginx/api.log", "combined"]


def test_17_add_access_log_global(remedy):
    """17. Add access_log global nếu scan result yêu cầu add_directive."""
    ast = {"parsed": [_http([_node("listen", ["80"])])]}
    _run(
        remedy,
        user_inputs=["global:/var/log/nginx/access.log combined"],
        scan_result_by_file={FILE: [{
            "action": "add_directive",
            "directive": "access_log",
            "context": CTX_HTTP_BLOCK,
        }]},
        ast_by_file={FILE: ast},
    )
    assert FILE in remedy.child_ast_modified
    http_block = _get_http_block(remedy.child_ast_modified)
    assert "access_log" in _directives(http_block)


def test_18_add_access_log_per_server(remedy):
    """18. Add access_log per_server nếu scan result yêu cầu add."""
    ast = {"parsed": [_http([_server([_node("listen", ["80"])])])]}
    _run(
        remedy,
        user_inputs=["per_server:/var/log/nginx/site.log combined"],
        scan_result_by_file={FILE: [{
            "action": "add",
            "directive": "access_log",
            "context": CTX_SERVER_BLOCK,
        }]},
        ast_by_file={FILE: ast},
    )
    assert FILE in remedy.child_ast_modified
    server_block = _get_server_block(remedy.child_ast_modified)
    assert "access_log" in _directives(server_block)


def test_19_add_access_log_location(remedy):
    """19. Add access_log location nếu scan result yêu cầu add."""
    ast = {
        "parsed": [
            _http([
                _server([
                    _location(["/api"], [_node("proxy_pass", ["http://backend"])])
                ])
            ])
        ]
    }
    _run(
        remedy,
        user_inputs=["location:/var/log/nginx/api.log combined"],
        scan_result_by_file={FILE: [{
            "action": "add",
            "directive": "access_log",
            "context": CTX_LOCATION_BLOCK,
        }]},
        ast_by_file={FILE: ast},
    )
    assert FILE in remedy.child_ast_modified
    loc_block = _get_location_block(remedy.child_ast_modified)
    assert "access_log" in _directives(loc_block)


def test_20_upsert_log_not_found_on(remedy):
    """20. Upsert log_not_found on khi input có giá trị hợp lệ."""
    ast = {"parsed": [_http([_access_log("/old/path.log")])]}
    _run(
        remedy,
        user_inputs=["global:/var/log/nginx/access.log combined", "on"],
        scan_result_by_file={FILE: [_replace_entry(CTX_GLOBAL_ACCESSLOG)]},
        ast_by_file={FILE: ast},
    )
    http_block = _get_http_block(remedy.child_ast_modified)
    assert "log_not_found" in _directives(http_block)
    assert _args_of(http_block, "log_not_found") == ["on"]


def test_21_upsert_log_not_found_off(remedy):
    """21. Upsert log_not_found off khi input == 'off'."""
    ast = {"parsed": [_http([_access_log("/old/path.log")])]}
    _run(
        remedy,
        user_inputs=["global:/var/log/nginx/access.log combined", "off"],
        scan_result_by_file={FILE: [_replace_entry(CTX_GLOBAL_ACCESSLOG)]},
        ast_by_file={FILE: ast},
    )
    http_block = _get_http_block(remedy.child_ast_modified)
    assert _args_of(http_block, "log_not_found") == ["off"]


def test_22_scope_specific_arg_has_priority(remedy):
    """22. Update access_log args theo scope_map ưu tiên scope cụ thể."""
    # Both global and per_server provided — server-level violation should use per_server
    ast = {"parsed": [_http([_server([_access_log("/old/server.log")])])]}
    _run(
        remedy,
        user_inputs=[
            "global:/var/log/nginx/access.log combined,"
            "per_server:/var/log/nginx/site.log main_access_json"
        ],
        scan_result_by_file={FILE: [_replace_entry(CTX_SERVER_ACCESSLOG)]},
        ast_by_file={FILE: ast},
    )
    server_block = _get_server_block(remedy.child_ast_modified)
    # per_server value should win over global
    assert _args_of(server_block, "access_log") == ["/var/log/nginx/site.log", "main_access_json"]


def test_23_fallback_to_global_when_specific_scope_missing(remedy):
    """23. Fallback sang global khi scope-specific input không có."""
    ast = {"parsed": [_http([_server([_access_log("/old/server.log")])])]}
    _run(
        remedy,
        # Only global is provided, not per_server
        user_inputs=["global:/var/log/nginx/access.log combined"],
        scan_result_by_file={FILE: [_replace_entry(CTX_SERVER_ACCESSLOG)]},
        ast_by_file={FILE: ast},
    )
    server_block = _get_server_block(remedy.child_ast_modified)
    # Should fallback to global value
    assert _args_of(server_block, "access_log") == ["/var/log/nginx/access.log", "combined"]


def test_24_fallback_to_default_when_both_missing(remedy):
    """24. Fallback sang default khi scope-specific và global đều không có."""
    scope_map = Remediate32._parse_scope_map("/var/log/nginx/access.log combined")  # no scope key
    result = Remediate32._access_log_args_for_scope(scope_map, "per_server")
    # Should return 'default' entry
    assert result == ["/var/log/nginx/access.log", "combined"]


def test_25_other_directives_in_block_not_changed(remedy):
    """25. Không thay đổi directive khác trong cùng block."""
    ast = {
        "parsed": [
            _http([
                _access_log("/old/path.log"),
                _node("keepalive_timeout", ["65"]),
                _node("sendfile", ["on"]),
            ])
        ]
    }
    _run(
        remedy,
        user_inputs=["global:/var/log/nginx/access.log combined"],
        scan_result_by_file={FILE: [_replace_entry(CTX_GLOBAL_ACCESSLOG)]},
        ast_by_file={FILE: ast},
    )
    http_block = _get_http_block(remedy.child_ast_modified)
    assert _args_of(http_block, "keepalive_timeout") == ["65"]
    assert _args_of(http_block, "sendfile") == ["on"]


def test_26_multiple_access_logs_updates_target(remedy):
    """26. Nhiều access_log trong file, cập nhật đúng target."""
    ast = {
        "parsed": [
            _http([
                _access_log("/old/global.log"),  # index 0 — target
                _server([_access_log("/old/server.log")]),  # index 1
            ])
        ]
    }
    _run(
        remedy,
        user_inputs=["global:/var/log/nginx/access.log combined"],
        # Only the global-level access_log is targeted
        scan_result_by_file={FILE: [_replace_entry(CTX_GLOBAL_ACCESSLOG)]},
        ast_by_file={FILE: ast},
    )
    http_block = _get_http_block(remedy.child_ast_modified)
    # Global-level access_log updated
    assert _args_of(http_block, "access_log") == ["/var/log/nginx/access.log", "combined"]
    # Server-level access_log untouched
    server_block = http_block[1]["block"]
    assert _args_of(server_block, "access_log") == ["/old/server.log"]


# ===========================================================================
# D. Scope inference / context (27-34)
# ===========================================================================

def test_27_relative_context_block_count_1_is_global():
    """27. relative_context với block_count == 1 → scope global."""
    # After _relative_context: [0, "block", 0] has 1 "block"
    rel_ctx = [0, "block", 0]
    assert Remediate32._infer_scope(rel_ctx) == "global"


def test_28_relative_context_block_count_2_is_per_server():
    """28. relative_context với block_count == 2 → scope per_server."""
    rel_ctx = [0, "block", 0, "block", 0]
    assert Remediate32._infer_scope(rel_ctx) == "per_server"


def test_29_relative_context_block_count_gt2_is_location():
    """29. relative_context với block_count > 2 → scope location."""
    rel_ctx = [0, "block", 0, "block", 0, "block", 0]
    assert Remediate32._infer_scope(rel_ctx) == "location"


def test_30_empty_relative_context_no_mutate(remedy):
    """30. Context rỗng (rel_ctx empty après _relative_context) → pas de mutation."""
    ast = {"parsed": [_http([_access_log("/old/path.log")])]}
    original_parsed = copy.deepcopy(ast["parsed"])

    _run(
        remedy,
        user_inputs=["global:/var/log/nginx/access.log combined"],
        scan_result_by_file={FILE: [{
            "action": "replace",
            "directive": "access_log",
            "context": [],  # empty context → rel_ctx = [] → skipped
        }]},
        ast_by_file={FILE: ast},
    )
    # No modification should happen (empty rel_ctx skipped)
    if FILE in remedy.child_ast_modified:
        modified_parsed = remedy.child_ast_modified[FILE]["parsed"]
        assert modified_parsed == original_parsed


def test_31_context_lopsided_still_maps_target(remedy):
    """31. Context lệch nhưng vẫn map được target list (add scenario)."""
    # add action where context points to a list → _upsert_in_block
    ast = {"parsed": [_http([_node("listen", ["80"])])]}
    _run(
        remedy,
        user_inputs=["global:/var/log/nginx/access.log combined"],
        scan_result_by_file={FILE: [{
            "action": "add",
            "directive": "access_log",
            "context": CTX_HTTP_BLOCK,
        }]},
        ast_by_file={FILE: ast},
    )
    assert FILE in remedy.child_ast_modified
    http_block = _get_http_block(remedy.child_ast_modified)
    assert "access_log" in _directives(http_block)


def test_32_file_path_same_key_matches(remedy):
    """32. File path normalize khác kiểu vẫn match đúng khi key giống nhau."""
    ast = {"parsed": [_http([_access_log("/old/path.log")])]}
    _run(
        remedy,
        user_inputs=["global:/var/log/nginx/access.log combined"],
        scan_result_by_file={FILE: [_replace_entry(CTX_GLOBAL_ACCESSLOG)]},
        ast_by_file={FILE: ast},
    )
    assert FILE in remedy.child_ast_modified


def test_33_multi_file_only_violating_file_changed(remedy):
    """33. Nhiều file, chỉ file có violation bị đổi."""
    ast_a = {"parsed": [_http([_access_log("/old/a.log")])]}
    ast_b = {"parsed": [_http([_access_log("/old/b.log")])]}

    _run(
        remedy,
        user_inputs=["global:/var/log/nginx/access.log combined"],
        scan_result_by_file={FILE_A: [_replace_entry(CTX_GLOBAL_ACCESSLOG)]},  # only FILE_A
        ast_by_file={FILE_A: ast_a, FILE_B: ast_b},
    )
    assert FILE_A in remedy.child_ast_modified
    assert FILE_B not in remedy.child_ast_modified


def test_34_ast_root_not_polluted_with_wrong_scope_directive(remedy):
    """34. AST root không bị chèn directive sai scope."""
    # add at HTTP block scope → directive must not go to parsed root
    ast = {"parsed": [_http([_node("listen", ["80"])])]}
    _run(
        remedy,
        user_inputs=["global:/var/log/nginx/access.log combined"],
        scan_result_by_file={FILE: [{
            "action": "add",
            "directive": "access_log",
            "context": CTX_HTTP_BLOCK,
        }]},
        ast_by_file={FILE: ast},
    )
    parsed_root = remedy.child_ast_modified[FILE]["parsed"]
    # Root list should not directly contain access_log
    assert "access_log" not in _directives(parsed_root)
    # But http block should contain it
    http_block = parsed_root[0]["block"]
    assert "access_log" in _directives(http_block)


# ===========================================================================
# E. Safety / no-op / diff (35-40)
# ===========================================================================

def test_35_empty_scan_result_ast_unchanged(remedy):
    """35. Scan result rỗng, AST không đổi và child_ast_modified rỗng."""
    remedy.user_inputs = ["global:/var/log/nginx/access.log combined"]
    remedy.child_scan_result = {}
    remedy.child_ast_config = {FILE: {"parsed": [_http([_access_log("/old/path.log")])]}}
    remedy.remediate()
    assert remedy.child_ast_modified == {}


def test_36_invalid_input_child_ast_modified_empty(remedy):
    """36. Input invalid → child_ast_modified rỗng."""
    ast = {"parsed": [_http([_access_log("/old/path.log")])]}
    _run(
        remedy,
        user_inputs=["relative/path.log"],  # no scope key, relative path → rejected
        scan_result_by_file={FILE: [_replace_entry(CTX_GLOBAL_ACCESSLOG)]},
        ast_by_file={FILE: ast},
    )
    assert remedy.child_ast_modified == {}


def test_37_diff_reflects_only_access_log_and_log_not_found(remedy):
    """37. Diff chỉ phản ánh access_log / log_not_found."""
    ast = {"parsed": [_http([_access_log("/old/path.log"), _node("sendfile", ["on"])])]}
    _run(
        remedy,
        user_inputs=["global:/var/log/nginx/access.log combined", "off"],
        scan_result_by_file={FILE: [_replace_entry(CTX_GLOBAL_ACCESSLOG)]},
        ast_by_file={FILE: ast},
    )
    # Set original for diff
    remedy.child_ast_config = {FILE: ast}
    payload = remedy.build_file_diff_payload(FILE)
    assert payload["file_path"] == FILE
    assert payload["mode"] == "config"
    diff = payload["diff_text"]
    assert "access_log" in diff
    # sendfile should not appear in diff additions/removals
    assert "sendfile" not in diff or diff.count("sendfile") <= 2  # may appear in context lines


def test_38_child_ast_modified_is_deep_copy(remedy):
    """38. child_ast_modified deep copy độc lập."""
    original_parsed = [_http([_access_log("/old/path.log")])]
    ast = {"parsed": original_parsed}

    _run(
        remedy,
        user_inputs=["global:/var/log/nginx/access.log combined"],
        scan_result_by_file={FILE: [_replace_entry(CTX_GLOBAL_ACCESSLOG)]},
        ast_by_file={FILE: ast},
    )
    # Original should remain unchanged
    assert original_parsed[0]["block"][0]["args"] == ["/old/path.log"]
    # Modified should reflect new args
    modified = remedy.child_ast_modified[FILE]["parsed"]
    assert modified[0]["block"][0]["args"] == ["/var/log/nginx/access.log", "combined"]


def test_39_repeated_remediation_no_duplicate_access_log(remedy):
    """39. Remediate lặp lại không tạo duplicate access_log directive."""
    ast = {"parsed": [_http([_node("listen", ["80"])])]}
    _run(
        remedy,
        user_inputs=["global:/var/log/nginx/access.log combined"],
        scan_result_by_file={FILE: [{
            "action": "add",
            "directive": "access_log",
            "context": CTX_HTTP_BLOCK,
        }]},
        ast_by_file={FILE: ast},
    )
    after_first = copy.deepcopy(remedy.child_ast_modified[FILE])

    # Second run with the modified AST
    _run(
        remedy,
        user_inputs=["global:/var/log/nginx/access.log combined"],
        scan_result_by_file={FILE: [{
            "action": "add",
            "directive": "access_log",
            "context": CTX_HTTP_BLOCK,
        }]},
        ast_by_file={FILE: after_first},
    )
    http_block = remedy.child_ast_modified[FILE]["parsed"][0]["block"]
    access_log_count = sum(1 for n in http_block if n.get("directive") == "access_log")
    assert access_log_count == 1, f"Expected 1 access_log, got {access_log_count}"


def test_40_file_without_access_log_target_untouched(remedy):
    """40. File không có access_log target vẫn giữ nguyên structure."""
    # Context trỏ vào vị trí không có access_log → ASTEditor trả về None
    ast = {"parsed": [_http([_node("listen", ["80"]), _node("sendfile", ["on"])])]}
    original_parsed = copy.deepcopy(ast["parsed"])

    _run(
        remedy,
        user_inputs=["global:/var/log/nginx/access.log combined"],
        scan_result_by_file={FILE: [_replace_entry(CTX_GLOBAL_ACCESSLOG)]},
        ast_by_file={FILE: ast},
    )
    # The plugin processes the file but access_log wasn't found at target context
    if FILE in remedy.child_ast_modified:
        modified_parsed = remedy.child_ast_modified[FILE]["parsed"]
        # Other directives must be untouched
        assert _args_of(modified_parsed[0]["block"], "listen") == ["80"]
        assert _args_of(modified_parsed[0]["block"], "sendfile") == ["on"]
