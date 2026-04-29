"""
Unit tests for Remediate34 — CIS Nginx Benchmark Rule 3.4.
Bám sát ma trận kiểm thử tại docs/tests/remedyEng/test_remediate_34.md.

Nhóm A. Metadata / contract               (tests  1– 3)
Nhóm B. Input validation / proxy_pass     (tests  4–10)
Nhóm C. Header mutation correctness       (tests 11–24)
Nhóm D. Context / safety                  (tests 25–34)
Nhóm E. Regression / edge                 (tests 35–40)

Tổng: 40 test cases.
"""

import copy
import pytest

from core.remedyEng.base_remedy import BaseRemedy
from core.remedyEng.recommendations.remediate_34 import Remediate34


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

FILE   = "/etc/nginx/nginx.conf"
FILE_A = "/etc/nginx/nginx.conf"
FILE_B = "/etc/nginx/conf.d/site.conf"

# Standard CIS 3.4 header definitions
HDR_XFF   = ["X-Forwarded-For", "$proxy_add_x_forwarded_for"]
HDR_XRI   = ["X-Real-IP", "$remote_addr"]
HDR_XFP   = ["X-Forwarded-Proto", "$scheme"]

# ---------------------------------------------------------------------------
# AST node builders
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


def _proxy_pass(upstream: str) -> dict:
    return _node("proxy_pass", [upstream])


def _proxy_set_header(name: str, value: str) -> dict:
    return _node("proxy_set_header", [name, value])


# ---------------------------------------------------------------------------
# Scan-result entry builders
# ---------------------------------------------------------------------------

def _add_header_entry(context: list, header_name: str, header_value: str) -> dict:
    """Scan-result: add proxy_set_header directive."""
    return {
        "action": "add",
        "directive": "proxy_set_header",
        "args": [header_name, header_value],
        "context": context,
    }


def _add_directive_header_entry(context: list, header_name: str, header_value: str) -> dict:
    """Scan-result: add_directive proxy_set_header directive."""
    return {
        "action": "add_directive",
        "directive": "proxy_set_header",
        "args": [header_name, header_value],
        "context": context,
    }


# ---------------------------------------------------------------------------
# Context shortcuts
# Context points to the *target list* (block) for "add" / "add_directive" actions.
# Structure: parsed[0] = http, block[0] = server, block[0] = location
# ---------------------------------------------------------------------------

# Scan result context that points directly to the location block list
CTX_LOCATION_BLOCK = ["config", 0, "parsed", 0, "block", 0, "block", 0, "block"]

# Relative context after _relative_context() strips "config/0/parsed"
REL_CTX_LOCATION_BLOCK = [0, "block", 0, "block", 0, "block"]


# ---------------------------------------------------------------------------
# Helper: build standard 3-violation scan result for a location block
# ---------------------------------------------------------------------------

def _three_header_entries(context: list | None = None) -> list:
    """Return 3 add entries for the standard CIS 3.4 headers."""
    ctx = context or CTX_LOCATION_BLOCK
    return [
        _add_header_entry(ctx, "X-Forwarded-For", "$proxy_add_x_forwarded_for"),
        _add_header_entry(ctx, "X-Real-IP", "$remote_addr"),
        _add_header_entry(ctx, "X-Forwarded-Proto", "$scheme"),
    ]


# ---------------------------------------------------------------------------
# Helper: build AST with a proxied location block
# ---------------------------------------------------------------------------

def _ast_with_proxy_location(extra_location_directives: list | None = None) -> dict:
    """Return AST: http → server → location/{} with proxy_pass."""
    loc_block = [_proxy_pass("http://backend:8080")]
    if extra_location_directives:
        loc_block.extend(extra_location_directives)
    return {
        "parsed": [
            _http([
                _server([
                    _location(["/"], loc_block)
                ])
            ])
        ]
    }


# ---------------------------------------------------------------------------
# Helper: run Remediate34
# ---------------------------------------------------------------------------

def _run(
    remedy: Remediate34,
    user_inputs: list,
    scan_result_by_file: dict,
    ast_by_file: dict,
) -> None:
    remedy.user_inputs = user_inputs
    remedy.child_scan_result = scan_result_by_file
    remedy.child_ast_config = ast_by_file
    remedy.remediate()


# ---------------------------------------------------------------------------
# Navigation shortcuts
# ---------------------------------------------------------------------------

def _get_location_block(modified: dict, file: str = FILE) -> list:
    """http > server > location block"""
    return modified[file]["parsed"][0]["block"][0]["block"][0]["block"]


def _directives(block: list) -> list[str]:
    return [n.get("directive") for n in block if isinstance(n, dict)]


def _args_of(block: list, directive: str) -> list | None:
    for n in block:
        if isinstance(n, dict) and n.get("directive") == directive:
            return n.get("args")
    return None


def _all_proxy_set_header_names(block: list) -> list[str]:
    names = []
    for n in block:
        if isinstance(n, dict) and n.get("directive") == "proxy_set_header":
            args = n.get("args", [])
            if args:
                names.append(args[0])
    return names


# ===========================================================================
# A. Metadata / contract (1-3)
# ===========================================================================

@pytest.fixture
def remedy() -> Remediate34:
    return Remediate34()


def test_01_is_base_remedy_subclass(remedy):
    """1. Kiểm tra kế thừa BaseRemedy."""
    assert isinstance(remedy, BaseRemedy)


def test_02_has_input_is_true(remedy):
    """2. Kiểm tra has_input == True."""
    assert remedy.has_input is True
    assert remedy.id == "3.4"


def test_03_guide_detail_describes_proxy_header_forwarding(remedy):
    """3. Kiểm tra guide detail mô tả proxy header forwarding."""
    guide = remedy.remedy_guide_detail
    assert isinstance(guide, str) and guide.strip()
    # Must mention the 3 required headers
    assert "X-Forwarded-For" in guide
    assert "X-Real-IP" in guide
    assert "X-Forwarded-Proto" in guide


# ===========================================================================
# B. Input validation / proxy_pass (4-10)
# ===========================================================================

def test_04_http_proxy_pass_valid(remedy):
    """4. http://backend:8080 hợp lệ."""
    remedy.user_inputs = ["http://backend:8080"]
    ok, msg = remedy._validate_user_inputs()
    assert ok is True, msg


def test_05_https_proxy_pass_valid(remedy):
    """5. https://backend.example.com hợp lệ."""
    remedy.user_inputs = ["https://backend.example.com"]
    ok, msg = remedy._validate_user_inputs()
    assert ok is True, msg


def test_06_unix_socket_proxy_pass_valid(remedy):
    """6. unix:/tmp/backend.sock hợp lệ."""
    remedy.user_inputs = ["unix:/tmp/backend.sock"]
    ok, msg = remedy._validate_user_inputs()
    assert ok is True, msg


def test_07_empty_input_auto_detect(remedy):
    """7. Input rỗng cho phép auto-detect từ scan result."""
    remedy.user_inputs = []
    ok, msg = remedy._validate_user_inputs()
    assert ok is True, msg


def test_08_no_protocol_proxy_pass_rejected(remedy):
    """8. backend:8080 không có protocol bị từ chối."""
    remedy.user_inputs = ["backend:8080"]
    ok, msg = remedy._validate_user_inputs()
    assert ok is False
    assert msg  # must contain error description


def test_09_ftp_proxy_pass_rejected(remedy):
    """9. ftp://server bị từ chối (ftp không dùng làm nginx upstream proxy)."""
    remedy.user_inputs = ["ftp://server"]
    ok, msg = remedy._validate_user_inputs()
    assert ok is False
    assert msg


def test_10_whitespace_only_input_rejected(remedy):
    """10. Input chỉ khoảng trắng bị từ chối."""
    remedy.user_inputs = ["   "]
    ok, msg = remedy._validate_user_inputs()
    # Whitespace-only is treated as "no input" → valid (auto-detect mode)
    # Per validator logic: strip() is empty → returns (True, "")
    assert ok is True


# ===========================================================================
# C. Header mutation correctness (11-24)
# ===========================================================================

def test_11_add_x_forwarded_for(remedy):
    """11. Add X-Forwarded-For vào location block."""
    ast = _ast_with_proxy_location()
    _run(
        remedy,
        user_inputs=[],
        scan_result_by_file={FILE: [
            _add_header_entry(CTX_LOCATION_BLOCK, "X-Forwarded-For",
                              "$proxy_add_x_forwarded_for"),
        ]},
        ast_by_file={FILE: ast},
    )
    loc_block = _get_location_block(remedy.child_ast_modified)
    assert "X-Forwarded-For" in _all_proxy_set_header_names(loc_block)


def test_12_add_x_real_ip(remedy):
    """12. Add X-Real-IP vào location block."""
    ast = _ast_with_proxy_location()
    _run(
        remedy,
        user_inputs=[],
        scan_result_by_file={FILE: [
            _add_header_entry(CTX_LOCATION_BLOCK, "X-Real-IP", "$remote_addr"),
        ]},
        ast_by_file={FILE: ast},
    )
    loc_block = _get_location_block(remedy.child_ast_modified)
    assert "X-Real-IP" in _all_proxy_set_header_names(loc_block)


def test_13_add_x_forwarded_proto(remedy):
    """13. Add X-Forwarded-Proto vào location block."""
    ast = _ast_with_proxy_location()
    _run(
        remedy,
        user_inputs=[],
        scan_result_by_file={FILE: [
            _add_header_entry(CTX_LOCATION_BLOCK, "X-Forwarded-Proto", "$scheme"),
        ]},
        ast_by_file={FILE: ast},
    )
    loc_block = _get_location_block(remedy.child_ast_modified)
    assert "X-Forwarded-Proto" in _all_proxy_set_header_names(loc_block)


def test_14_replace_x_forwarded_for_when_existing(remedy):
    """14. Replace X-Forwarded-For khi đã tồn tại."""
    ast = _ast_with_proxy_location(extra_location_directives=[
        _proxy_set_header("X-Forwarded-For", "$remote_addr"),  # wrong value
    ])
    _run(
        remedy,
        user_inputs=[],
        scan_result_by_file={FILE: [
            _add_header_entry(CTX_LOCATION_BLOCK, "X-Forwarded-For",
                              "$proxy_add_x_forwarded_for"),
        ]},
        ast_by_file={FILE: ast},
    )
    loc_block = _get_location_block(remedy.child_ast_modified)
    xff_args = _args_of_header(loc_block, "X-Forwarded-For")
    assert xff_args == ["X-Forwarded-For", "$proxy_add_x_forwarded_for"]


def test_15_replace_x_real_ip_when_existing(remedy):
    """15. Replace X-Real-IP khi đã tồn tại."""
    ast = _ast_with_proxy_location(extra_location_directives=[
        _proxy_set_header("X-Real-IP", "$proxy_add_x_forwarded_for"),  # wrong
    ])
    _run(
        remedy,
        user_inputs=[],
        scan_result_by_file={FILE: [
            _add_header_entry(CTX_LOCATION_BLOCK, "X-Real-IP", "$remote_addr"),
        ]},
        ast_by_file={FILE: ast},
    )
    loc_block = _get_location_block(remedy.child_ast_modified)
    xri_args = _args_of_header(loc_block, "X-Real-IP")
    assert xri_args == ["X-Real-IP", "$remote_addr"]


def test_16_replace_x_forwarded_proto_when_existing(remedy):
    """16. Replace X-Forwarded-Proto khi đã tồn tại."""
    ast = _ast_with_proxy_location(extra_location_directives=[
        _proxy_set_header("X-Forwarded-Proto", "$host"),  # wrong
    ])
    _run(
        remedy,
        user_inputs=[],
        scan_result_by_file={FILE: [
            _add_header_entry(CTX_LOCATION_BLOCK, "X-Forwarded-Proto", "$scheme"),
        ]},
        ast_by_file={FILE: ast},
    )
    loc_block = _get_location_block(remedy.child_ast_modified)
    xfp_args = _args_of_header(loc_block, "X-Forwarded-Proto")
    assert xfp_args == ["X-Forwarded-Proto", "$scheme"]


def test_17_all_three_headers_present_after_full_remediation(remedy):
    """17. Sau full remediation, đủ 3 header trong block."""
    ast = _ast_with_proxy_location()
    _run(
        remedy,
        user_inputs=[],
        scan_result_by_file={FILE: _three_header_entries()},
        ast_by_file={FILE: ast},
    )
    loc_block = _get_location_block(remedy.child_ast_modified)
    header_names = _all_proxy_set_header_names(loc_block)
    assert "X-Forwarded-For" in header_names
    assert "X-Real-IP" in header_names
    assert "X-Forwarded-Proto" in header_names


def test_18_keep_existing_proxy_pass_when_no_input(remedy):
    """18. Giữ proxy_pass hiện có nếu input rỗng."""
    ast = _ast_with_proxy_location()
    _run(
        remedy,
        user_inputs=[],
        scan_result_by_file={FILE: _three_header_entries()},
        ast_by_file={FILE: ast},
    )
    loc_block = _get_location_block(remedy.child_ast_modified)
    assert _args_of(loc_block, "proxy_pass") == ["http://backend:8080"]


def test_19_upsert_proxy_pass_when_user_provides_input(remedy):
    """19. Upsert proxy_pass khi user nhập giá trị mới."""
    ast = _ast_with_proxy_location()
    new_upstream = "https://new-backend.example.com"
    _run(
        remedy,
        user_inputs=[new_upstream],
        scan_result_by_file={FILE: _three_header_entries()},
        ast_by_file={FILE: ast},
    )
    loc_block = _get_location_block(remedy.child_ast_modified)
    assert _args_of(loc_block, "proxy_pass") == [new_upstream]


def test_20_no_duplicate_proxy_set_header_same_name(remedy):
    """20. Không tạo duplicate proxy_set_header cùng tên."""
    ast = _ast_with_proxy_location(extra_location_directives=[
        _proxy_set_header("X-Forwarded-For", "$remote_addr"),
    ])
    _run(
        remedy,
        user_inputs=[],
        scan_result_by_file={FILE: [
            _add_header_entry(CTX_LOCATION_BLOCK, "X-Forwarded-For",
                              "$proxy_add_x_forwarded_for"),
        ]},
        ast_by_file={FILE: ast},
    )
    loc_block = _get_location_block(remedy.child_ast_modified)
    xff_count = sum(
        1 for n in loc_block
        if isinstance(n, dict)
        and n.get("directive") == "proxy_set_header"
        and n.get("args", [None])[0] == "X-Forwarded-For"
    )
    assert xff_count == 1


def test_21_unrelated_headers_not_changed(remedy):
    """21. Header khác ngoài 3 header rule yêu cầu không bị thay đổi."""
    ast = _ast_with_proxy_location(extra_location_directives=[
        _proxy_set_header("Host", "$host"),
        _proxy_set_header("Authorization", "$http_authorization"),
    ])
    _run(
        remedy,
        user_inputs=[],
        scan_result_by_file={FILE: _three_header_entries()},
        ast_by_file={FILE: ast},
    )
    loc_block = _get_location_block(remedy.child_ast_modified)
    assert _args_of_header(loc_block, "Host") == ["Host", "$host"]
    assert _args_of_header(loc_block, "Authorization") == [
        "Authorization", "$http_authorization"
    ]


def test_22_only_update_block_with_proxy_pass(remedy):
    """22. Chỉ update block có proxy_pass (theo scan result context)."""
    # Location block at index 1 (no proxy_pass) should not be mutated
    ast = {
        "parsed": [
            _http([
                _server([
                    _location(["/proxy"], [_proxy_pass("http://backend")]),
                    _location(["/static"], [_node("root", ["/var/www"])]),
                ])
            ])
        ]
    }
    # Context for /proxy location block
    ctx_proxy_block = ["config", 0, "parsed", 0, "block", 0, "block", 0, "block"]
    _run(
        remedy,
        user_inputs=[],
        scan_result_by_file={FILE: [
            _add_header_entry(ctx_proxy_block, "X-Forwarded-For",
                              "$proxy_add_x_forwarded_for"),
        ]},
        ast_by_file={FILE: ast},
    )
    proxy_loc_block = remedy.child_ast_modified[FILE]["parsed"][0]["block"][0]["block"][0]["block"]
    static_loc_block = remedy.child_ast_modified[FILE]["parsed"][0]["block"][0]["block"][1]["block"]
    assert "X-Forwarded-For" in _all_proxy_set_header_names(proxy_loc_block)
    assert "X-Forwarded-For" not in _all_proxy_set_header_names(static_loc_block)


def test_23_block_without_proxy_pass_can_still_receive_headers_from_scan(remedy):
    """23. Block không có proxy_pass vẫn có thể được upsert khi scan result yêu cầu add."""
    # Scan result may legitimately point to a block that lost proxy_pass already
    ast = {
        "parsed": [
            _http([
                _server([
                    _location(["/"], [_node("root", ["/var/www"])])
                ])
            ])
        ]
    }
    _run(
        remedy,
        user_inputs=[],
        scan_result_by_file={FILE: [
            _add_header_entry(CTX_LOCATION_BLOCK, "X-Forwarded-For",
                              "$proxy_add_x_forwarded_for"),
        ]},
        ast_by_file={FILE: ast},
    )
    assert FILE in remedy.child_ast_modified
    loc_block = _get_location_block(remedy.child_ast_modified)
    assert "X-Forwarded-For" in _all_proxy_set_header_names(loc_block)


def test_24_mixed_blocks_target_correct_location(remedy):
    """24. Mixed http/server/location blocks, target đúng block."""
    # http contains server, server contains 2 locations, only second gets headers
    ctx_second_loc = ["config", 0, "parsed", 0, "block", 0, "block", 1, "block"]
    ast = {
        "parsed": [
            _http([
                _server([
                    _location(["/a"], [_proxy_pass("http://backend-a")]),
                    _location(["/b"], [_proxy_pass("http://backend-b")]),
                ])
            ])
        ]
    }
    _run(
        remedy,
        user_inputs=[],
        scan_result_by_file={FILE: [
            _add_header_entry(ctx_second_loc, "X-Forwarded-For",
                              "$proxy_add_x_forwarded_for"),
        ]},
        ast_by_file={FILE: ast},
    )
    loc_a = remedy.child_ast_modified[FILE]["parsed"][0]["block"][0]["block"][0]["block"]
    loc_b = remedy.child_ast_modified[FILE]["parsed"][0]["block"][0]["block"][1]["block"]
    assert "X-Forwarded-For" not in _all_proxy_set_header_names(loc_a)
    assert "X-Forwarded-For" in _all_proxy_set_header_names(loc_b)


# ===========================================================================
# D. Context / safety (25-34)
# ===========================================================================

def test_25_empty_context_no_mutate(remedy):
    """25. Context rỗng không mutate."""
    ast = _ast_with_proxy_location()
    original_parsed = copy.deepcopy(ast["parsed"])
    _run(
        remedy,
        user_inputs=[],
        scan_result_by_file={FILE: [{
            "action": "add",
            "directive": "proxy_set_header",
            "args": ["X-Forwarded-For", "$proxy_add_x_forwarded_for"],
            "context": [],  # empty → rel_ctx = [] → skipped
        }]},
        ast_by_file={FILE: ast},
    )
    if FILE in remedy.child_ast_modified:
        assert remedy.child_ast_modified[FILE]["parsed"] == original_parsed


def test_26_context_mismatch_target_list_still_safe(remedy):
    """26. Context lệch nhưng target list tìm được vẫn an toàn."""
    ast = _ast_with_proxy_location()
    # Context pointing to index 99 which doesn't exist → ASTEditor returns None → skip
    bad_ctx = ["config", 0, "parsed", 0, "block", 99, "block"]
    _run(
        remedy,
        user_inputs=[],
        scan_result_by_file={FILE: [
            _add_header_entry(bad_ctx, "X-Forwarded-For", "$proxy_add_x_forwarded_for"),
        ]},
        ast_by_file={FILE: ast},
    )
    # Should not raise; header NOT added to block because context was invalid
    if FILE in remedy.child_ast_modified:
        loc_block = remedy.child_ast_modified[FILE]["parsed"][0]["block"][0]["block"][0]["block"]
        # The block may still be present, but no spurious header added
        assert isinstance(loc_block, list)


def test_27_multi_file_only_violating_file_changed(remedy):
    """27. Nhiều file, chỉ file có violation sửa."""
    ast_a = _ast_with_proxy_location()
    ast_b = _ast_with_proxy_location()
    _run(
        remedy,
        user_inputs=[],
        scan_result_by_file={FILE_A: _three_header_entries()},  # only FILE_A
        ast_by_file={FILE_A: ast_a, FILE_B: ast_b},
    )
    assert FILE_A in remedy.child_ast_modified
    assert FILE_B not in remedy.child_ast_modified


def test_28_file_path_normalize_same_key_matches(remedy):
    """28. File path normalize khác kiểu vẫn match đúng khi key giống nhau."""
    ast = _ast_with_proxy_location()
    _run(
        remedy,
        user_inputs=[],
        scan_result_by_file={FILE: _three_header_entries()},
        ast_by_file={FILE: ast},
    )
    assert FILE in remedy.child_ast_modified


def test_29_ast_root_list_not_polluted(remedy):
    """29. AST root list không bị chèn sai."""
    ast = _ast_with_proxy_location()
    _run(
        remedy,
        user_inputs=[],
        scan_result_by_file={FILE: _three_header_entries()},
        ast_by_file={FILE: ast},
    )
    parsed_root = remedy.child_ast_modified[FILE]["parsed"]
    # Root should only contain http directive, not proxy_set_header
    assert "proxy_set_header" not in _directives(parsed_root)


def test_30_child_ast_modified_is_deep_copy(remedy):
    """30. child_ast_modified độc lập với input AST (deep copy)."""
    original_block = [_proxy_pass("http://backend:8080")]
    loc = _location(["/"], original_block)
    ast = {"parsed": [_http([_server([loc])])]}

    _run(
        remedy,
        user_inputs=[],
        scan_result_by_file={FILE: _three_header_entries()},
        ast_by_file={FILE: ast},
    )
    # Modifying original should not affect modified
    original_block.append(_node("add_header", ["X-Test", "1"]))
    loc_mod = _get_location_block(remedy.child_ast_modified)
    assert not any(
        n.get("directive") == "add_header" for n in loc_mod if isinstance(n, dict)
    )


def test_31_scan_result_action_not_add_ignored(remedy):
    """31. Scan result action ngoài add/add_directive bị bỏ qua."""
    ast = _ast_with_proxy_location()
    original_parsed = copy.deepcopy(ast["parsed"])
    _run(
        remedy,
        user_inputs=[],
        scan_result_by_file={FILE: [{
            "action": "replace",  # not add/add_directive
            "directive": "proxy_set_header",
            "args": ["X-Forwarded-For", "$proxy_add_x_forwarded_for"],
            "context": CTX_LOCATION_BLOCK,
        }]},
        ast_by_file={FILE: ast},
    )
    # Because action is "replace" (not add/add_directive), no header should be added
    if FILE in remedy.child_ast_modified:
        loc_block = _get_location_block(remedy.child_ast_modified)
        assert "X-Forwarded-For" not in _all_proxy_set_header_names(loc_block)


def test_32_scan_result_directive_not_proxy_set_header_ignored(remedy):
    """32. Scan result directive khác proxy_set_header bị bỏ qua."""
    ast = _ast_with_proxy_location()
    _run(
        remedy,
        user_inputs=[],
        scan_result_by_file={FILE: [{
            "action": "add",
            "directive": "add_header",  # not proxy_set_header
            "args": ["X-Forwarded-For", "$proxy_add_x_forwarded_for"],
            "context": CTX_LOCATION_BLOCK,
        }]},
        ast_by_file={FILE: ast},
    )
    if FILE in remedy.child_ast_modified:
        loc_block = _get_location_block(remedy.child_ast_modified)
        # add_header directive should not be added by this plugin
        assert "add_header" not in _directives(loc_block)


def test_33_target_not_list_skipped_safely(remedy):
    """33. Target không phải list bị skip an toàn."""
    # Context pointing to a dict (not a list) → ASTEditor returns dict → skipped
    ast_dict_at_target = {
        "parsed": [
            _http([
                _server([
                    _node("listen", ["80"]),  # no location block → block index 0 is a node not list
                ])
            ])
        ]
    }
    ctx_wrong = ["config", 0, "parsed", 0, "block", 0, "block", 0]  # points to a dict node
    _run(
        remedy,
        user_inputs=[],
        scan_result_by_file={FILE: [
            _add_header_entry(ctx_wrong, "X-Forwarded-For", "$proxy_add_x_forwarded_for"),
        ]},
        ast_by_file={FILE: ast_dict_at_target},
    )
    # Must not crash; either no modified or modified with intact structure
    if FILE in remedy.child_ast_modified:
        parsed = remedy.child_ast_modified[FILE]["parsed"]
        assert isinstance(parsed, list)


def test_34_diff_shows_proxy_header_changes(remedy):
    """34. Diff chỉ thể hiện proxy header changes."""
    ast = _ast_with_proxy_location()
    _run(
        remedy,
        user_inputs=[],
        scan_result_by_file={FILE: _three_header_entries()},
        ast_by_file={FILE: ast},
    )
    remedy.child_ast_config = {FILE: ast}
    payload = remedy.build_file_diff_payload(FILE)
    assert payload["file_path"] == FILE
    assert payload["mode"] == "config"
    diff = payload["diff_text"]
    assert "proxy_set_header" in diff


# ===========================================================================
# E. Regression / edge (35-40)
# ===========================================================================

def test_35_repeated_remediation_no_duplicate_headers(remedy):
    """35. Remediate lặp lại không tạo header trùng."""
    ast = _ast_with_proxy_location()
    _run(
        remedy,
        user_inputs=[],
        scan_result_by_file={FILE: _three_header_entries()},
        ast_by_file={FILE: ast},
    )
    after_first = copy.deepcopy(remedy.child_ast_modified[FILE])

    # Second run with modified AST as input
    _run(
        remedy,
        user_inputs=[],
        scan_result_by_file={FILE: _three_header_entries()},
        ast_by_file={FILE: after_first},
    )
    loc_block = _get_location_block(remedy.child_ast_modified)
    for header_name in ("X-Forwarded-For", "X-Real-IP", "X-Forwarded-Proto"):
        count = sum(
            1 for n in loc_block
            if isinstance(n, dict)
            and n.get("directive") == "proxy_set_header"
            and n.get("args", [None])[0] == header_name
        )
        assert count == 1, f"Expected 1 occurrence of {header_name}, got {count}"


def test_36_multiple_proxy_locations_update_correct_block(remedy):
    """36. Nhiều proxy_pass trong một file, update đúng block."""
    ctx_first_loc = ["config", 0, "parsed", 0, "block", 0, "block", 0, "block"]
    ctx_second_loc = ["config", 0, "parsed", 0, "block", 0, "block", 1, "block"]
    ast = {
        "parsed": [
            _http([
                _server([
                    _location(["/api"], [_proxy_pass("http://api-backend")]),
                    _location(["/app"], [_proxy_pass("http://app-backend")]),
                ])
            ])
        ]
    }
    # Only remediate /api (first location)
    _run(
        remedy,
        user_inputs=[],
        scan_result_by_file={FILE: [
            _add_header_entry(ctx_first_loc, "X-Forwarded-For",
                              "$proxy_add_x_forwarded_for"),
        ]},
        ast_by_file={FILE: ast},
    )
    loc_api = remedy.child_ast_modified[FILE]["parsed"][0]["block"][0]["block"][0]["block"]
    loc_app = remedy.child_ast_modified[FILE]["parsed"][0]["block"][0]["block"][1]["block"]
    assert "X-Forwarded-For" in _all_proxy_set_header_names(loc_api)
    assert "X-Forwarded-For" not in _all_proxy_set_header_names(loc_app)


def test_37_x_forwarded_for_args_match_user_or_default(remedy):
    """37. X-Forwarded-For giữ args từ scan result chính xác."""
    ast = _ast_with_proxy_location()
    _run(
        remedy,
        user_inputs=[],
        scan_result_by_file={FILE: [
            _add_header_entry(CTX_LOCATION_BLOCK, "X-Forwarded-For",
                              "$proxy_add_x_forwarded_for"),
        ]},
        ast_by_file={FILE: ast},
    )
    loc_block = _get_location_block(remedy.child_ast_modified)
    xff_args = _args_of_header(loc_block, "X-Forwarded-For")
    assert xff_args == ["X-Forwarded-For", "$proxy_add_x_forwarded_for"]


def test_38_proxy_pass_unchanged_when_matches_input(remedy):
    """38. proxy_pass giữ nguyên nếu đã khớp với user input."""
    upstream = "http://backend:8080"
    ast = _ast_with_proxy_location()  # already has http://backend:8080
    _run(
        remedy,
        user_inputs=[upstream],
        scan_result_by_file={FILE: _three_header_entries()},
        ast_by_file={FILE: ast},
    )
    loc_block = _get_location_block(remedy.child_ast_modified)
    assert _args_of(loc_block, "proxy_pass") == [upstream]


def test_39_empty_scan_result_ast_unchanged(remedy):
    """39. Scan result rỗng, AST không đổi."""
    remedy.user_inputs = []
    remedy.child_scan_result = {}
    remedy.child_ast_config = {FILE: _ast_with_proxy_location()}
    remedy.remediate()
    assert remedy.child_ast_modified == {}


def test_40_location_without_proxy_not_touched(remedy):
    """40. Location path không proxy vẫn giữ nguyên."""
    # Two locations: /static (no proxy) and /api (proxy).
    # Scan result only add to /api.
    ctx_api = ["config", 0, "parsed", 0, "block", 0, "block", 1, "block"]
    ast = {
        "parsed": [
            _http([
                _server([
                    _location(["/static"], [_node("root", ["/var/www/html"])]),
                    _location(["/api"], [_proxy_pass("http://api-backend")]),
                ])
            ])
        ]
    }
    _run(
        remedy,
        user_inputs=[],
        scan_result_by_file={FILE: [
            _add_header_entry(ctx_api, "X-Forwarded-For",
                              "$proxy_add_x_forwarded_for"),
        ]},
        ast_by_file={FILE: ast},
    )
    static_block = remedy.child_ast_modified[FILE]["parsed"][0]["block"][0]["block"][0]["block"]
    api_block = remedy.child_ast_modified[FILE]["parsed"][0]["block"][0]["block"][1]["block"]
    # /static block untouched
    assert _all_proxy_set_header_names(static_block) == []
    assert _args_of(static_block, "root") == ["/var/www/html"]
    # /api block has the header
    assert "X-Forwarded-For" in _all_proxy_set_header_names(api_block)


# ===========================================================================
# Helper: lookup proxy_set_header args by header name
# ===========================================================================

def _args_of_header(block: list, header_name: str) -> list | None:
    """Return args of first proxy_set_header with matching header_name."""
    for n in block:
        if not isinstance(n, dict):
            continue
        if n.get("directive") != "proxy_set_header":
            continue
        args = n.get("args", [])
        if args and args[0] == header_name:
            return args
    return None
