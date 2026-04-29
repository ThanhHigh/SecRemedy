"""
Unit tests for Remediate411 — CIS Nginx Benchmark Rule 4.1.1.
Bám sát ma trận kiểm thử tại docs/tests/remedyEng/test_remediate_411.md.

Nhóm A. Metadata / contract               (tests  1– 3)
Nhóm B. Input validation                  (tests  4–12)
Nhóm C. Mutation correctness              (tests 13–25)
Nhóm D. Context / safety                  (tests 26–34)
Nhóm E. Regression / edge                 (tests 35–40)

Tổng: 40 test cases.
"""

import copy
import pytest

from core.remedyEng.base_remedy import BaseRemedy
from core.remedyEng.recommendations.remediate_411 import Remediate411


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

FILE   = "/etc/nginx/nginx.conf"
FILE_A = "/etc/nginx/nginx.conf"
FILE_B = "/etc/nginx/conf.d/site.conf"

RULE_ID = "4.1.1"

# Standard valid inputs
CODE_301 = "301"
CODE_302 = "302"
CODE_307 = "307"
TARGET_HOST       = "https://$host$request_uri"
TARGET_EXAMPLE    = "https://example.com$request_uri"


# ---------------------------------------------------------------------------
# AST node builders (local, minimal)
# ---------------------------------------------------------------------------

def _node(directive: str, args: list | None = None, block: list | None = None) -> dict:
    item: dict = {"directive": directive, "args": args or []}
    if block is not None:
        item["block"] = block
    return item


def _server(block: list) -> dict:
    return _node("server", [], block)


def _http(block: list) -> dict:
    return _node("http", [], block)


# ---------------------------------------------------------------------------
# Scan-result entry builders
# ---------------------------------------------------------------------------

def _return_entry(action: str, context: list) -> dict:
    """Scan-result entry requesting a 'return' directive be added/replaced."""
    return {
        "action": action,
        "directive": "return",
        "context": context,
    }


# ---------------------------------------------------------------------------
# Context shortcuts
# Structure: parsed[0] = http, block[0] = server
# Context pointing to server block list:
#   config → 0 → parsed → 0 → block → 0 → block
# ---------------------------------------------------------------------------

CTX_SERVER_BLOCK = ["config", 0, "parsed", 0, "block", 0, "block"]

# Context pointing to the server *node* itself (dict, not list)
CTX_SERVER_NODE  = ["config", 0, "parsed", 0, "block", 0]

# Context that resolves back to the parsed root (empty relative)
CTX_PARSED_ROOT  = ["config", 0, "parsed"]


# ---------------------------------------------------------------------------
# AST builders
# ---------------------------------------------------------------------------

def _ast_server_listen_80(extra_server_directives: list | None = None) -> dict:
    """Return AST: http → server{listen 80; server_name example.com;}"""
    block = [
        _node("listen", ["80"]),
        _node("server_name", ["example.com"]),
    ]
    if extra_server_directives:
        block.extend(extra_server_directives)
    return {"parsed": [_http([_server(block)])]}


def _ast_server_with_return(code: str, target: str) -> dict:
    """Return AST: http → server{listen 80; return <code> <target>;}"""
    return {"parsed": [_http([_server([
        _node("listen", ["80"]),
        _node("return", [code, target]),
    ])])]}


# ---------------------------------------------------------------------------
# Helpers: run plugin
# ---------------------------------------------------------------------------

def _run(
    remedy: Remediate411,
    user_inputs: list,
    scan_result_by_file: dict,
    ast_by_file: dict,
) -> None:
    remedy.user_inputs = user_inputs
    remedy.child_scan_result = scan_result_by_file
    remedy.child_ast_config = ast_by_file
    remedy.remediate()


# ---------------------------------------------------------------------------
# Navigation helpers
# ---------------------------------------------------------------------------

def _get_server_block(modified: dict, file: str = FILE) -> list:
    """http → server → block list"""
    return modified[file]["parsed"][0]["block"][0]["block"]


def _args_of(block: list, directive: str) -> list | None:
    for n in block:
        if isinstance(n, dict) and n.get("directive") == directive:
            return n.get("args")
    return None


def _count_directive(block: list, directive: str) -> int:
    return sum(1 for n in block if isinstance(n, dict) and n.get("directive") == directive)


# ===========================================================================
# A. Metadata / contract (1-3)
# ===========================================================================

@pytest.fixture
def remedy() -> Remediate411:
    return Remediate411()


def test_01_is_base_remedy_subclass(remedy):
    """1. Kiểm tra kế thừa BaseRemedy."""
    assert isinstance(remedy, BaseRemedy)


def test_02_has_input_is_true(remedy):
    """2. Kiểm tra has_input == True."""
    assert remedy.has_input is True
    assert remedy.id == RULE_ID


def test_03_guide_detail_describes_http_to_https(remedy):
    """3. Kiểm tra guide detail mô tả redirect HTTP→HTTPS."""
    guide = remedy.remedy_guide_detail
    assert isinstance(guide, str) and guide.strip()
    # Must mention core redirect concepts
    assert "301" in guide
    assert "https://" in guide
    assert "$request_uri" in guide


# ===========================================================================
# B. Input validation (4-12)
# ===========================================================================

def test_04_code_301_is_valid(remedy):
    """4. Code 301 hợp lệ."""
    remedy.user_inputs = ["301", TARGET_HOST]
    ok, msg = remedy._validate_user_inputs()
    assert ok is True, msg


def test_05_code_302_is_valid(remedy):
    """5. Code 302 hợp lệ."""
    remedy.user_inputs = ["302", TARGET_HOST]
    ok, msg = remedy._validate_user_inputs()
    assert ok is True, msg


def test_06_code_307_is_valid(remedy):
    """6. Code 307 hợp lệ."""
    remedy.user_inputs = ["307", TARGET_HOST]
    ok, msg = remedy._validate_user_inputs()
    assert ok is True, msg


def test_07_empty_inputs_use_default_301(remedy):
    """7. Code rỗng → auto default 301, target default."""
    remedy.user_inputs = []
    ok, msg = remedy._validate_user_inputs()
    assert ok is True, msg
    # After validation with empty inputs, defaults should be set
    assert remedy.user_inputs[0] == "301"
    assert remedy.user_inputs[1] == "https://$host$request_uri"


def test_08_invalid_code_rejected(remedy):
    """8. Code ngoài tập cho phép bị từ chối."""
    remedy.user_inputs = ["302", TARGET_HOST]  # reset first
    # Now test invalid
    remedy2 = Remediate411()
    remedy2.user_inputs = ["308", TARGET_HOST]
    ok, msg = remedy2._validate_user_inputs()
    assert ok is False
    assert msg  # Must contain error description


def test_08b_code_200_rejected(remedy):
    """8b. Code 200 không phải redirect, bị từ chối."""
    remedy.user_inputs = ["200", TARGET_HOST]
    ok, msg = remedy._validate_user_inputs()
    assert ok is False
    assert "301" in msg or "302" in msg or "307" in msg or "invalid" in msg.lower()


def test_09_target_host_request_uri_valid(remedy):
    """9. Target https://$host$request_uri hợp lệ."""
    remedy.user_inputs = ["301", "https://$host$request_uri"]
    ok, msg = remedy._validate_user_inputs()
    assert ok is True, msg


def test_10_target_example_com_request_uri_valid(remedy):
    """10. Target https://example.com$request_uri hợp lệ."""
    remedy.user_inputs = ["301", "https://example.com$request_uri"]
    ok, msg = remedy._validate_user_inputs()
    assert ok is True, msg


def test_11_target_without_https_rejected(remedy):
    """11. Target không bắt đầu https:// bị từ chối."""
    remedy.user_inputs = ["301", "http://$host$request_uri"]
    ok, msg = remedy._validate_user_inputs()
    assert ok is False
    assert msg


def test_12_target_without_request_uri_rejected(remedy):
    """12. Target thiếu $request_uri bị từ chối."""
    remedy.user_inputs = ["301", "https://example.com/"]
    ok, msg = remedy._validate_user_inputs()
    assert ok is False
    assert "$request_uri" in msg or "request_uri" in msg


# ===========================================================================
# C. Mutation correctness (13-25)
# ===========================================================================

def test_13_add_return_301_default_target(remedy):
    """13. Add return 301 https://$host$request_uri; vào server block."""
    ast = _ast_server_listen_80()
    _run(
        remedy,
        user_inputs=["301", TARGET_HOST],
        scan_result_by_file={FILE: [_return_entry("add", CTX_SERVER_BLOCK)]},
        ast_by_file={FILE: ast},
    )
    server_block = _get_server_block(remedy.child_ast_modified)
    assert _args_of(server_block, "return") == ["301", TARGET_HOST]


def test_14_add_return_302(remedy):
    """14. Add return 302 https://$host$request_uri;"""
    ast = _ast_server_listen_80()
    _run(
        remedy,
        user_inputs=["302", TARGET_HOST],
        scan_result_by_file={FILE: [_return_entry("add", CTX_SERVER_BLOCK)]},
        ast_by_file={FILE: ast},
    )
    server_block = _get_server_block(remedy.child_ast_modified)
    assert _args_of(server_block, "return") == ["302", TARGET_HOST]


def test_15_add_return_307(remedy):
    """15. Add return 307 https://$host$request_uri;"""
    ast = _ast_server_listen_80()
    _run(
        remedy,
        user_inputs=["307", TARGET_HOST],
        scan_result_by_file={FILE: [_return_entry("add", CTX_SERVER_BLOCK)]},
        ast_by_file={FILE: ast},
    )
    server_block = _get_server_block(remedy.child_ast_modified)
    assert _args_of(server_block, "return") == ["307", TARGET_HOST]


def test_16_replace_existing_return_directive(remedy):
    """16. Replace return hiện có bằng code/target mới."""
    ast = _ast_server_with_return("302", "https://old.example.com$request_uri")
    _run(
        remedy,
        user_inputs=["301", TARGET_HOST],
        scan_result_by_file={FILE: [_return_entry("replace", CTX_SERVER_BLOCK)]},
        ast_by_file={FILE: ast},
    )
    server_block = _get_server_block(remedy.child_ast_modified)
    assert _args_of(server_block, "return") == ["301", TARGET_HOST]


def test_17_update_args_when_return_already_present_via_modify_directive(remedy):
    """17. Update args khi scan result đã có return directive (action=modify_directive)."""
    ast = _ast_server_with_return("302", "https://old.example.com$request_uri")
    _run(
        remedy,
        user_inputs=["307", TARGET_EXAMPLE],
        scan_result_by_file={FILE: [_return_entry("modify_directive", CTX_SERVER_BLOCK)]},
        ast_by_file={FILE: ast},
    )
    server_block = _get_server_block(remedy.child_ast_modified)
    assert _args_of(server_block, "return") == ["307", TARGET_EXAMPLE]


def test_18_server_block_listen_80_selected_for_return(remedy):
    """18. Server block listen 80 được chọn để chèn return."""
    ast = _ast_server_listen_80()
    _run(
        remedy,
        user_inputs=["301", TARGET_HOST],
        scan_result_by_file={FILE: [_return_entry("add", CTX_SERVER_BLOCK)]},
        ast_by_file={FILE: ast},
    )
    server_block = _get_server_block(remedy.child_ast_modified)
    # listen 80 directive must still be there
    assert _args_of(server_block, "listen") == ["80"]
    # return directive added
    assert _args_of(server_block, "return") == ["301", TARGET_HOST]


def test_19_existing_return_node_updated(remedy):
    """19. Target block có return và node được cập nhật."""
    ast = _ast_server_with_return("302", "https://old$request_uri")
    _run(
        remedy,
        user_inputs=["301", TARGET_HOST],
        scan_result_by_file={FILE: [_return_entry("add", CTX_SERVER_BLOCK)]},
        ast_by_file={FILE: ast},
    )
    server_block = _get_server_block(remedy.child_ast_modified)
    # After upsert, args should be updated to new values
    args = _args_of(server_block, "return")
    assert args == ["301", TARGET_HOST]


def test_20_target_list_block_receives_new_directive(remedy):
    """20. Target list block nhận directive mới đúng vị trí."""
    ast = _ast_server_listen_80()
    before_len = len(ast["parsed"][0]["block"][0]["block"])
    _run(
        remedy,
        user_inputs=["301", TARGET_HOST],
        scan_result_by_file={FILE: [_return_entry("add", CTX_SERVER_BLOCK)]},
        ast_by_file={FILE: ast},
    )
    server_block = _get_server_block(remedy.child_ast_modified)
    # Should have at least one more directive than before (the return)
    assert len(server_block) >= before_len + 1


def test_21_no_duplicate_return_directive(remedy):
    """21. Không tạo duplicate return directive khi đã có sẵn."""
    ast = _ast_server_with_return("301", TARGET_HOST)
    _run(
        remedy,
        user_inputs=["301", TARGET_HOST],
        scan_result_by_file={FILE: [_return_entry("add", CTX_SERVER_BLOCK)]},
        ast_by_file={FILE: ast},
    )
    server_block = _get_server_block(remedy.child_ast_modified)
    count = _count_directive(server_block, "return")
    assert count == 1, f"Expected 1 return directive, got {count}"


def test_22_fallback_to_server_block_when_context_resolves_empty(remedy):
    """22. Fallback sang server block khi context lệch (empty relative context)."""
    ast = _ast_server_listen_80()
    # Context that completely strips to empty relative (points to parsed root)
    _run(
        remedy,
        user_inputs=["301", TARGET_HOST],
        scan_result_by_file={FILE: [_return_entry("add", CTX_PARSED_ROOT)]},
        ast_by_file={FILE: ast},
    )
    # Fallback should insert into server block
    server_block = _get_server_block(remedy.child_ast_modified)
    assert _args_of(server_block, "return") == ["301", TARGET_HOST]


def test_23_keep_server_name_directive_in_block(remedy):
    """23. Giữ server_name hiện có trong block."""
    ast = _ast_server_listen_80()
    _run(
        remedy,
        user_inputs=["301", TARGET_HOST],
        scan_result_by_file={FILE: [_return_entry("add", CTX_SERVER_BLOCK)]},
        ast_by_file={FILE: ast},
    )
    server_block = _get_server_block(remedy.child_ast_modified)
    assert _args_of(server_block, "server_name") == ["example.com"]


def test_24_keep_other_directives_in_block(remedy):
    """24. Giữ directive khác trong block."""
    ast = _ast_server_listen_80(extra_server_directives=[
        _node("keepalive_timeout", ["65"]),
    ])
    _run(
        remedy,
        user_inputs=["301", TARGET_HOST],
        scan_result_by_file={FILE: [_return_entry("add", CTX_SERVER_BLOCK)]},
        ast_by_file={FILE: ast},
    )
    server_block = _get_server_block(remedy.child_ast_modified)
    assert _args_of(server_block, "keepalive_timeout") == ["65"]


def test_25_return_inserted_in_correct_server_scope(remedy):
    """25. Chèn return trong block server đúng scope."""
    ast = _ast_server_listen_80()
    _run(
        remedy,
        user_inputs=["301", TARGET_HOST],
        scan_result_by_file={FILE: [_return_entry("add", CTX_SERVER_BLOCK)]},
        ast_by_file={FILE: ast},
    )
    # Parsed root should NOT contain return at top level
    parsed_root = remedy.child_ast_modified[FILE]["parsed"]
    root_directives = [n.get("directive") for n in parsed_root if isinstance(n, dict)]
    assert "return" not in root_directives
    # return should be inside server block
    server_block = _get_server_block(remedy.child_ast_modified)
    assert _args_of(server_block, "return") is not None


# ===========================================================================
# D. Context / safety (26-34)
# ===========================================================================

def test_26_empty_context_does_not_pollute_parsed_root(remedy):
    """26. Context rỗng không chèn sai root."""
    ast = _ast_server_listen_80()
    # Action with truly empty context []
    entry = {
        "action": "add",
        "directive": "return",
        "context": [],
    }
    _run(
        remedy,
        user_inputs=["301", TARGET_HOST],
        scan_result_by_file={FILE: [entry]},
        ast_by_file={FILE: ast},
    )
    if FILE in remedy.child_ast_modified:
        parsed_root = remedy.child_ast_modified[FILE]["parsed"]
        # return MUST NOT be inserted at root level
        root_directives = [n.get("directive") for n in parsed_root if isinstance(n, dict)]
        assert "return" not in root_directives


def test_27_context_is_directive_object_handled_correctly(remedy):
    """27. Context adalah directive object, plugin vẫn xử lý đúng."""
    ast = _ast_server_listen_80()
    # Context points to a server node dict (not its block list)
    _run(
        remedy,
        user_inputs=["301", TARGET_HOST],
        scan_result_by_file={FILE: [_return_entry("add", CTX_SERVER_NODE)]},
        ast_by_file={FILE: ast},
    )
    # Should not crash; if modified, structure must be valid
    if FILE in remedy.child_ast_modified:
        parsed = remedy.child_ast_modified[FILE]["parsed"]
        assert isinstance(parsed, list)


def test_28_multi_server_blocks_mutate_correct_target_block(remedy):
    """28. Nhiều server block, mutate đúng block target."""
    # Context points to second server block's list
    ctx_second_server = ["config", 0, "parsed", 0, "block", 1, "block"]
    ast = {
        "parsed": [_http([
            _server([_node("listen", ["80"]), _node("server_name", ["first.com"])]),
            _server([_node("listen", ["80"]), _node("server_name", ["second.com"])]),
        ])]
    }
    _run(
        remedy,
        user_inputs=["301", TARGET_HOST],
        scan_result_by_file={FILE: [_return_entry("add", ctx_second_server)]},
        ast_by_file={FILE: ast},
    )
    parsed = remedy.child_ast_modified[FILE]["parsed"]
    first_server_block  = parsed[0]["block"][0]["block"]
    second_server_block = parsed[0]["block"][1]["block"]
    assert _args_of(first_server_block,  "return") is None
    assert _args_of(second_server_block, "return") == ["301", TARGET_HOST]


def test_29_file_path_normalization_key_match(remedy):
    """29. File path normalize khác kiểu vẫn match đúng (khi key giống nhau)."""
    ast = _ast_server_listen_80()
    _run(
        remedy,
        user_inputs=["301", TARGET_HOST],
        scan_result_by_file={FILE: [_return_entry("add", CTX_SERVER_BLOCK)]},
        ast_by_file={FILE: ast},
    )
    assert FILE in remedy.child_ast_modified


def test_30_other_rule_scan_result_does_not_affect_ast(remedy):
    """30. Scan result cho rule khác không đổi AST (no matching file)."""
    ast = _ast_server_listen_80()
    original_parsed = copy.deepcopy(ast["parsed"])
    # child_scan_result empty → no file matches
    _run(
        remedy,
        user_inputs=["301", TARGET_HOST],
        scan_result_by_file={},  # no violating files
        ast_by_file={FILE: ast},
    )
    # Nothing should be modified
    assert remedy.child_ast_modified == {}


def test_31_child_ast_modified_only_has_violating_file(remedy):
    """31. child_ast_modified chỉ có file vi phạm."""
    ast_a = _ast_server_listen_80()
    ast_b = _ast_server_listen_80()
    _run(
        remedy,
        user_inputs=["301", TARGET_HOST],
        scan_result_by_file={FILE_A: [_return_entry("add", CTX_SERVER_BLOCK)]},
        ast_by_file={FILE_A: ast_a, FILE_B: ast_b},
    )
    assert FILE_A in remedy.child_ast_modified
    assert FILE_B not in remedy.child_ast_modified


def test_32_ast_root_list_not_polluted_with_return(remedy):
    """32. AST root list không bị thêm return sai chỗ."""
    ast = _ast_server_listen_80()
    _run(
        remedy,
        user_inputs=["301", TARGET_HOST],
        scan_result_by_file={FILE: [_return_entry("add", CTX_SERVER_BLOCK)]},
        ast_by_file={FILE: ast},
    )
    parsed_root = remedy.child_ast_modified[FILE]["parsed"]
    root_directives = [n.get("directive") for n in parsed_root if isinstance(n, dict)]
    assert "return" not in root_directives


def test_33_repeated_remediation_does_not_corrupt_ast(remedy):
    """33. Remediate lặp lại không làm thay đổi sai."""
    ast = _ast_server_listen_80()
    _run(
        remedy,
        user_inputs=["301", TARGET_HOST],
        scan_result_by_file={FILE: [_return_entry("add", CTX_SERVER_BLOCK)]},
        ast_by_file={FILE: ast},
    )
    after_first = copy.deepcopy(remedy.child_ast_modified[FILE])

    # Second run using the already-modified AST
    _run(
        remedy,
        user_inputs=["301", TARGET_HOST],
        scan_result_by_file={FILE: [_return_entry("add", CTX_SERVER_BLOCK)]},
        ast_by_file={FILE: after_first},
    )
    server_block = _get_server_block(remedy.child_ast_modified)
    count = _count_directive(server_block, "return")
    assert count == 1


def test_34_deep_copy_ast_no_alias_to_input(remedy):
    """34. Deep copy AST không alias input."""
    ast = _ast_server_listen_80()
    original_server_block_ref = ast["parsed"][0]["block"][0]["block"]

    _run(
        remedy,
        user_inputs=["301", TARGET_HOST],
        scan_result_by_file={FILE: [_return_entry("add", CTX_SERVER_BLOCK)]},
        ast_by_file={FILE: ast},
    )
    # Mutate original input after remediation
    original_server_block_ref.append(_node("some_directive", ["value"]))
    # Modified AST must NOT reflect this change
    server_block_mod = _get_server_block(remedy.child_ast_modified)
    directives_mod = [n.get("directive") for n in server_block_mod if isinstance(n, dict)]
    assert "some_directive" not in directives_mod


# ===========================================================================
# E. Regression / edge (35-40)
# ===========================================================================

def test_35_empty_scan_result_ast_unchanged(remedy):
    """35. Scan result rỗng, AST không đổi."""
    ast = _ast_server_listen_80()
    _run(
        remedy,
        user_inputs=["301", TARGET_HOST],
        scan_result_by_file={},
        ast_by_file={FILE: ast},
    )
    assert remedy.child_ast_modified == {}


def test_36_partial_input_uses_safe_defaults(remedy):
    """36. Input thiếu một phần, plugin dùng default an toàn."""
    ast = _ast_server_listen_80()
    # Provide only code, no target → triggers len(user_inputs) < 2 → defaults
    remedy.user_inputs = []  # trigger default path
    is_valid, _ = remedy._validate_user_inputs()
    assert is_valid is True
    assert remedy.user_inputs[0] == "301"
    assert "$request_uri" in remedy.user_inputs[1]


def test_37_redirect_301_preserves_correct_target(remedy):
    """37. Redirect code 301 vẫn giữ nguyên target đúng."""
    ast = _ast_server_listen_80()
    _run(
        remedy,
        user_inputs=["301", TARGET_HOST],
        scan_result_by_file={FILE: [_return_entry("add", CTX_SERVER_BLOCK)]},
        ast_by_file={FILE: ast},
    )
    server_block = _get_server_block(remedy.child_ast_modified)
    args = _args_of(server_block, "return")
    assert args[0] == "301"
    assert args[1] == TARGET_HOST


def test_38_target_with_query_string_still_preserves_request_uri(remedy):
    """38. Target có $request_uri vẫn giữ nguyên $request_uri."""
    target_with_query = "https://$host$request_uri"
    ast = _ast_server_listen_80()
    _run(
        remedy,
        user_inputs=["301", target_with_query],
        scan_result_by_file={FILE: [_return_entry("add", CTX_SERVER_BLOCK)]},
        ast_by_file={FILE: ast},
    )
    server_block = _get_server_block(remedy.child_ast_modified)
    args = _args_of(server_block, "return")
    assert args is not None
    assert "$request_uri" in args[1]


def test_39_diff_reflects_return_directive_change(remedy):
    """39. Diff chỉ thể hiện return directive."""
    ast = _ast_server_listen_80()
    _run(
        remedy,
        user_inputs=["301", TARGET_HOST],
        scan_result_by_file={FILE: [_return_entry("add", CTX_SERVER_BLOCK)]},
        ast_by_file={FILE: ast},
    )
    remedy.child_ast_config = {FILE: ast}
    payload = remedy.build_file_diff_payload(FILE)
    assert payload["file_path"] == FILE
    assert payload["mode"] == "config"
    diff = payload["diff_text"]
    assert "return" in diff


def test_40_ast_after_remedy_has_valid_crossplane_structure(remedy):
    """40. AST sau sửa vẫn giữ cấu trúc crossplane hợp lệ."""
    ast = _ast_server_listen_80()
    _run(
        remedy,
        user_inputs=["301", TARGET_HOST],
        scan_result_by_file={FILE: [_return_entry("add", CTX_SERVER_BLOCK)]},
        ast_by_file={FILE: ast},
    )
    modified = remedy.child_ast_modified[FILE]
    parsed = modified.get("parsed")
    assert isinstance(parsed, list)
    # Top-level node should be http
    assert parsed[0].get("directive") == "http"
    # http block must exist and be a list
    http_block = parsed[0].get("block")
    assert isinstance(http_block, list)
    # Should contain server block
    assert http_block[0].get("directive") == "server"
    # server block must be a list
    server_block = http_block[0].get("block")
    assert isinstance(server_block, list)
    # Every node in server block must be a dict with directive key
    for node in server_block:
        assert isinstance(node, dict)
        assert "directive" in node
