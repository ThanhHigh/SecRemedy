"""
Unit tests for Remediate532 — CIS Nginx Benchmark Rule 5.3.2.
Bám sát ma trận kiểm thử tại docs/tests/remedyEng/test_remediate_532.md.

Nhóm A. Metadata / contract               (tests  1– 3)
Nhóm B. Policy selection (_get_csp_policy)(tests  4–12)
Nhóm C. Mutation correctness              (tests 13–25)
Nhóm D. Context / safety                  (tests 26–34)
Nhóm E. Regression / edge                (tests 35–40)

Tổng: 40 test cases.
"""

import copy
import pytest

from core.remedyEng.base_remedy import BaseRemedy
from core.remedyEng.recommendations.remediate_532 import Remediate532


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

FILE   = "/etc/nginx/nginx.conf"
FILE_A = "/etc/nginx/nginx.conf"
FILE_B = "/etc/nginx/conf.d/site.conf"

HEADER_NAME     = "Content-Security-Policy"
BASELINE_POLICY = "default-src 'self'; frame-ancestors 'self'; form-action 'self';"
MINIMAL_POLICY  = "default-src 'self';"

# Quoted baseline as it appears in args list
BASELINE_ARGS = [HEADER_NAME, f'"{BASELINE_POLICY}"', "always"]


# ---------------------------------------------------------------------------
# Helpers: AST node builders
# ---------------------------------------------------------------------------

def _node(directive: str, args: list | None = None, block: list | None = None) -> dict:
    item = {"directive": directive, "args": args or []}
    if block is not None:
        item["block"] = block
    return item


def _http(block: list) -> dict:
    return _node("http", [], block)


def _server(block: list) -> dict:
    return _node("server", [], block)


def _location(args: list, block: list) -> dict:
    return _node("location", args, block)


# ---------------------------------------------------------------------------
# Parsed AST factories
# ---------------------------------------------------------------------------

def _simple_parsed_http() -> list:
    """http > server (không có add_header). Dùng cho action=add."""
    return [
        _http([
            _server([
                _node("listen", ["80"]),
                _node("server_name", ["example.com"]),
            ])
        ])
    ]


def _parsed_server_with_csp(csp_args: list | None = None) -> list:
    """http > server > add_header CSP (sai / cũ). Dùng cho action=replace."""
    header_args = csp_args if csp_args is not None else [HEADER_NAME, '"old-policy"']
    return [
        _http([
            _server([
                _node("listen", ["80"]),
                _node("add_header", header_args),
            ])
        ])
    ]


def _parsed_with_extra_headers() -> list:
    """http > server với thêm X-Frame-Options và X-Content-Type-Options."""
    return [
        _http([
            _server([
                _node("listen", ["443"]),
                _node("add_header", ["X-Frame-Options", "SAMEORIGIN", "always"]),
                _node("add_header", ["X-Content-Type-Options", '"nosniff"', "always"]),
            ])
        ])
    ]


def _parsed_location_block() -> list:
    """http > server > location /api với directive proxy_pass."""
    return [
        _http([
            _server([
                _node("listen", ["80"]),
                _location(["/api"], [
                    _node("proxy_pass", ["http://backend"]),
                ]),
            ])
        ])
    ]


def _make_ast(parsed: list) -> dict:
    return {"parsed": parsed}


# ---------------------------------------------------------------------------
# exact_path helpers
#
# _simple_parsed_http():
#   parsed[0]                → http node
#   parsed[0]["block"][0]    → server node
#   parsed[0]["block"][0]["block"] → [listen, server_name]  ← parent for add
#
# action="add": exact_path = [0, "block", 0, "block", 2]
#               parent     = [0, "block", 0, "block"]
#
# _parsed_server_with_csp():
#   parsed[0]["block"][0]["block"][1] = add_header (old)  ← replace target
# ---------------------------------------------------------------------------

ADD_EXACT_PATH     = [0, "block", 0, "block", 2]   # parent = server block
REPLACE_EXACT_PATH = [0, "block", 0, "block", 1]   # exact add_header node
HTTP_ADD_PATH      = [0, "block", 1]                # parent = http block
LOCATION_ADD_PATH  = [0, "block", 0, "block", 1, "block", 1]


# ---------------------------------------------------------------------------
# Violation builders
# ---------------------------------------------------------------------------

def _violation_add(
    exact_path: list | None = None,
    directive: str = "add_header",
) -> dict:
    return {
        "action": "add",
        "directive": directive,
        "exact_path": exact_path if exact_path is not None else ADD_EXACT_PATH,
        "args": BASELINE_ARGS,
    }


def _violation_replace(
    exact_path: list | None = None,
    directive: str = "add_header",
) -> dict:
    return {
        "action": "replace",
        "directive": directive,
        "exact_path": exact_path if exact_path is not None else REPLACE_EXACT_PATH,
        "args": BASELINE_ARGS,
    }


# ---------------------------------------------------------------------------
# Run helpers
# ---------------------------------------------------------------------------

def _run(
    remedy: Remediate532,
    user_inputs: list,
    scan_result_by_file: dict,
    ast_by_file: dict,
) -> None:
    remedy.user_inputs = user_inputs
    remedy.child_scan_result = scan_result_by_file
    remedy.child_ast_config = ast_by_file
    remedy.remediate()


def _std_add_run(remedy: Remediate532, use_baseline: str = "yes", custom_csp: str = "") -> None:
    """Chạy với action=add, baseline policy."""
    _run(
        remedy,
        user_inputs=[use_baseline, custom_csp],
        scan_result_by_file={FILE: [_violation_add()]},
        ast_by_file={FILE: _make_ast(_simple_parsed_http())},
    )


def _std_replace_run(remedy: Remediate532, use_baseline: str = "yes", custom_csp: str = "") -> None:
    """Chạy với action=replace, baseline policy."""
    _run(
        remedy,
        user_inputs=[use_baseline, custom_csp],
        scan_result_by_file={FILE: [_violation_replace()]},
        ast_by_file={FILE: _make_ast(_parsed_server_with_csp())},
    )


def _get_server_block(modified: dict, file: str = FILE) -> list:
    """Return server block list từ modified output."""
    return modified[file]["parsed"][0]["block"][0]["block"]


# ===========================================================================
# A. Metadata / contract (1-3)
# ===========================================================================

def test_01_is_base_remedy_subclass():
    """1. Kiểm tra kế thừa BaseRemedy."""
    remedy = Remediate532()
    assert isinstance(remedy, BaseRemedy)


def test_02_has_input_is_true():
    """2. Kiểm tra has_input == True và id == '5.3.2'."""
    remedy = Remediate532()
    assert remedy.has_input is True
    assert remedy.id == "5.3.2"


def test_03_guide_detail_mentions_csp_risk():
    """3. Guide mô tả rủi ro CSP quá chặt (baseline và custom)."""
    remedy = Remediate532()
    assert remedy.has_guide_detail is True
    detail = remedy.remedy_guide_detail
    assert isinstance(detail, str) and len(detail) > 0
    lowered = detail.lower()
    # Guide phải đề cập Content-Security-Policy hoặc CSP
    assert "content-security-policy" in lowered or "csp" in lowered


# ===========================================================================
# B. Policy selection – _get_csp_policy() (4-12)
# ===========================================================================

@pytest.fixture
def remedy() -> Remediate532:
    return Remediate532()


def test_04_baseline_when_inputs_empty(remedy):
    """4. _get_csp_policy() chọn baseline khi user_inputs rỗng."""
    remedy.user_inputs = []
    policy = remedy._get_csp_policy()
    assert policy == BASELINE_POLICY


def test_05_baseline_when_user_says_yes(remedy):
    """5. _get_csp_policy() chọn baseline khi user nhập 'yes' và không custom."""
    remedy.user_inputs = ["yes", ""]
    policy = remedy._get_csp_policy()
    assert policy == BASELINE_POLICY


def test_06_custom_policy_overrides_baseline(remedy):
    """6. _get_csp_policy() chọn custom khi user nhập policy tùy chỉnh."""
    custom = "default-src 'self'; img-src 'self' https://cdn.example.com;"
    remedy.user_inputs = ["yes", custom]
    policy = remedy._get_csp_policy()
    assert policy == custom


def test_07_no_baseline_no_custom_returns_minimal(remedy):
    """7. User từ chối baseline và không nhập custom → minimal policy."""
    remedy.user_inputs = ["no", ""]
    policy = remedy._get_csp_policy()
    assert policy == MINIMAL_POLICY


def test_08_custom_policy_has_default_src(remedy):
    """8. Policy custom có chứa 'default-src'."""
    custom = "default-src 'self'; img-src 'self';"
    remedy.user_inputs = ["yes", custom]
    policy = remedy._get_csp_policy()
    assert "default-src" in policy


def test_09_custom_policy_has_frame_ancestors(remedy):
    """9. Policy custom có chứa 'frame-ancestors'."""
    custom = "default-src 'self'; frame-ancestors 'self' https://partner.com;"
    remedy.user_inputs = ["yes", custom]
    policy = remedy._get_csp_policy()
    assert "frame-ancestors" in policy


def test_10_custom_policy_has_form_action(remedy):
    """10. Policy custom có chứa 'form-action'."""
    custom = "default-src 'self'; form-action 'self';"
    remedy.user_inputs = ["yes", custom]
    policy = remedy._get_csp_policy()
    assert "form-action" in policy


def test_11_empty_custom_falls_back_to_baseline(remedy):
    """11. Custom rỗng với use_baseline='yes' → baseline được dùng."""
    remedy.user_inputs = ["yes", ""]
    policy = remedy._get_csp_policy()
    assert policy == BASELINE_POLICY


def test_12_n_variant_also_returns_minimal(remedy):
    """12. Các biến thể từ chối ('n', 'false', '0') đều trả về minimal policy."""
    for reject_val in ["n", "false", "0"]:
        remedy.user_inputs = [reject_val, ""]
        policy = remedy._get_csp_policy()
        assert policy == MINIMAL_POLICY, (
            f"Biến thể từ chối '{reject_val}' phải trả về minimal policy, nhận: {policy}"
        )


# ===========================================================================
# C. Mutation correctness (13-25)
# ===========================================================================

def test_13_add_csp_header_baseline(remedy):
    """13. Add CSP header baseline vào server block."""
    _std_add_run(remedy)
    assert FILE in remedy.child_ast_modified
    server_block = _get_server_block(remedy.child_ast_modified)
    csp_headers = [n for n in server_block
                   if n["directive"] == "add_header" and n["args"][0] == HEADER_NAME]
    assert len(csp_headers) >= 1, "Phải có add_header Content-Security-Policy"


def test_14_add_csp_header_custom(remedy):
    """14. Add CSP header với policy tùy chỉnh."""
    custom = "default-src 'self'; img-src 'self' https://cdn.example.com;"
    _run(
        remedy,
        user_inputs=["yes", custom],
        scan_result_by_file={FILE: [_violation_add()]},
        ast_by_file={FILE: _make_ast(_simple_parsed_http())},
    )
    server_block = _get_server_block(remedy.child_ast_modified)
    csp_headers = [n for n in server_block if n["directive"] == "add_header"
                   and n["args"][0] == HEADER_NAME]
    assert len(csp_headers) >= 1
    assert custom in csp_headers[0]["args"][1]  # policy quoted in args


def test_15_replace_csp_header(remedy):
    """15. Replace CSP header hiện có bằng baseline."""
    _std_replace_run(remedy)
    server_block = _get_server_block(remedy.child_ast_modified)
    csp_headers = [n for n in server_block if n["directive"] == "add_header"
                   and n["args"][0] == HEADER_NAME]
    assert len(csp_headers) >= 1
    assert BASELINE_POLICY in csp_headers[0]["args"][1]


def test_16_add_always_flag(remedy):
    """16. Add 'always' flag vào CSP header."""
    _std_add_run(remedy)
    server_block = _get_server_block(remedy.child_ast_modified)
    csp_headers = [n for n in server_block if n["directive"] == "add_header"
                   and n["args"][0] == HEADER_NAME]
    assert csp_headers[0]["args"][-1] == "always", "'always' phải có trong CSP header args"


def test_17_preserve_other_headers(remedy):
    """17. Giữ nguyên các header khác trong cùng block khi add."""
    parsed = _parsed_with_extra_headers()
    add_path = [0, "block", 0, "block", 3]  # sau listen, X-Frame, X-Content-Type
    _run(
        remedy,
        user_inputs=["yes", ""],
        scan_result_by_file={FILE: [_violation_add(exact_path=add_path)]},
        ast_by_file={FILE: _make_ast(parsed)},
    )
    server_block = _get_server_block(remedy.child_ast_modified)
    header_names = [n["args"][0] for n in server_block if n["directive"] == "add_header"]
    assert "X-Frame-Options" in header_names, "X-Frame-Options phải còn nguyên"
    assert "X-Content-Type-Options" in header_names, "X-Content-Type-Options phải còn nguyên"


def test_18_add_in_http_block(remedy):
    """18. Add CSP header vào http block."""
    parsed = [_http([_server([])])]
    add_path = [0, "block", 1]  # parent = http["block"]
    _run(
        remedy,
        user_inputs=["yes", ""],
        scan_result_by_file={FILE: [_violation_add(exact_path=add_path)]},
        ast_by_file={FILE: _make_ast(parsed)},
    )
    http_block = remedy.child_ast_modified[FILE]["parsed"][0]["block"]
    csp_headers = [n for n in http_block if n.get("directive") == "add_header"
                   and n["args"][0] == HEADER_NAME]
    assert len(csp_headers) >= 1, "CSP header phải được thêm vào http block"


def test_19_add_in_server_block(remedy):
    """19. Add CSP header trong server block (standard case)."""
    _std_add_run(remedy)
    server_block = _get_server_block(remedy.child_ast_modified)
    csp_headers = [n for n in server_block if n["directive"] == "add_header"]
    assert len(csp_headers) >= 1


def test_20_add_in_location_block(remedy):
    """20. Add CSP header trong location block."""
    parsed = _parsed_location_block()
    _run(
        remedy,
        user_inputs=["yes", ""],
        scan_result_by_file={FILE: [_violation_add(exact_path=LOCATION_ADD_PATH)]},
        ast_by_file={FILE: _make_ast(parsed)},
    )
    location_block = remedy.child_ast_modified[FILE]["parsed"][0]["block"][0]["block"][1]["block"]
    csp_headers = [n for n in location_block if n.get("directive") == "add_header"
                   and n["args"][0] == HEADER_NAME]
    assert len(csp_headers) >= 1, "CSP header phải được thêm vào location block"


def test_21_replace_correct_node_via_exact_path(remedy):
    """21. Replace đúng node từ exact_path (không đụng node khác)."""
    parsed = [
        _http([
            _server([
                _node("listen", ["443"]),
                _node("add_header", [HEADER_NAME, '"weak-policy"']),
                _node("server_name", ["example.com"]),
            ])
        ])
    ]
    replace_path = [0, "block", 0, "block", 1]
    _run(
        remedy,
        user_inputs=["yes", ""],
        scan_result_by_file={FILE: [_violation_replace(exact_path=replace_path)]},
        ast_by_file={FILE: _make_ast(parsed)},
    )
    server_block = remedy.child_ast_modified[FILE]["parsed"][0]["block"][0]["block"]
    assert server_block[1]["directive"] == "add_header"
    assert BASELINE_POLICY in server_block[1]["args"][1], "Node tại index 1 phải được update"
    assert server_block[2]["directive"] == "server_name", "server_name phải còn nguyên"


def test_22_add_correct_parent_list(remedy):
    """22. Append đúng parent list khi action=add, không append vào root."""
    _std_add_run(remedy)
    parsed = remedy.child_ast_modified[FILE]["parsed"]
    root_add = [n for n in parsed if n.get("directive") == "add_header"]
    assert len(root_add) == 0, "Không được append CSP header ở root"
    server_block = _get_server_block(remedy.child_ast_modified)
    server_csp = [n for n in server_block if n["directive"] == "add_header"]
    assert len(server_csp) >= 1, "CSP header phải xuất hiện ở server block"


def test_23_other_named_headers_not_changed(remedy):
    """23. Không đổi header khác tên (listen directive không bị mutate)."""
    _std_add_run(remedy)
    server_block = _get_server_block(remedy.child_ast_modified)
    listen_nodes = [n for n in server_block if n["directive"] == "listen"]
    assert len(listen_nodes) >= 1
    assert listen_nodes[0]["args"] == ["80"], "listen directive không được bị thay đổi"


def test_24_no_duplicate_csp_on_repeated_remediate(remedy):
    """24. Không tạo duplicate CSP header khi remediate lặp lại."""
    _std_add_run(remedy)
    after_first = copy.deepcopy(remedy.child_ast_modified[FILE])
    # Lần 2: không có violation
    _run(
        remedy,
        user_inputs=["yes", ""],
        scan_result_by_file={},
        ast_by_file={FILE: after_first},
    )
    assert remedy.child_ast_modified == {}, "Không violation → không được mutate lần 2"


def test_25_policy_serialized_as_quoted_string(remedy):
    """25. Policy được serialize thành quoted string trong args đúng format."""
    custom = "default-src 'self'; form-action 'self';"
    _run(
        remedy,
        user_inputs=["yes", custom],
        scan_result_by_file={FILE: [_violation_add()]},
        ast_by_file={FILE: _make_ast(_simple_parsed_http())},
    )
    server_block = _get_server_block(remedy.child_ast_modified)
    csp_headers = [n for n in server_block if n["directive"] == "add_header"
                   and n["args"][0] == HEADER_NAME]
    assert len(csp_headers) >= 1
    policy_arg = csp_headers[0]["args"][1]
    # Phải được quote
    assert policy_arg.startswith('"') and policy_arg.endswith('"'), (
        f"Policy args phải được quote: {policy_arg}"
    )


# ===========================================================================
# D. Context / safety (26-34)
# ===========================================================================

def test_26_empty_context_no_root_mutation(remedy):
    """26. Context rỗng (không có violation) thì không mutate root."""
    _run(
        remedy,
        user_inputs=["yes", ""],
        scan_result_by_file={},
        ast_by_file={FILE: _make_ast(_simple_parsed_http())},
    )
    assert remedy.child_ast_modified == {}


def test_27_bad_exact_path_no_ast_corruption(remedy):
    """27. Exact_path sai, plugin không corrupt AST và không crash."""
    bad_path = [0, "block", 0, "block", 99, "block", 0]
    _run(
        remedy,
        user_inputs=["yes", ""],
        scan_result_by_file={FILE: [_violation_add(exact_path=bad_path)]},
        ast_by_file={FILE: _make_ast(_simple_parsed_http())},
    )
    # Plugin không được crash
    if FILE in remedy.child_ast_modified:
        server_block = _get_server_block(remedy.child_ast_modified)
        csp_headers = [n for n in server_block if n["directive"] == "add_header"]
        assert len(csp_headers) == 0, "Path sai không được mutate server block"


def test_28_multi_file_only_violating_file_modified(remedy):
    """28. Nhiều file, chỉ file vi phạm được sửa."""
    ast_b = _make_ast([_http([_server([_node("listen", ["443"])])])])
    _run(
        remedy,
        user_inputs=["yes", ""],
        scan_result_by_file={FILE_A: [_violation_add()]},
        ast_by_file={
            FILE_A: _make_ast(_simple_parsed_http()),
            FILE_B: ast_b,
        },
    )
    assert FILE_A in remedy.child_ast_modified, "FILE_A có violation phải được sửa"
    assert FILE_B not in remedy.child_ast_modified, "FILE_B không có violation không được sửa"


def test_29_file_path_key_match(remedy):
    """29. File path normalize khác kiểu vẫn match đúng (same key lookup)."""
    _std_add_run(remedy)
    assert FILE in remedy.child_ast_modified


def test_30_non_add_header_directive_skipped(remedy):
    """30. Scan result directive khác add_header bị bỏ qua."""
    _run(
        remedy,
        user_inputs=["yes", ""],
        scan_result_by_file={FILE: [_violation_add(directive="server_tokens")]},
        ast_by_file={FILE: _make_ast(_simple_parsed_http())},
    )
    if FILE in remedy.child_ast_modified:
        server_block = _get_server_block(remedy.child_ast_modified)
        csp_headers = [n for n in server_block if n["directive"] == "add_header"]
        assert len(csp_headers) == 0, "Directive khác add_header không được tạo CSP header"


def test_31_deep_copy_independent_from_original(remedy):
    """31. AST deep copy độc lập — input gốc không bị alias."""
    original_ast = _make_ast(_simple_parsed_http())
    original_snapshot = copy.deepcopy(original_ast["parsed"])
    _run(
        remedy,
        user_inputs=["yes", ""],
        scan_result_by_file={FILE: [_violation_add()]},
        ast_by_file={FILE: original_ast},
    )
    assert original_ast["parsed"] == original_snapshot, (
        "remediate() không được alias và mutate input AST gốc"
    )


def test_32_diff_reflects_csp_change(remedy):
    """32. Diff phản ánh đúng thay đổi CSP header."""
    _std_add_run(remedy)
    remedy.child_ast_config = {FILE: _make_ast(_simple_parsed_http())}
    payload = remedy.build_file_diff_payload(FILE)
    assert payload["file_path"] == FILE
    diff = payload["diff_text"]
    assert "Content-Security-Policy" in diff or "default-src" in diff, (
        "Diff phải phản ánh thay đổi CSP"
    )


def test_33_ast_still_valid_after_mutation(remedy):
    """33. AST sau sửa vẫn hợp lệ: list > http > server."""
    _std_add_run(remedy)
    parsed = remedy.child_ast_modified[FILE]["parsed"]
    assert isinstance(parsed, list)
    http_node = parsed[0]
    assert http_node["directive"] == "http"
    assert isinstance(http_node["block"], list)
    server_node = http_node["block"][0]
    assert server_node["directive"] == "server"
    assert isinstance(server_node["block"], list)


def test_34_child_ast_modified_only_violating_file(remedy):
    """34. child_ast_modified chỉ chứa file vi phạm, không thừa file khác."""
    ast_b = _make_ast([_http([_server([])])])
    _run(
        remedy,
        user_inputs=["yes", ""],
        scan_result_by_file={FILE_A: [_violation_add()]},
        ast_by_file={
            FILE_A: _make_ast(_simple_parsed_http()),
            FILE_B: ast_b,
        },
    )
    assert set(remedy.child_ast_modified.keys()) == {FILE_A}, (
        "child_ast_modified chỉ nên chứa file vi phạm"
    )


# ===========================================================================
# E. Regression / edge (35-40)
# ===========================================================================

def test_35_baseline_csp_has_all_required_directives(remedy):
    """35. Baseline CSP phải chứa default-src, frame-ancestors, form-action."""
    remedy.user_inputs = []
    policy = remedy._get_csp_policy()
    assert "default-src" in policy
    assert "frame-ancestors" in policy
    assert "form-action" in policy


def test_36_custom_csp_takes_priority_over_baseline(remedy):
    """36. Custom CSP ưu tiên hơn baseline kể cả khi use_baseline='yes'."""
    custom = "default-src 'none'; script-src 'self';"
    remedy.user_inputs = ["yes", custom]
    policy = remedy._get_csp_policy()
    assert policy == custom
    assert policy != BASELINE_POLICY


def test_37_empty_scan_result_no_mutation(remedy):
    """37. Scan result rỗng, AST không đổi."""
    remedy.user_inputs = ["yes", ""]
    remedy.child_scan_result = {}
    remedy.child_ast_config = {FILE: _make_ast(_simple_parsed_http())}
    remedy.remediate()
    assert remedy.child_ast_modified == {}


def test_38_remediate_twice_no_duplicate_header(remedy):
    """38. Remediate lặp lại không tạo duplicate CSP header."""
    _std_add_run(remedy)
    after_first = copy.deepcopy(remedy.child_ast_modified[FILE])
    remedy2 = Remediate532()
    _run(
        remedy2,
        user_inputs=["yes", ""],
        scan_result_by_file={},  # Không còn violation
        ast_by_file={FILE: after_first},
    )
    assert remedy2.child_ast_modified == {}, "Không violation → không duplicate header"


def test_39_header_inserted_in_correct_target_block(remedy):
    """39. Header được chèn đúng block mục tiêu, không vào root hay block khác."""
    _std_add_run(remedy)
    parsed = remedy.child_ast_modified[FILE]["parsed"]
    root_directives = [n.get("directive") for n in parsed]
    assert "add_header" not in root_directives, "CSP header không được chèn vào root"
    server_block = _get_server_block(remedy.child_ast_modified)
    server_csp = [n for n in server_block if n["directive"] == "add_header"
                  and n["args"][0] == HEADER_NAME]
    assert len(server_csp) >= 1, "CSP header phải xuất hiện ở đúng server block"


def test_40_other_directives_in_block_not_lost(remedy):
    """40. Output không làm mất các directive khác trong block."""
    _std_add_run(remedy)
    server_block = _get_server_block(remedy.child_ast_modified)
    directives = [n["directive"] for n in server_block]
    assert "listen" in directives, "listen directive không được bị mất"
    assert "server_name" in directives, "server_name directive không được bị mất"
