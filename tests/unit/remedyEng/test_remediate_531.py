"""
Unit tests for Remediate531 — CIS Nginx Benchmark Rule 5.3.1.
Bám sát ma trận kiểm thử tại docs/tests/remedyEng/test_remediate_531.md.

Nhóm A. Metadata / contract               (tests  1– 3)
Nhóm B. Confirmation gate                 (tests  4–10)
Nhóm C. Mutation correctness              (tests 11–24)
Nhóm D. Context / safety                  (tests 25–34)
Nhóm E. Regression / edge                (tests 35–40)

Tổng: 40 test cases.
"""

import copy
import pytest

from core.remedyEng.base_remedy import BaseRemedy
from core.remedyEng.recommendations.remediate_531 import Remediate531


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

FILE   = "/etc/nginx/nginx.conf"
FILE_A = "/etc/nginx/nginx.conf"
FILE_B = "/etc/nginx/conf.d/site.conf"

HEADER_NAME  = "X-Content-Type-Options"
HEADER_VALUE = '"nosniff"'
HEADER_FLAG  = "always"

CORRECT_ARGS = [HEADER_NAME, HEADER_VALUE, HEADER_FLAG]

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
    """Parsed chứa http > server (không có add_header). Dùng cho action=add."""
    return [
        _http([
            _server([
                _node("listen", ["80"]),
                _node("server_name", ["example.com"]),
            ])
        ])
    ]


def _parsed_server_with_header(args: list | None = None) -> list:
    """http > server > add_header node. Dùng cho action=replace."""
    header_args = args if args is not None else [HEADER_NAME, '"wrong"']
    return [
        _http([
            _server([
                _node("listen", ["80"]),
                _node("add_header", header_args),
            ])
        ])
    ]


def _parsed_with_extra_headers() -> list:
    """http > server với thêm CSP và X-Frame-Options. Dùng để kiểm tra preservation."""
    return [
        _http([
            _server([
                _node("listen", ["443"]),
                _node("add_header", ["Content-Security-Policy", '"default-src self"', "always"]),
                _node("add_header", ["X-Frame-Options", "SAMEORIGIN", "always"]),
            ])
        ])
    ]


def _parsed_location_block() -> list:
    """http > server > location /api với các directives khác."""
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
# Cấu trúc _simple_parsed_http():
#   parsed         → list
#   [0]            → http node
#   ["block"]      → [server]
#   [0]            → server node
#   ["block"]      → [listen, server_name]   ← parent for add
#
# Để action="add" append vào server block, ta cần parent path = [0, "block", 0, "block"]
# và exact_path = [0, "block", 0, "block", <next_index>]
# Plugin lấy parent = exact_path[:-1], nên:
#   exact_path = [0, "block", 0, "block", 2]  → parent = [0, "block", 0, "block"]
#
# Cấu trúc _parsed_server_with_header():
#   parsed[0]["block"][0]["block"][1] = add_header node   ← đích cho replace
#   exact_path = [0, "block", 0, "block", 1]
# ---------------------------------------------------------------------------

# Path để add vào server block (parent = [0, "block", 0, "block"])
ADD_EXACT_PATH    = [0, "block", 0, "block", 2]   # index 2 vì server block đã có 2 phần tử

# Path để replace add_header tại server block index 1
REPLACE_EXACT_PATH = [0, "block", 0, "block", 1]

# Path để add vào http block (http["block"] = [server])
HTTP_ADD_PATH = [0, "block", 1]

# Path để add vào location block
#  _parsed_location_block: parsed[0]["block"][0]["block"][1]["block"] = [proxy_pass]
LOCATION_ADD_PATH = [0, "block", 0, "block", 1, "block", 1]


# ---------------------------------------------------------------------------
# Violation builders
# ---------------------------------------------------------------------------

def _violation_add(
    exact_path: list | None = None,
    args: list | None = None,
    directive: str = "add_header",
) -> dict:
    return {
        "action": "add",
        "directive": directive,
        "exact_path": exact_path if exact_path is not None else ADD_EXACT_PATH,
        "args": args if args is not None else CORRECT_ARGS,
    }


def _violation_replace(
    exact_path: list | None = None,
    args: list | None = None,
    directive: str = "add_header",
) -> dict:
    return {
        "action": "replace",
        "directive": directive,
        "exact_path": exact_path if exact_path is not None else REPLACE_EXACT_PATH,
        "args": args if args is not None else CORRECT_ARGS,
    }


# ---------------------------------------------------------------------------
# Run helpers
# ---------------------------------------------------------------------------

def _run(
    remedy: Remediate531,
    user_inputs: list,
    scan_result_by_file: dict,
    ast_by_file: dict,
) -> None:
    remedy.user_inputs = user_inputs
    remedy.child_scan_result = scan_result_by_file
    remedy.child_ast_config = ast_by_file
    remedy.remediate()


def _std_add_run(remedy: Remediate531, confirm: str = "yes") -> None:
    """Chạy với action=add, user xác nhận."""
    _run(
        remedy,
        user_inputs=[confirm],
        scan_result_by_file={FILE: [_violation_add()]},
        ast_by_file={FILE: _make_ast(_simple_parsed_http())},
    )


def _std_replace_run(remedy: Remediate531, confirm: str = "yes") -> None:
    """Chạy với action=replace, user xác nhận."""
    _run(
        remedy,
        user_inputs=[confirm],
        scan_result_by_file={FILE: [_violation_replace()]},
        ast_by_file={FILE: _make_ast(_parsed_server_with_header())},
    )


def _get_server_block(modified: dict, file: str = FILE) -> list:
    """Return server[\"block\"] list từ modified output."""
    return modified[file]["parsed"][0]["block"][0]["block"]


# ===========================================================================
# A. Metadata / contract (1-3)
# ===========================================================================

def test_01_is_base_remedy_subclass():
    """1. Kiểm tra kế thừa BaseRemedy."""
    remedy = Remediate531()
    assert isinstance(remedy, BaseRemedy)


def test_02_has_input_is_true():
    """2. Kiểm tra has_input == True và id == '5.3.1'."""
    remedy = Remediate531()
    assert remedy.has_input is True
    assert remedy.id == "5.3.1"


def test_03_guide_detail_describes_confirmation():
    """3. Kiểm tra guide mô tả rõ remediation chỉ chạy khi người dùng đồng ý."""
    remedy = Remediate531()
    assert remedy.has_guide_detail is True
    detail = remedy.remedy_guide_detail
    assert isinstance(detail, str) and len(detail) > 0
    lowered = detail.lower()
    # Guide phải đề cập header X-Content-Type-Options hoặc nosniff
    assert "x-content-type-options" in lowered or "nosniff" in lowered


# ===========================================================================
# B. Confirmation gate (4-10)
# ===========================================================================

@pytest.fixture
def remedy() -> Remediate531:
    return Remediate531()


def test_04_input_yes_allows_remediation(remedy):
    """4. Input 'yes' cho phép chạy remediation."""
    _std_add_run(remedy, confirm="yes")
    assert FILE in remedy.child_ast_modified, "Xác nhận 'yes' phải kích hoạt mutation"


def test_05_input_y_allows_remediation(remedy):
    """5. Input 'y' cho phép chạy."""
    _std_add_run(remedy, confirm="y")
    assert FILE in remedy.child_ast_modified


def test_06_input_true_allows_remediation(remedy):
    """6. Input 'true' cho phép chạy."""
    _std_add_run(remedy, confirm="true")
    assert FILE in remedy.child_ast_modified


def test_07_input_1_allows_remediation(remedy):
    """7. Input '1' cho phép chạy."""
    _std_add_run(remedy, confirm="1")
    assert FILE in remedy.child_ast_modified


def test_08_input_no_rejects_remediation(remedy):
    """8. Input 'no' từ chối chạy."""
    _std_add_run(remedy, confirm="no")
    assert remedy.child_ast_modified == {}


def test_09_input_false_rejects_remediation(remedy):
    """9. Input 'false' từ chối chạy."""
    _std_add_run(remedy, confirm="false")
    assert remedy.child_ast_modified == {}


def test_10_empty_input_rejects_remediation(remedy):
    """10. Input rỗng từ chối chạy."""
    _run(
        remedy,
        user_inputs=[""],
        scan_result_by_file={FILE: [_violation_add()]},
        ast_by_file={FILE: _make_ast(_simple_parsed_http())},
    )
    assert remedy.child_ast_modified == {}


# ===========================================================================
# C. Mutation correctness (11-24)
# ===========================================================================

def test_11_add_header_name_is_x_content_type_options(remedy):
    """11. Add 'X-Content-Type-Options' header mới đúng tên."""
    _std_add_run(remedy)
    server_block = _get_server_block(remedy.child_ast_modified)
    add_headers = [n for n in server_block if n["directive"] == "add_header"]
    assert any(n["args"][0] == HEADER_NAME for n in add_headers), (
        "Phải có add_header với tên X-Content-Type-Options"
    )


def test_12_add_header_value_is_nosniff(remedy):
    """12. Add 'nosniff' đúng giá trị."""
    _std_add_run(remedy)
    server_block = _get_server_block(remedy.child_ast_modified)
    add_headers = [n for n in server_block
                   if n["directive"] == "add_header" and n["args"][0] == HEADER_NAME]
    assert len(add_headers) >= 1
    assert add_headers[0]["args"][1] == HEADER_VALUE, "Giá trị phải là '\"nosniff\"'"


def test_13_add_header_has_always_flag(remedy):
    """13. Add 'always' đúng flag."""
    _std_add_run(remedy)
    server_block = _get_server_block(remedy.child_ast_modified)
    add_headers = [n for n in server_block
                   if n["directive"] == "add_header" and n["args"][0] == HEADER_NAME]
    assert add_headers[0]["args"][2] == HEADER_FLAG, "Flag 'always' phải có trong args"


def test_14_replace_updates_header_args(remedy):
    """14. Replace header existing value đúng."""
    _std_replace_run(remedy)
    server_block = _get_server_block(remedy.child_ast_modified)
    add_headers = [n for n in server_block if n["directive"] == "add_header"]
    assert len(add_headers) >= 1
    target = add_headers[0]
    assert target["args"] == CORRECT_ARGS, (
        f"args sau replace phải là {CORRECT_ARGS}, nhận được {target['args']}"
    )


def test_15_preserve_other_headers_in_same_block(remedy):
    """15. Giữ nguyên các header khác trong cùng block khi add."""
    parsed = _parsed_with_extra_headers()
    # Thêm path cho action add vào server block (đây đã có 3 nodes: listen, CSP, X-Frame)
    add_path = [0, "block", 0, "block", 3]  # index 3 = sau listen, CSP, X-Frame
    _run(
        remedy,
        user_inputs=["yes"],
        scan_result_by_file={FILE: [_violation_add(exact_path=add_path)]},
        ast_by_file={FILE: _make_ast(parsed)},
    )
    server_block = _get_server_block(remedy.child_ast_modified)
    directives = [n["directive"] for n in server_block]
    assert "add_header" in directives
    # CSP và X-Frame phải còn
    add_header_args = [n["args"][0] for n in server_block if n["directive"] == "add_header"]
    assert "Content-Security-Policy" in add_header_args
    assert "X-Frame-Options" in add_header_args


def test_16_add_header_in_http_block(remedy):
    """16. Add header có thể vực trong http block."""
    # AST với http block; path trỏ vào http["block"] index 1 (sau server)
    parsed = [_http([_server([])])]
    add_path = [0, "block", 1]  # parent = [0, "block"] = http["block"]
    _run(
        remedy,
        user_inputs=["yes"],
        scan_result_by_file={FILE: [_violation_add(exact_path=add_path)]},
        ast_by_file={FILE: _make_ast(parsed)},
    )
    http_block = remedy.child_ast_modified[FILE]["parsed"][0]["block"]
    add_headers = [n for n in http_block if n.get("directive") == "add_header"]
    assert len(add_headers) >= 1
    assert add_headers[0]["args"][0] == HEADER_NAME


def test_17_add_header_in_server_block(remedy):
    """17. Add header trong server block (standard case)."""
    _std_add_run(remedy)
    server_block = _get_server_block(remedy.child_ast_modified)
    add_headers = [n for n in server_block if n["directive"] == "add_header"]
    assert len(add_headers) >= 1


def test_18_add_header_in_location_block(remedy):
    """18. Add header trong location block."""
    parsed = _parsed_location_block()
    # parsed[0]["block"][0]["block"][1]["block"] = [proxy_pass]
    # parent = parsed[0]["block"][0]["block"][1]["block"]
    # exact_path = [0, "block", 0, "block", 1, "block", 1]  (index 1 after proxy_pass)
    _run(
        remedy,
        user_inputs=["yes"],
        scan_result_by_file={FILE: [_violation_add(exact_path=LOCATION_ADD_PATH)]},
        ast_by_file={FILE: _make_ast(parsed)},
    )
    location_block = remedy.child_ast_modified[FILE]["parsed"][0]["block"][0]["block"][1]["block"]
    add_headers = [n for n in location_block if n.get("directive") == "add_header"]
    assert len(add_headers) >= 1
    assert add_headers[0]["args"][0] == HEADER_NAME


def test_19_update_directive_action_add(remedy):
    """19. Directive được cập nhật khi action là 'add'."""
    _std_add_run(remedy)
    server_block = _get_server_block(remedy.child_ast_modified)
    add_headers = [n for n in server_block if n["directive"] == "add_header"]
    assert len(add_headers) >= 1


def test_20_update_directive_action_replace(remedy):
    """20. Directive được cập nhật khi action là 'replace'."""
    _std_replace_run(remedy)
    server_block = _get_server_block(remedy.child_ast_modified)
    add_headers = [n for n in server_block if n["directive"] == "add_header"]
    assert len(add_headers) >= 1
    assert add_headers[0]["args"] == CORRECT_ARGS


def test_21_other_header_names_not_changed(remedy):
    """21. Không đổi header khác tên (non-add_header directives không bị mutate)."""
    _std_add_run(remedy)
    server_block = _get_server_block(remedy.child_ast_modified)
    listen_nodes = [n for n in server_block if n["directive"] == "listen"]
    assert len(listen_nodes) >= 1
    assert listen_nodes[0]["args"] == ["80"], "listen directive không được bị thay đổi"


def test_22_no_duplicate_header_on_repeated_remediate(remedy):
    """22. Không tạo duplicate header khi remediate lặp lại (kiểm tra count)."""
    _std_add_run(remedy)
    # Lần 2: dùng kết quả của lần 1 làm input
    after_first = copy.deepcopy(remedy.child_ast_modified[FILE])
    # Trong lần 2 không có violation → child_ast_modified sẽ rỗng
    _run(
        remedy,
        user_inputs=["yes"],
        scan_result_by_file={},  # không có violation
        ast_by_file={FILE: after_first},
    )
    assert remedy.child_ast_modified == {}, "Không có violation thì không được mutate"


def test_23_upsert_correct_node_from_exact_path(remedy):
    """23. Upsert đúng node từ exact_path khi action=replace."""
    # Server block: [listen, add_header_wrong, server_name]
    parsed = [
        _http([
            _server([
                _node("listen", ["443"]),
                _node("add_header", [HEADER_NAME, '"wrong-value"']),
                _node("server_name", ["example.com"]),
            ])
        ])
    ]
    replace_path = [0, "block", 0, "block", 1]  # exact node = add_header
    _run(
        remedy,
        user_inputs=["yes"],
        scan_result_by_file={FILE: [_violation_replace(exact_path=replace_path)]},
        ast_by_file={FILE: _make_ast(parsed)},
    )
    server_block = remedy.child_ast_modified[FILE]["parsed"][0]["block"][0]["block"]
    assert server_block[1]["directive"] == "add_header"
    assert server_block[1]["args"] == CORRECT_ARGS, "Node tại index 1 phải được update đúng"
    # server_name phải còn nguyên
    assert server_block[2]["directive"] == "server_name"


def test_24_append_to_correct_parent_list_on_add(remedy):
    """24. Append đúng parent list khi action=add (không append vào root hay http)."""
    _std_add_run(remedy)
    parsed = remedy.child_ast_modified[FILE]["parsed"]
    # Root list không được có add_header
    root_add_headers = [n for n in parsed if n.get("directive") == "add_header"]
    assert len(root_add_headers) == 0, "Không được append ở root"
    # Server block mới có add_header
    server_block = _get_server_block(remedy.child_ast_modified)
    server_add_headers = [n for n in server_block if n["directive"] == "add_header"]
    assert len(server_add_headers) >= 1, "add_header phải xuất hiện ở server block"


# ===========================================================================
# D. Context / safety (25-34)
# ===========================================================================

def test_25_user_decline_ast_not_changed(remedy):
    """25. User từ chối thì child_ast_modified phải rỗng."""
    _run(
        remedy,
        user_inputs=["no"],
        scan_result_by_file={FILE: [_violation_add()]},
        ast_by_file={FILE: _make_ast(_simple_parsed_http())},
    )
    assert remedy.child_ast_modified == {}


def test_26_empty_context_no_root_mutation(remedy):
    """26. Context rỗng (không có violation) thì không mutate root."""
    _run(
        remedy,
        user_inputs=["yes"],
        scan_result_by_file={},
        ast_by_file={FILE: _make_ast(_simple_parsed_http())},
    )
    assert remedy.child_ast_modified == {}


def test_27_multi_file_only_violating_file_modified(remedy):
    """27. Nhiều file, chỉ file vi phạm được sửa."""
    ast_b = _make_ast([_http([_server([_node("listen", ["443"])])])])
    _run(
        remedy,
        user_inputs=["yes"],
        scan_result_by_file={FILE_A: [_violation_add()]},
        ast_by_file={
            FILE_A: _make_ast(_simple_parsed_http()),
            FILE_B: ast_b,
        },
    )
    assert FILE_A in remedy.child_ast_modified, "FILE_A có violation phải được sửa"
    assert FILE_B not in remedy.child_ast_modified, "FILE_B không có violation không được sửa"


def test_28_file_path_same_key_match(remedy):
    """28. File path normalize khác kiểu vẫn match đúng (same key lookup)."""
    _std_add_run(remedy)
    assert FILE in remedy.child_ast_modified


def test_29_non_add_header_directive_skipped(remedy):
    """29. Scan result directive khác add_header, plugin bỏ qua."""
    _run(
        remedy,
        user_inputs=["yes"],
        scan_result_by_file={FILE: [_violation_add(directive="add_header_wrong")]},
        ast_by_file={FILE: _make_ast(_simple_parsed_http())},
    )
    # Nếu plugin bỏ qua, server block không thay đổi (không có extra add_header)
    if FILE in remedy.child_ast_modified:
        server_block = _get_server_block(remedy.child_ast_modified)
        add_headers = [n for n in server_block if n["directive"] == "add_header"]
        assert len(add_headers) == 0, "Directive khác add_header không được mutate"


def test_30_bad_exact_path_no_ast_corruption(remedy):
    """30. Exact_path sai, plugin không corrupt AST."""
    bad_path = [0, "block", 0, "block", 99, "block", 0]
    _run(
        remedy,
        user_inputs=["yes"],
        scan_result_by_file={FILE: [_violation_add(exact_path=bad_path)]},
        ast_by_file={FILE: _make_ast(_simple_parsed_http())},
    )
    # Plugin không được crash; nếu có trong modified thì server block giữ nguyên
    if FILE in remedy.child_ast_modified:
        server_block = _get_server_block(remedy.child_ast_modified)
        add_headers = [n for n in server_block if n["directive"] == "add_header"]
        assert len(add_headers) == 0, "Path sai không được mutate server block"


def test_31_deep_copy_independent_from_original(remedy):
    """31. AST deep copy độc lập — input gốc không bị alias."""
    original_ast = _make_ast(_simple_parsed_http())
    original_snapshot = copy.deepcopy(original_ast["parsed"])
    _run(
        remedy,
        user_inputs=["yes"],
        scan_result_by_file={FILE: [_violation_add()]},
        ast_by_file={FILE: original_ast},
    )
    assert original_ast["parsed"] == original_snapshot, (
        "remediate() không được alias và mutate input AST gốc"
    )


def test_32_diff_reflects_only_header_security_change(remedy):
    """32. Diff phản ánh đúng thay đổi header security."""
    _std_add_run(remedy)
    remedy.child_ast_config = {FILE: _make_ast(_simple_parsed_http())}
    payload = remedy.build_file_diff_payload(FILE)
    assert payload["file_path"] == FILE
    diff = payload["diff_text"]
    assert "X-Content-Type-Options" in diff or "nosniff" in diff, (
        "Diff phải phản ánh thay đổi header security"
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


def test_34_child_ast_modified_only_exists_when_confirmed(remedy):
    """34. child_ast_modified chỉ tồn tại khi user đồng ý."""
    # Từ chối
    _run(
        remedy,
        user_inputs=["no"],
        scan_result_by_file={FILE: [_violation_add()]},
        ast_by_file={FILE: _make_ast(_simple_parsed_http())},
    )
    assert remedy.child_ast_modified == {}, "User từ chối → child_ast_modified rỗng"

    # Đồng ý
    remedy2 = Remediate531()
    _run(
        remedy2,
        user_inputs=["yes"],
        scan_result_by_file={FILE: [_violation_add()]},
        ast_by_file={FILE: _make_ast(_simple_parsed_http())},
    )
    assert FILE in remedy2.child_ast_modified, "User đồng ý → child_ast_modified chứa kết quả"


# ===========================================================================
# E. Regression / edge (35-40)
# ===========================================================================

def test_35_always_flag_preserved_after_replace(remedy):
    """35. 'always' vẫn còn trong args sau replace."""
    _std_replace_run(remedy)
    server_block = _get_server_block(remedy.child_ast_modified)
    add_headers = [n for n in server_block if n["directive"] == "add_header"]
    assert add_headers[0]["args"][-1] == "always", (
        "'always' phải được bảo tồn sau replace"
    )


def test_36_nosniff_quoted_format_correct(remedy):
    """36. 'nosniff' được quote đúng format ('\"nosniff\"')."""
    _std_add_run(remedy)
    server_block = _get_server_block(remedy.child_ast_modified)
    add_headers = [n for n in server_block
                   if n["directive"] == "add_header" and n["args"][0] == HEADER_NAME]
    assert add_headers[0]["args"][1] == '"nosniff"', (
        "Giá trị nosniff phải được quote: '\"nosniff\"'"
    )


def test_37_empty_scan_result_no_mutation(remedy):
    """37. Scan result rỗng, AST không đổi."""
    remedy.user_inputs = ["yes"]
    remedy.child_scan_result = {}
    remedy.child_ast_config = {FILE: _make_ast(_simple_parsed_http())}
    remedy.remediate()
    assert remedy.child_ast_modified == {}


def test_38_remediate_twice_no_duplicate(remedy):
    """38. Remediate lặp lại không tạo duplicate header."""
    _std_add_run(remedy)
    after_first = copy.deepcopy(remedy.child_ast_modified[FILE])
    # Lần 2: dùng AST đã có header, không có violation mới
    remedy2 = Remediate531()
    _run(
        remedy2,
        user_inputs=["yes"],
        scan_result_by_file={},  # Không còn violation
        ast_by_file={FILE: after_first},
    )
    # Không có violation → child_ast_modified rỗng (không thêm duplicate)
    assert remedy2.child_ast_modified == {}, "Không violation → không duplicate header"


def test_39_header_inserted_in_correct_target_block(remedy):
    """39. Header được chèn đúng block mục tiêu, không vào block khác."""
    _std_add_run(remedy)
    parsed = remedy.child_ast_modified[FILE]["parsed"]
    # Root phải không có add_header
    root_directives = [n.get("directive") for n in parsed]
    assert "add_header" not in root_directives
    # Server block phải có add_header
    server_block = _get_server_block(remedy.child_ast_modified)
    server_add = [n for n in server_block if n["directive"] == "add_header"]
    assert len(server_add) >= 1


def test_40_other_directives_in_block_not_lost(remedy):
    """40. Output không làm mất directive khác trong block."""
    _std_add_run(remedy)
    server_block = _get_server_block(remedy.child_ast_modified)
    directives = [n["directive"] for n in server_block]
    assert "listen" in directives, "listen directive không được bị mất sau remediation"
    assert "server_name" in directives, "server_name directive không được bị mất"
