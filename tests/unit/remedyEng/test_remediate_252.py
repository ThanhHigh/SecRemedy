"""
Unit tests for Remediate252 — CIS Nginx Benchmark Rule 2.5.2.
Bám sát ma trận kiểm thử tại docs/tests/remedyEng/test_remediate_252.md.

Nhóm A. Metadata / contract           (tests  1– 3)
Nhóm B. Input validation – URI         (tests  4–13)
Nhóm C. Input validation – root path  (tests 14–19)
Nhóm D. Mutation correctness          (tests 20–30)
Nhóm E. Safety / context / no-op      (tests 31–40)

Tổng: 40 test cases.
"""

import copy
import pytest

from core.remedyEng.base_remedy import BaseRemedy
from core.remedyEng.recommendations.remediate_252 import Remediate252


# ---------------------------------------------------------------------------
# Helpers
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


def _error_page(args: list) -> dict:
    return _node("error_page", args)


def _listen(port: str = "80") -> dict:
    return _node("listen", [port])


def _make_ast(parsed: list) -> dict:
    return {"parsed": parsed}


def _add_remediation(args: list, context: list) -> dict:
    """Tạo một remediation entry action=add cho error_page."""
    return {
        "action": "add",
        "directive": "error_page",
        "args": args,
        "context": context,
        "logical_context": "http",
    }


# Contexts thường dùng
CTX_ROOT = ["config", 0, "parsed"]          # trỏ tới parsed root list
CTX_HTTP = ["config", 0, "parsed", 0, "block"]  # trỏ tới http block list
CTX_SERVER = ["config", 0, "parsed", 0, "block", 0, "block"]  # trỏ tới server block list

FILE = "/etc/nginx/nginx.conf"
FILE_A = "/etc/nginx/nginx.conf"
FILE_B = "/etc/nginx/conf.d/app.conf"
FILE_C = "/etc/nginx/conf.d/api.conf"

ARGS_404 = ["404", "./404.html"]
ARGS_50X = ["500", "502", "503", "504", "./50x.html"]


@pytest.fixture
def remedy() -> Remediate252:
    return Remediate252()


def _simple_ast() -> dict:
    """AST đơn giản: một http block chứa một server block."""
    return _make_ast([_http([_server([_listen()])])])


def _run(remedy: Remediate252, user_inputs: list, scan_result_by_file: dict, ast_by_file: dict) -> None:
    """Thiết lập và chạy remedy.remediate()."""
    remedy.user_inputs = user_inputs
    remedy.child_scan_result = scan_result_by_file
    remedy.child_ast_config = ast_by_file
    remedy.remediate()


# ===========================================================================
# A. Metadata / contract (1-3)
# ===========================================================================

def test_01_is_base_remedy_subclass(remedy):
    """1. Kiểm tra kế thừa BaseRemedy."""
    assert isinstance(remedy, BaseRemedy)


def test_02_has_input_is_true(remedy):
    """2. Kiểm tra has_input == True."""
    assert remedy.has_input is True
    assert remedy.id == "2.5.2"


def test_03_remedy_input_require_has_three_fields(remedy):
    """3. Kiểm tra remedy_input_require có đủ 3 input."""
    req = remedy.remedy_input_require
    assert "error_page_40x" in req
    assert "error_page_50x" in req
    assert "location_50x_root" in req
    assert len(req) == 3


# ===========================================================================
# B. Input validation – error page URI (4-13)
# ===========================================================================

def test_04_err_40x_valid_absolute_uri(remedy):
    """4. err_40x=/404.html hợp lệ."""
    remedy.user_inputs = ["/404.html", "", ""]
    ok, msg = remedy._validate_user_inputs()
    assert ok is True


def test_05_err_50x_valid_absolute_uri(remedy):
    """5. err_50x=/50x.html hợp lệ."""
    remedy.user_inputs = ["", "/50x.html", ""]
    ok, msg = remedy._validate_user_inputs()
    assert ok is True


def test_06_both_uri_valid(remedy):
    """6. Cả hai URI đều hợp lệ."""
    remedy.user_inputs = ["/404.html", "/50x.html", ""]
    ok, msg = remedy._validate_user_inputs()
    assert ok is True


def test_07_empty_50x_uri_still_valid_if_40x_present(remedy):
    """7. URI rỗng cho 50x, 40x hợp lệ → pass (một trong hai đủ)."""
    remedy.user_inputs = ["/404.html", "", ""]
    ok, msg = remedy._validate_user_inputs()
    assert ok is True


def test_08_empty_40x_uri_still_valid_if_50x_present(remedy):
    """8. URI rỗng cho 40x, 50x hợp lệ → pass (một trong hai đủ)."""
    remedy.user_inputs = ["", "/50x.html", ""]
    ok, msg = remedy._validate_user_inputs()
    assert ok is True


def test_09_both_uri_empty_rejected(remedy):
    """9. Cả hai URI rỗng, bị từ chối."""
    remedy.user_inputs = ["", "", "/var/www/html"]
    ok, msg = remedy._validate_user_inputs()
    assert ok is False
    assert "At least one error page path required" in msg


def test_10_40x_uri_dot_slash_prefix_rejected(remedy):
    """10. URI bắt đầu bằng './' cho 40x, bị từ chối."""
    remedy.user_inputs = ["./404.html", "/50x.html", ""]
    ok, msg = remedy._validate_user_inputs()
    assert ok is False
    assert "Invalid 40x" in msg


def test_11_50x_uri_dot_slash_prefix_rejected(remedy):
    """11. URI bắt đầu bằng './' cho 50x, bị từ chối."""
    remedy.user_inputs = ["/404.html", "./50x.html", ""]
    ok, msg = remedy._validate_user_inputs()
    assert ok is False
    assert "Invalid 50x" in msg


def test_12_40x_uri_no_leading_slash_rejected(remedy):
    """12. URI không bắt đầu bằng '/', bị từ chối."""
    remedy.user_inputs = ["404.html", "", ""]
    ok, msg = remedy._validate_user_inputs()
    assert ok is False
    assert "Invalid 40x" in msg


def test_13_50x_uri_with_scheme_rejected(remedy):
    """13. URI chứa '://' (scheme), bị từ chối."""
    remedy.user_inputs = ["/404.html", "https://example.com/50x.html", ""]
    ok, msg = remedy._validate_user_inputs()
    assert ok is False
    assert "Invalid 50x" in msg


# ===========================================================================
# C. Input validation – root path (14-19)
# ===========================================================================

def test_14_root_50x_standard_path_valid(remedy):
    """14. root_50x=/var/www/html/errors hợp lệ."""
    remedy.user_inputs = ["/404.html", "/50x.html", "/var/www/html/errors"]
    ok, msg = remedy._validate_user_inputs()
    assert ok is True


def test_15_root_50x_alternate_path_valid(remedy):
    """15. root_50x=/srv/www/errors hợp lệ."""
    remedy.user_inputs = ["", "/50x.html", "/srv/www/errors"]
    ok, msg = remedy._validate_user_inputs()
    assert ok is True


def test_16_empty_root_50x_valid_no_location_block(remedy):
    """16. root_50x rỗng → valid, chỉ tạo error_page, không tạo location block."""
    remedy.user_inputs = ["", "/50x.html", ""]
    ok, msg = remedy._validate_user_inputs()
    assert ok is True

    _run(remedy, ["", "/50x.html", ""],
         {FILE: [_add_remediation(ARGS_50X, CTX_ROOT)]},
         {FILE: _simple_ast()})

    server_block = remedy.child_ast_modified[FILE]["parsed"][0]["block"][0]["block"]
    assert not any(n["directive"] == "location" for n in server_block)


def test_17_root_50x_no_leading_slash_rejected(remedy):
    """17. root_50x không bắt đầu '/', bị từ chối."""
    remedy.user_inputs = ["/404.html", "/50x.html", "var/www/html"]
    ok, msg = remedy._validate_user_inputs()
    assert ok is False
    assert "Invalid 50x root" in msg


def test_18_root_50x_with_whitespace_rejected(remedy):
    """18. root_50x chứa khoảng trắng, bị từ chối."""
    remedy.user_inputs = ["/404.html", "/50x.html", "/var/www/html errors"]
    ok, msg = remedy._validate_user_inputs()
    assert ok is False
    assert "Invalid 50x root" in msg


def test_19_root_50x_with_scheme_rejected(remedy):
    """19. root_50x chứa scheme 'http://', bị từ chối."""
    remedy.user_inputs = ["/404.html", "/50x.html", "http:///var/www/html"]
    ok, msg = remedy._validate_user_inputs()
    assert ok is False
    assert "Invalid 50x root" in msg


# ===========================================================================
# D. Mutation correctness (20-30)
# ===========================================================================

def test_20_adds_error_page_404(remedy):
    """20. Thêm error_page 404 /404.html;"""
    _run(remedy, ["/custom_404.html", "", ""],
         {FILE: [_add_remediation(["404", "./404.html"], CTX_ROOT)]},
         {FILE: _simple_ast()})

    http_block = remedy.child_ast_modified[FILE]["parsed"][0]["block"]
    ep_args = [n["args"] for n in http_block if n["directive"] == "error_page"]
    assert ["404", "/custom_404.html"] in ep_args


def test_21_adds_error_page_50x(remedy):
    """21. Thêm error_page 500 502 503 504 /50x.html;"""
    _run(remedy, ["", "/custom_50x.html", ""],
         {FILE: [_add_remediation(ARGS_50X, CTX_ROOT)]},
         {FILE: _simple_ast()})

    http_block = remedy.child_ast_modified[FILE]["parsed"][0]["block"]
    ep_args = [n["args"] for n in http_block if n["directive"] == "error_page"]
    assert ["500", "502", "503", "504", "/custom_50x.html"] in ep_args


def test_22_adds_both_error_page_directives(remedy):
    """22. Add cả 2 error_page directives trong cùng file."""
    _run(remedy, ["/404.html", "/50x.html", ""],
         {FILE: [
             _add_remediation(ARGS_404, CTX_ROOT),
             _add_remediation(ARGS_50X, CTX_ROOT),
         ]},
         {FILE: _simple_ast()})

    http_block = remedy.child_ast_modified[FILE]["parsed"][0]["block"]
    ep_args = [n["args"] for n in http_block if n["directive"] == "error_page"]
    assert ["404", "/404.html"] in ep_args
    assert ["500", "502", "503", "504", "/50x.html"] in ep_args


def test_23_upserts_existing_404_error_page(remedy):
    """23. Upsert error_page 404 nếu đã tồn tại (không tạo duplicate)."""
    ast = _make_ast([
        _http([
            _error_page(["404", "/old_404.html"]),
            _server([_listen()])
        ])
    ])
    _run(remedy, ["/new_404.html", "", ""],
         {FILE: [_add_remediation(["404", "./old_404.html"], CTX_HTTP)]},
         {FILE: ast})

    http_block = remedy.child_ast_modified[FILE]["parsed"][0]["block"]
    ep_args = [n["args"] for n in http_block if n["directive"] == "error_page"]
    assert ep_args == [["404", "/new_404.html"]]


def test_24_upserts_existing_50x_error_page(remedy):
    """24. Upsert error_page 50x nếu đã tồn tại."""
    ast = _make_ast([
        _http([
            _error_page(["500", "502", "503", "504", "/old_50x.html"]),
            _server([_listen()])
        ])
    ])
    _run(remedy, ["", "/new_50x.html", ""],
         {FILE: [_add_remediation(["500", "502", "503", "504", "./old_50x.html"], CTX_HTTP)]},
         {FILE: ast})

    http_block = remedy.child_ast_modified[FILE]["parsed"][0]["block"]
    ep_args = [n["args"] for n in http_block if n["directive"] == "error_page"]
    assert ep_args == [["500", "502", "503", "504", "/new_50x.html"]]


def test_25_creates_new_location_50x(remedy):
    """25. Tạo location = /50x.html mới trong server block."""
    _run(remedy, ["", "/50x.html", "/var/www/html"],
         {FILE: [_add_remediation(ARGS_50X, CTX_ROOT)]},
         {FILE: _simple_ast()})

    server_block = remedy.child_ast_modified[FILE]["parsed"][0]["block"][0]["block"]
    loc_nodes = [n for n in server_block if n["directive"] == "location"]
    assert len(loc_nodes) == 1
    assert loc_nodes[0]["args"] == ["=", "/50x.html"]


def test_26_location_50x_has_correct_root(remedy):
    """26. location = /50x.html có root đúng."""
    _run(remedy, ["", "/50x.html", "/var/www/html/errors"],
         {FILE: [_add_remediation(ARGS_50X, CTX_ROOT)]},
         {FILE: _simple_ast()})

    server_block = remedy.child_ast_modified[FILE]["parsed"][0]["block"][0]["block"]
    loc = next(n for n in server_block if n["directive"] == "location")
    root_node = next(n for n in loc["block"] if n["directive"] == "root")
    assert root_node["args"] == ["/var/www/html/errors"]


def test_27_location_50x_has_internal_directive(remedy):
    """27. location = /50x.html có internal;"""
    _run(remedy, ["", "/50x.html", "/var/www/html"],
         {FILE: [_add_remediation(ARGS_50X, CTX_ROOT)]},
         {FILE: _simple_ast()})

    server_block = remedy.child_ast_modified[FILE]["parsed"][0]["block"][0]["block"]
    loc = next(n for n in server_block if n["directive"] == "location")
    directives = [n["directive"] for n in loc["block"]]
    assert "internal" in directives


def test_28_location_50x_not_duplicated_on_rerun(remedy):
    """28. location 50x không bị duplicate khi gọi lại."""
    _run(remedy, ["", "/50x.html", "/var/www/html"],
         {FILE: [_add_remediation(ARGS_50X, CTX_ROOT)]},
         {FILE: _simple_ast()})

    after_first = copy.deepcopy(remedy.child_ast_modified[FILE])
    # Chạy lần 2: context trỏ vào server block (đã có location)
    remedy.child_ast_config = {FILE: after_first}
    remedy.child_scan_result = {
        FILE: [_add_remediation(["500", "502", "503", "504", "./50x.html"], CTX_SERVER)]
    }
    remedy.remediate()

    server_block = remedy.child_ast_modified[FILE]["parsed"][0]["block"][0]["block"]
    loc_nodes = [n for n in server_block if n["directive"] == "location"]
    assert len(loc_nodes) == 1


def test_29_root_updated_when_root_50x_changes(remedy):
    """29. Khi root_50x đổi, root trong location được cập nhật."""
    # Lần 1: root = /var/www/html
    _run(remedy, ["", "/50x.html", "/var/www/html"],
         {FILE: [_add_remediation(ARGS_50X, CTX_ROOT)]},
         {FILE: _simple_ast()})

    after_first = copy.deepcopy(remedy.child_ast_modified[FILE])

    # Lần 2: root mới = /srv/errors, context trỏ server block
    remedy.child_ast_config = {FILE: after_first}
    remedy.child_scan_result = {
        FILE: [_add_remediation(["500", "502", "503", "504", "./50x.html"], CTX_SERVER)]
    }
    remedy.user_inputs = ["", "/50x.html", "/srv/errors"]
    remedy.remediate()

    server_block = remedy.child_ast_modified[FILE]["parsed"][0]["block"][0]["block"]
    loc = next(n for n in server_block if n["directive"] == "location")
    root_node = next(n for n in loc["block"] if n["directive"] == "root")
    assert root_node["args"] == ["/srv/errors"]


def test_30_location_args_follow_err_50x_uri(remedy):
    """30. Khi err_50x đổi, location args đổi tương ứng."""
    _run(remedy, ["", "/error.html", "/var/www/html"],
         {FILE: [_add_remediation(ARGS_50X, CTX_ROOT)]},
         {FILE: _simple_ast()})

    server_block = remedy.child_ast_modified[FILE]["parsed"][0]["block"][0]["block"]
    loc_nodes = [n for n in server_block if n["directive"] == "location"]
    assert len(loc_nodes) == 1
    assert loc_nodes[0]["args"] == ["=", "/error.html"]


# ===========================================================================
# E. Safety / context / no-op (31-40)
# ===========================================================================

def test_31_empty_context_fallback_to_http_or_server(remedy):
    """31. Context rỗng, plugin fallback sang http hoặc server (không insert vào root)."""
    _run(remedy, ["/404.html", "", ""],
         {FILE: [_add_remediation(ARGS_404, [])]},  # empty context
         {FILE: _simple_ast()})

    parsed = remedy.child_ast_modified[FILE]["parsed"]
    # Không được insert tại root list
    assert not any(n["directive"] == "error_page" for n in parsed)
    # Phải insert vào http block
    http_block = parsed[0]["block"]
    assert any(n["directive"] == "error_page" for n in http_block)


def test_32_context_pointing_to_wrong_directive_no_root_insert(remedy):
    """32. Context trỏ tới index ngoài phạm vi parsed → không chèn sai root."""
    _run(remedy, ["/404.html", "", ""],
         {FILE: [_add_remediation(ARGS_404, ["config", 0, "parsed", 99])]},  # out of bounds
         {FILE: _simple_ast()})

    parsed = remedy.child_ast_modified[FILE]["parsed"]
    # Dù fallback, error_page vẫn không nằm tại root list
    assert not any(n["directive"] == "error_page" for n in parsed)


def test_33_multi_server_mutates_correct_target_block(remedy):
    """33. AST có nhiều server block, mutate đúng block target."""
    ast = _make_ast([
        _http([
            _server([_listen("80")]),
            _server([_listen("443")]),
        ])
    ])
    # Scan result trỏ server[1] block list
    ctx_server1 = ["config", 0, "parsed", 0, "block", 1, "block"]
    _run(remedy, ["/404.html", "", ""],
         {FILE: [_add_remediation(ARGS_404, ctx_server1)]},
         {FILE: ast})

    http_block = remedy.child_ast_modified[FILE]["parsed"][0]["block"]
    # server[0] không bị chạm
    assert not any(n["directive"] == "error_page" for n in http_block[0]["block"])
    # server[1] có error_page
    assert any(n["directive"] == "error_page" for n in http_block[1]["block"])


def test_34_file_path_in_scan_result_must_match_ast_config_key(remedy):
    """34. File path normalize: scan_result key phải khớp ast_config key."""
    remedy.user_inputs = ["/404.html", "", ""]
    # child_scan_result và child_ast_config dùng cùng key → match
    remedy.child_scan_result = {
        FILE: [_add_remediation(ARGS_404, CTX_ROOT)]
    }
    remedy.child_ast_config = {
        FILE: _simple_ast()
    }
    remedy.remediate()

    assert FILE in remedy.child_ast_modified


def test_35_empty_scan_result_no_modification(remedy):
    """35. Scan result rỗng thì AST không đổi."""
    remedy.user_inputs = ["/404.html", "/50x.html", "/var/www/html"]
    remedy.child_scan_result = {}
    remedy.child_ast_config = {FILE: _simple_ast()}
    remedy.remediate()

    assert remedy.child_ast_modified == {}


def test_36_only_violating_file_appears_in_modified(remedy):
    """36. Chỉ file có violation mới xuất hiện trong child_ast_modified."""
    _run(remedy, ["/404.html", "", ""],
         {FILE_A: [_add_remediation(ARGS_404, CTX_ROOT)]},
         {
             FILE_A: _simple_ast(),
             FILE_B: _simple_ast(),  # có AST nhưng không có violation
         })

    assert FILE_A in remedy.child_ast_modified
    assert FILE_B not in remedy.child_ast_modified


def test_37_only_40x_valid_creates_only_404_error_page(remedy):
    """37. Khi chỉ 40x hợp lệ, plugin vẫn tạo đúng 40x error_page."""
    _run(remedy, ["/404.html", "", ""],
         {FILE: [_add_remediation(ARGS_404, CTX_ROOT)]},
         {FILE: _simple_ast()})

    http_block = remedy.child_ast_modified[FILE]["parsed"][0]["block"]
    ep_args = [n["args"] for n in http_block if n["directive"] == "error_page"]
    assert len(ep_args) == 1
    assert ep_args[0][0] == "404"


def test_38_only_50x_valid_creates_only_50x_error_page(remedy):
    """38. Khi chỉ 50x hợp lệ, plugin vẫn tạo đúng 50x error_page."""
    _run(remedy, ["", "/50x.html", ""],
         {FILE: [_add_remediation(ARGS_50X, CTX_ROOT)]},
         {FILE: _simple_ast()})

    http_block = remedy.child_ast_modified[FILE]["parsed"][0]["block"]
    ep_args = [n["args"] for n in http_block if n["directive"] == "error_page"]
    assert len(ep_args) == 1
    assert ep_args[0][0] == "500"


def test_39_no_location_block_when_root_50x_empty(remedy):
    """39. Không chèn location 50x nếu root_50x rỗng."""
    _run(remedy, ["", "/50x.html", ""],
         {FILE: [_add_remediation(ARGS_50X, CTX_ROOT)]},
         {FILE: _simple_ast()})

    server_block = remedy.child_ast_modified[FILE]["parsed"][0]["block"][0]["block"]
    assert not any(n["directive"] == "location" for n in server_block)


def test_40_diff_shows_added_error_page_without_breaking_structure(remedy):
    """40. Diff thể hiện chính xác add/upsert mà không phá cấu trúc block."""
    _run(remedy, ["/404.html", "/50x.html", "/var/www/html"],
         {FILE: [
             _add_remediation(ARGS_404, CTX_ROOT),
             _add_remediation(ARGS_50X, CTX_ROOT),
         ]},
         {FILE: _simple_ast()})

    remedy.child_ast_config = {FILE: _simple_ast()}  # original (before remediate) for diff
    payload = remedy.build_file_diff_payload(FILE)

    assert payload["file_path"] == FILE
    assert payload["mode"] == "config"
    diff = payload["diff_text"]
    assert "error_page" in diff
    # Không được xoá khối http/server
    assert "http" in diff or "server" in diff or "listen" in diff
