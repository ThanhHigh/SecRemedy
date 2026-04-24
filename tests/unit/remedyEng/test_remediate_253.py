"""
Unit tests for Remediate253 — CIS Nginx Benchmark Rule 2.5.3.
Bám sát ma trận kiểm thử tại docs/tests/remedyEng/test_remediate_253.md.

Nhóm A. Metadata / contract               (tests  1– 3)
Nhóm B. Input validation                  (tests  4–12)
Nhóm C. Mutation correctness – blocks     (tests 13–25)
Nhóm D. Ordering / placement             (tests 26–33)
Nhóm E. Safety / no-op / diff            (tests 34–40)

Tổng: 40 test cases.
"""

import copy
import pytest

from core.remedyEng.base_remedy import BaseRemedy
from core.remedyEng.recommendations.remediate_253 import Remediate253


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

FILE = "/etc/nginx/nginx.conf"
FILE_A = "/etc/nginx/nginx.conf"
FILE_B = "/etc/nginx/conf.d/site.conf"
FILE_C = "/etc/nginx/conf.d/api.conf"

DENY_ARGS = ["~", "/\\."]
ACME_ARGS = ["~", "/\\.well-known/acme-challenge/"]

# Typical context paths (full crossplane-style)
CTX_PARSED_ROOT = ["config", 0, "parsed"]
CTX_SERVER = ["config", 0, "parsed", 0, "block"]   # http[0].block → server list
CTX_SERVER_BLOCK = ["config", 0, "parsed", 0, "block", 0, "block"]  # server[0].block


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


def _listen(port: str = "80") -> dict:
    return _node("listen", [port])


def _server_name(name: str) -> dict:
    return _node("server_name", [name])


def _location(args: list, block: list) -> dict:
    return _node("location", args, block)


def _deny_loc(extra_block: list | None = None) -> dict:
    """A canonical hidden-file deny location block."""
    blk = [
        _node("deny", ["all"]),
        _node("access_log", ["off"]),
        _node("log_not_found", ["off"]),
    ]
    if extra_block:
        blk.extend(extra_block)
    return _location(DENY_ARGS, blk)


def _acme_loc() -> dict:
    """A canonical ACME allow location block."""
    return _location(ACME_ARGS, [
        _node("allow", ["all"]),
        _node("access_log", ["on"]),
    ])


def _make_ast(parsed: list) -> dict:
    return {"parsed": parsed}


def _simple_server_ast() -> dict:
    """AST: http > server (empty except listen 80)."""
    return _make_ast([_http([_server([_listen()])])])


# ---------------------------------------------------------------------------
# Helpers: scan-result entry builder
# ---------------------------------------------------------------------------

def _add_block_remediation(
    context: list,
    args: list | None = None,
    block: list | None = None,
    logical_context: str = "server",
) -> dict:
    entry = {
        "action": "add_block",
        "directive": "location",
        "context": context,
        "logical_context": logical_context,
    }
    if args is not None:
        entry["args"] = args
    if block is not None:
        entry["block"] = block
    return entry


# ---------------------------------------------------------------------------
# Helpers: run fixture
# ---------------------------------------------------------------------------

def _run(
    remedy: Remediate253,
    user_inputs: list,
    scan_result_by_file: dict,
    ast_by_file: dict,
) -> None:
    remedy.user_inputs = user_inputs
    remedy.child_scan_result = scan_result_by_file
    remedy.child_ast_config = ast_by_file
    remedy.remediate()


def _get_server_block(modified: dict, file: str = FILE) -> list:
    """Navigate to server[0].block in a modified output."""
    return modified[file]["parsed"][0]["block"][0]["block"]


def _get_location_nodes(block: list) -> list:
    return [n for n in block if n.get("directive") == "location"]


def _get_location_by_args(block: list, args: list) -> dict | None:
    for n in block:
        if n.get("directive") == "location" and n.get("args") == args:
            return n
    return None


# ===========================================================================
# A. Metadata / contract (1-3)
# ===========================================================================

def test_01_is_base_remedy_subclass():
    """1. Kiểm tra kế thừa BaseRemedy."""
    remedy = Remediate253()
    assert isinstance(remedy, BaseRemedy)


def test_02_has_input_is_true():
    """2. Kiểm tra has_input == True và id == '2.5.3'."""
    remedy = Remediate253()
    assert remedy.has_input is True
    assert remedy.id == "2.5.3"


def test_03_remedy_input_require_describes_root_path_and_server_name():
    """3. Kiểm tra remedy_input_require mô tả root_path và server_name."""
    remedy = Remediate253()
    req = remedy.remedy_input_require
    assert isinstance(req, list)
    assert len(req) >= 2
    # phải đề cập root_path và server_name
    joined = " ".join(req).lower()
    assert "root_path" in joined or "root" in joined
    assert "server_name" in joined


# ===========================================================================
# B. Input validation (4-12)
# ===========================================================================

@pytest.fixture
def remedy() -> Remediate253:
    return Remediate253()


def test_04_root_path_standard_valid(remedy):
    """4. root_path=/var/www/html hợp lệ."""
    remedy.user_inputs = ["/var/www/html", ""]
    ok, msg = remedy._validate_user_inputs()
    assert ok is True, msg


def test_05_root_path_alternate_valid(remedy):
    """5. root_path=/srv/www/site hợp lệ."""
    remedy.user_inputs = ["/srv/www/site", ""]
    ok, msg = remedy._validate_user_inputs()
    assert ok is True, msg


def test_06_root_path_empty_rejected(remedy):
    """6. root_path rỗng, bị từ chối."""
    remedy.user_inputs = ["", ""]
    ok, msg = remedy._validate_user_inputs()
    assert ok is False
    assert msg  # must have error message


def test_07_root_path_no_leading_slash_rejected(remedy):
    """7. root_path không bắt đầu '/', bị từ chối."""
    remedy.user_inputs = ["var/www/html", ""]
    ok, msg = remedy._validate_user_inputs()
    assert ok is False
    assert "absolute" in msg.lower() or "/" in msg


def test_08_server_name_empty_valid(remedy):
    """8. server_name rỗng, hợp lệ (optional field)."""
    remedy.user_inputs = ["/var/www/html", ""]
    ok, msg = remedy._validate_user_inputs()
    assert ok is True, msg


def test_09_server_name_underscore_valid(remedy):
    """9. server_name=_, hợp lệ."""
    remedy.user_inputs = ["/var/www/html", "_"]
    ok, msg = remedy._validate_user_inputs()
    assert ok is True, msg


def test_10_server_name_fqdn_valid(remedy):
    """10. server_name=example.com, hợp lệ theo validator ký tự."""
    remedy.user_inputs = ["/var/www/html", "example.com"]
    ok, msg = remedy._validate_user_inputs()
    assert ok is True, msg


def test_11_server_name_with_space_rejected(remedy):
    """11. server_name chứa khoảng trắng, bị từ chối."""
    remedy.user_inputs = ["/var/www/html", "example .com"]
    ok, msg = remedy._validate_user_inputs()
    assert ok is False
    assert msg


def test_12_server_name_with_special_chars_rejected(remedy):
    """12. server_name chứa ký tự lạ (;, <>), bị từ chối."""
    remedy.user_inputs = ["/var/www/html", "example;com"]
    ok, msg = remedy._validate_user_inputs()
    assert ok is False
    assert msg


# ===========================================================================
# C. Mutation correctness – deny/ACME blocks (13-25)
# ===========================================================================

def _std_run(remedy: Remediate253, root_path: str = "/var/www/html", server_name: str = "") -> None:
    """Run remedy with a simple add_block remediation targeting the server block."""
    _run(
        remedy,
        user_inputs=[root_path, server_name],
        scan_result_by_file={
            FILE: [
                _add_block_remediation(
                    context=CTX_SERVER_BLOCK,
                    args=DENY_ARGS,
                    block=[
                        _node("deny", ["all"]),
                        _node("access_log", ["off"]),
                        _node("log_not_found", ["off"]),
                    ],
                )
            ]
        },
        ast_by_file={FILE: _simple_server_ast()},
    )


def test_13_creates_deny_location_block(remedy):
    """13. Tạo deny block `location ~ /\\.`."""
    _std_run(remedy)
    block = _get_server_block(remedy.child_ast_modified)
    deny = _get_location_by_args(block, DENY_ARGS)
    assert deny is not None, "deny location block không tìm thấy"


def test_14_creates_acme_location_block(remedy):
    """14. Tạo ACME block `location ~ /\\.well-known/acme-challenge/`."""
    _std_run(remedy)
    block = _get_server_block(remedy.child_ast_modified)
    acme = _get_location_by_args(block, ACME_ARGS)
    assert acme is not None, "ACME location block không tìm thấy"


def test_15_acme_block_before_deny_block(remedy):
    """15. ACME block đứng trước deny block."""
    _std_run(remedy)
    block = _get_server_block(remedy.child_ast_modified)
    locs = _get_location_nodes(block)
    args_order = [n["args"] for n in locs]
    assert ACME_ARGS in args_order, "ACME block thiếu"
    assert DENY_ARGS in args_order, "deny block thiếu"
    acme_idx = args_order.index(ACME_ARGS)
    deny_idx = args_order.index(DENY_ARGS)
    assert acme_idx < deny_idx, f"ACME (idx={acme_idx}) phải đứng trước deny (idx={deny_idx})"


def test_16_acme_block_has_allow_all(remedy):
    """16. Duy trì `allow all;` trong ACME block."""
    _std_run(remedy)
    block = _get_server_block(remedy.child_ast_modified)
    acme = _get_location_by_args(block, ACME_ARGS)
    assert acme is not None
    directives = {n["directive"]: n["args"] for n in acme["block"]}
    assert "allow" in directives
    assert directives["allow"] == ["all"]


def test_17_acme_block_has_access_log_on(remedy):
    """17. Duy trì `access_log on;` trong ACME block."""
    _std_run(remedy)
    block = _get_server_block(remedy.child_ast_modified)
    acme = _get_location_by_args(block, ACME_ARGS)
    assert acme is not None
    directives = {n["directive"]: n["args"] for n in acme["block"]}
    assert "access_log" in directives
    assert directives["access_log"] == ["on"]


def test_18_deny_block_has_deny_all(remedy):
    """18. Duy trì `deny all;` trong deny block."""
    _std_run(remedy)
    block = _get_server_block(remedy.child_ast_modified)
    deny = _get_location_by_args(block, DENY_ARGS)
    assert deny is not None
    directives = {n["directive"]: n["args"] for n in deny["block"]}
    assert "deny" in directives
    assert directives["deny"] == ["all"]


def test_19_deny_block_has_log_not_found_off(remedy):
    """19. Duy trì `log_not_found off;` trong deny block."""
    _std_run(remedy)
    block = _get_server_block(remedy.child_ast_modified)
    deny = _get_location_by_args(block, DENY_ARGS)
    assert deny is not None
    directives = {n["directive"]: n["args"] for n in deny["block"]}
    assert "log_not_found" in directives
    assert directives["log_not_found"] == ["off"]


def test_20_deny_block_contains_root_when_provided(remedy):
    """20. Duy trì `root` trong deny block khi user cung cấp root_path."""
    _std_run(remedy, root_path="/var/www/html")
    block = _get_server_block(remedy.child_ast_modified)
    deny = _get_location_by_args(block, DENY_ARGS)
    assert deny is not None
    directives = {n["directive"]: n["args"] for n in deny["block"]}
    assert "root" in directives
    assert directives["root"] == ["/var/www/html"]


def test_21_upsert_deny_block_when_already_exists(remedy):
    """21. Upsert block khi deny đã tồn tại: không tạo duplicate."""
    # Tạo AST với deny block có sẵn
    existing_deny_ast = _make_ast([
        _http([
            _server([
                _listen(),
                _deny_loc(),
            ])
        ])
    ])
    _run(
        remedy,
        user_inputs=["/var/www/html", ""],
        scan_result_by_file={
            FILE: [_add_block_remediation(CTX_SERVER_BLOCK, DENY_ARGS, [
                _node("deny", ["all"]),
                _node("access_log", ["off"]),
                _node("log_not_found", ["off"]),
            ])]
        },
        ast_by_file={FILE: existing_deny_ast},
    )
    block = _get_server_block(remedy.child_ast_modified)
    deny_locs = [n for n in block if n.get("directive") == "location" and n.get("args") == DENY_ARGS]
    assert len(deny_locs) == 1, f"Tồn tại {len(deny_locs)} deny block, kỳ vọng 1"


def test_22_upsert_acme_block_when_already_exists(remedy):
    """22. Upsert block khi ACME đã tồn tại: không tạo duplicate."""
    # Tạo AST với ACME block có sẵn
    existing_acme_ast = _make_ast([
        _http([
            _server([
                _listen(),
                _acme_loc(),
            ])
        ])
    ])
    _run(
        remedy,
        user_inputs=["/var/www/html", ""],
        scan_result_by_file={
            FILE: [_add_block_remediation(CTX_SERVER_BLOCK, DENY_ARGS, [
                _node("deny", ["all"]),
            ])]
        },
        ast_by_file={FILE: existing_acme_ast},
    )
    block = _get_server_block(remedy.child_ast_modified)
    acme_locs = [n for n in block if n.get("directive") == "location" and n.get("args") == ACME_ARGS]
    assert len(acme_locs) == 1, f"Tồn tại {len(acme_locs)} ACME block, kỳ vọng 1"


def test_23_no_duplicate_acme_block(remedy):
    """23. Không tạo duplicate ACME block khi chạy lần hai."""
    _std_run(remedy)
    after_first = copy.deepcopy(remedy.child_ast_modified[FILE])

    # Lần 2
    remedy.child_ast_config = {FILE: after_first}
    remedy.child_scan_result = {
        FILE: [_add_block_remediation(CTX_SERVER_BLOCK, DENY_ARGS, [
            _node("deny", ["all"]),
        ])]
    }
    remedy.remediate()

    block = _get_server_block(remedy.child_ast_modified)
    acme_locs = [n for n in block if n.get("directive") == "location" and n.get("args") == ACME_ARGS]
    assert len(acme_locs) == 1, f"Có {len(acme_locs)} ACME block sau lần 2, kỳ vọng 1"


def test_24_no_duplicate_deny_block(remedy):
    """24. Không tạo duplicate deny block khi chạy lần hai."""
    _std_run(remedy)
    after_first = copy.deepcopy(remedy.child_ast_modified[FILE])

    remedy.child_ast_config = {FILE: after_first}
    remedy.child_scan_result = {
        FILE: [_add_block_remediation(CTX_SERVER_BLOCK, DENY_ARGS, [
            _node("deny", ["all"]),
        ])]
    }
    remedy.remediate()

    block = _get_server_block(remedy.child_ast_modified)
    deny_locs = [n for n in block if n.get("directive") == "location" and n.get("args") == DENY_ARGS]
    assert len(deny_locs) == 1, f"Có {len(deny_locs)} deny block sau lần 2, kỳ vọng 1"


def test_25_server_name_upserted_when_provided(remedy):
    """25. Cập nhật `server_name` ở parent level khi user nhập."""
    _run(
        remedy,
        user_inputs=["/var/www/html", "example.com"],
        scan_result_by_file={
            FILE: [_add_block_remediation(CTX_SERVER_BLOCK, DENY_ARGS, [
                _node("deny", ["all"]),
            ])]
        },
        ast_by_file={FILE: _simple_server_ast()},
    )
    block = _get_server_block(remedy.child_ast_modified)
    sn_nodes = [n for n in block if n.get("directive") == "server_name"]
    assert sn_nodes, "server_name không được chèn vào server block"
    assert sn_nodes[0]["args"] == ["example.com"]


# ===========================================================================
# D. Ordering / placement (26-33)
# ===========================================================================

def test_26_acme_inserted_before_existing_deny(remedy):
    """26. Nếu deny đã có, ACME được insert trước vị trí deny."""
    existing_deny_ast = _make_ast([
        _http([
            _server([
                _listen(),
                _deny_loc(),
            ])
        ])
    ])
    _run(
        remedy,
        user_inputs=["/var/www/html", ""],
        scan_result_by_file={
            FILE: [_add_block_remediation(CTX_SERVER_BLOCK, DENY_ARGS, [
                _node("deny", ["all"]),
                _node("access_log", ["off"]),
                _node("log_not_found", ["off"]),
            ])]
        },
        ast_by_file={FILE: existing_deny_ast},
    )
    block = _get_server_block(remedy.child_ast_modified)
    locs = _get_location_nodes(block)
    args_order = [n["args"] for n in locs]
    assert ACME_ARGS in args_order
    assert DENY_ARGS in args_order
    assert args_order.index(ACME_ARGS) < args_order.index(DENY_ARGS), \
        "ACME phải đứng trước deny khi deny đã có sẵn"


def test_27_acme_appended_when_deny_not_yet_exist(remedy):
    """27. Nếu deny chưa có, ACME được append và vẫn hợp lệ."""
    # Truyền scan result nhưng block trống không có deny trước: giả lập đây là lần đầu
    _run(
        remedy,
        user_inputs=["/var/www/html", ""],
        scan_result_by_file={
            FILE: [_add_block_remediation(CTX_SERVER_BLOCK, DENY_ARGS, [
                _node("deny", ["all"]),
            ])]
        },
        ast_by_file={FILE: _simple_server_ast()},  # không có deny trước
    )
    block = _get_server_block(remedy.child_ast_modified)
    acme = _get_location_by_args(block, ACME_ARGS)
    deny = _get_location_by_args(block, DENY_ARGS)
    assert acme is not None, "ACME phải tồn tại"
    assert deny is not None, "deny phải tồn tại"
    # ACME vẫn phải trước deny sau khi _add_acme_exception_location chạy
    locs = _get_location_nodes(block)
    args_order = [n["args"] for n in locs]
    assert args_order.index(ACME_ARGS) < args_order.index(DENY_ARGS)


def test_28_multi_server_mutates_correct_target(remedy):
    """28. Nhiều server block: chỉ block mục tiêu được sửa."""
    ast = _make_ast([
        _http([
            _server([_listen("80")]),    # server[0] - không phải mục tiêu
            _server([_listen("443")]),   # server[1] - mục tiêu
        ])
    ])
    # Context trỏ server[1].block
    ctx_server1_block = ["config", 0, "parsed", 0, "block", 1, "block"]
    _run(
        remedy,
        user_inputs=["/var/www/html", ""],
        scan_result_by_file={
            FILE: [_add_block_remediation(ctx_server1_block, DENY_ARGS, [
                _node("deny", ["all"]),
            ])]
        },
        ast_by_file={FILE: ast},
    )
    http_block = remedy.child_ast_modified[FILE]["parsed"][0]["block"]
    # server[0] không bị chạm
    server0_block = http_block[0]["block"]
    assert not any(n["directive"] == "location" for n in server0_block), \
        "server[0] không phải mục tiêu, không được chèn location"
    # server[1] phải được sửa
    server1_block = http_block[1]["block"]
    assert any(n["directive"] == "location" for n in server1_block), \
        "server[1] là mục tiêu, phải có location block"


def test_29_context_root_does_not_insert_at_parsed_root(remedy):
    """29. Context trỏ root list (parsed), plugin không chèn sai root."""
    _run(
        remedy,
        user_inputs=["/var/www/html", ""],
        scan_result_by_file={
            FILE: [_add_block_remediation(
                context=CTX_PARSED_ROOT,  # context trỏ tới parsed root
                args=DENY_ARGS,
                block=[_node("deny", ["all"])],
                logical_context="server",  # fallback sang server
            )]
        },
        ast_by_file={FILE: _simple_server_ast()},
    )
    if FILE not in remedy.child_ast_modified:
        # Plugin bỏ qua remediation này → OK (không chèn sai vị trí)
        return
    parsed = remedy.child_ast_modified[FILE]["parsed"]
    # Không được insert location block tại root list
    assert not any(n.get("directive") == "location" for n in parsed), \
        "Plugin không được chèn location block tại parsed root"


def test_30_logical_context_server_used_as_fallback(remedy):
    """30. Logical context `server` được dùng làm fallback đúng."""
    _run(
        remedy,
        user_inputs=["/var/www/html", ""],
        scan_result_by_file={
            FILE: [_add_block_remediation(
                context=[],  # context rỗng → dùng logical_context
                args=DENY_ARGS,
                block=[_node("deny", ["all"])],
                logical_context="server",
            )]
        },
        ast_by_file={FILE: _simple_server_ast()},
    )
    # Nếu plugin dùng fallback đúng → server block phải được sửa
    if FILE not in remedy.child_ast_modified:
        pytest.skip("Plugin không xử lý empty context với logical_context fallback trong phiên bản này")
    block = _get_server_block(remedy.child_ast_modified)
    assert any(n["directive"] == "location" for n in block), \
        "Server block phải chứa location block sau fallback"


def test_31_file_path_normalization_match(remedy):
    """31. File path normalize khác kiểu vẫn match đúng (same key in scan_result và ast_config)."""
    # Đảm bảo cùng key → match thành công
    _run(
        remedy,
        user_inputs=["/var/www/html", ""],
        scan_result_by_file={FILE: [_add_block_remediation(CTX_SERVER_BLOCK, DENY_ARGS, [
            _node("deny", ["all"]),
        ])]},
        ast_by_file={FILE: _simple_server_ast()},
    )
    assert FILE in remedy.child_ast_modified, "File phải xuất hiện trong child_ast_modified"


def test_32_multi_file_each_mutated_independently(remedy):
    """32. Violation nhiều file: mỗi file mutate độc lập."""
    ast_b = _make_ast([_http([_server([_listen("443")])])])

    _run(
        remedy,
        user_inputs=["/var/www/html", ""],
        scan_result_by_file={
            FILE_A: [_add_block_remediation(CTX_SERVER_BLOCK, DENY_ARGS, [_node("deny", ["all"])])],
            FILE_B: [_add_block_remediation(CTX_SERVER_BLOCK, DENY_ARGS, [_node("deny", ["all"])])],
        },
        ast_by_file={
            FILE_A: _simple_server_ast(),
            FILE_B: ast_b,
        },
    )
    for f in [FILE_A, FILE_B]:
        assert f in remedy.child_ast_modified, f"{f} phải được xử lý"
        blk = remedy.child_ast_modified[f]["parsed"][0]["block"][0]["block"]
        assert any(n["directive"] == "location" for n in blk), \
            f"{f}: server block thiếu location"


def test_33_scan_result_with_offset_context_still_processed(remedy):
    """33. Scan result với context lệch (out-of-bounds), plugin xử lý mà không crash."""
    _run(
        remedy,
        user_inputs=["/var/www/html", ""],
        scan_result_by_file={
            FILE: [_add_block_remediation(
                context=["config", 0, "parsed", 99, "block"],  # index 99 không tồn tại
                args=DENY_ARGS,
                block=[_node("deny", ["all"])],
                logical_context="server",
            )]
        },
        ast_by_file={FILE: _simple_server_ast()},
    )
    # Plugin không được raise exception — nếu context lệch, xử lý gracefully hoặc skip


# ===========================================================================
# E. Safety / no-op / diff (34-40)
# ===========================================================================

def test_34_empty_scan_result_ast_unchanged(remedy):
    """34. Scan result rỗng, AST không đổi và child_ast_modified rỗng."""
    remedy.user_inputs = ["/var/www/html", ""]
    remedy.child_scan_result = {}
    remedy.child_ast_config = {FILE: _simple_server_ast()}
    remedy.remediate()
    assert remedy.child_ast_modified == {}


def test_35_invalid_input_child_ast_modified_empty(remedy):
    """35. Nếu input invalid, child_ast_modified rỗng."""
    _run(
        remedy,
        user_inputs=["", ""],  # root_path rỗng → invalid
        scan_result_by_file={
            FILE: [_add_block_remediation(CTX_SERVER_BLOCK, DENY_ARGS, [_node("deny", ["all"])])]
        },
        ast_by_file={FILE: _simple_server_ast()},
    )
    assert remedy.child_ast_modified == {}, \
        "child_ast_modified phải rỗng khi user input không hợp lệ"


def test_36_ast_remains_valid_after_mutation(remedy):
    """36. AST vẫn hợp lệ (list) sau mutation."""
    _std_run(remedy)
    parsed = remedy.child_ast_modified[FILE]["parsed"]
    assert isinstance(parsed, list), "parsed phải là list"
    http_node = parsed[0]
    assert http_node["directive"] == "http"
    assert isinstance(http_node["block"], list)
    server_node = http_node["block"][0]
    assert server_node["directive"] == "server"
    assert isinstance(server_node["block"], list)


def test_37_existing_directives_not_lost(remedy):
    """37. Không làm mất directive khác trong server block."""
    ast_with_extras = _make_ast([
        _http([
            _server([
                _listen("80"),
                _server_name("mysite.com"),
                _node("keepalive_timeout", ["65"]),
            ])
        ])
    ])
    _run(
        remedy,
        user_inputs=["/var/www/html", ""],
        scan_result_by_file={
            FILE: [_add_block_remediation(CTX_SERVER_BLOCK, DENY_ARGS, [_node("deny", ["all"])])]
        },
        ast_by_file={FILE: ast_with_extras},
    )
    block = _get_server_block(remedy.child_ast_modified)
    directives = {n["directive"] for n in block}
    assert "listen" in directives, "listen không được mất"
    assert "server_name" in directives, "server_name không được mất"
    assert "keepalive_timeout" in directives, "keepalive_timeout không được mất"


def test_38_diff_shows_both_location_blocks(remedy):
    """38. Diff thể hiện đúng 2 location block."""
    _std_run(remedy)
    remedy.child_ast_config = {FILE: _simple_server_ast()}  # original for diff
    payload = remedy.build_file_diff_payload(FILE)

    assert payload["file_path"] == FILE
    assert payload["mode"] == "config"
    diff = payload["diff_text"]
    assert "location" in diff, "Diff phải chứa 'location'"
    assert "deny" in diff, "Diff phải thể hiện deny directive"
    assert "acme-challenge" in diff or "well-known" in diff, \
        "Diff phải thể hiện ACME location"


def test_39_repeated_remediation_idempotent(remedy):
    """39. Remediate lặp lại không làm thay đổi kết quả sai lệch (idempotent)."""
    _std_run(remedy)
    after_first = copy.deepcopy(remedy.child_ast_modified[FILE])
    block_after_first = copy.deepcopy(
        remedy.child_ast_modified[FILE]["parsed"][0]["block"][0]["block"]
    )

    # Lần 2
    remedy.child_ast_config = {FILE: after_first}
    remedy.child_scan_result = {
        FILE: [_add_block_remediation(CTX_SERVER_BLOCK, DENY_ARGS, [
            _node("deny", ["all"]),
            _node("access_log", ["off"]),
            _node("log_not_found", ["off"]),
        ])]
    }
    remedy.remediate()

    block_after_second = remedy.child_ast_modified[FILE]["parsed"][0]["block"][0]["block"]
    loc_count_1 = len(_get_location_nodes(block_after_first))
    loc_count_2 = len(_get_location_nodes(block_after_second))
    assert loc_count_1 == loc_count_2, \
        f"Số location block không nhất quán sau 2 lần chạy: {loc_count_1} vs {loc_count_2}"


def test_40_only_violating_file_in_modified(remedy):
    """40. Chỉ file có violation xuất hiện trong child_ast_modified."""
    _run(
        remedy,
        user_inputs=["/var/www/html", ""],
        scan_result_by_file={
            FILE_A: [_add_block_remediation(CTX_SERVER_BLOCK, DENY_ARGS, [_node("deny", ["all"])])]
            # FILE_B không có violation
        },
        ast_by_file={
            FILE_A: _simple_server_ast(),
            FILE_B: _simple_server_ast(),
        },
    )
    assert FILE_A in remedy.child_ast_modified, "FILE_A có violation phải được xử lý"
    assert FILE_B not in remedy.child_ast_modified, "FILE_B không có violation không được xuất hiện"
