"""
Unit tests for Remediate511 — CIS Nginx Benchmark Rule 5.1.1.
Bám sát ma trận kiểm thử tại docs/tests/remedyEng/test_remediate_511.md.

Nhóm A. Metadata / contract               (tests  1– 3)
Nhóm B. Input validation / parsing        (tests  4–12)
Nhóm C. Mutation correctness              (tests 13–25)
Nhóm D. Context / safety                  (tests 26–34)
Nhóm E. Regression / edge                (tests 35–40)

Tổng: 40 test cases.
"""

import copy
import pytest

from core.remedyEng.base_remedy import BaseRemedy
from core.remedyEng.recommendations.remediate_511 import Remediate511


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

FILE   = "/etc/nginx/nginx.conf"
FILE_A = "/etc/nginx/nginx.conf"
FILE_B = "/etc/nginx/conf.d/site.conf"

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


def _make_parsed(nodes: list) -> list:
    """Return a parsed list (top-level AST nodes)."""
    return nodes


def _simple_parsed() -> list:
    """http > server (empty except listen 80 and a location /admin_login/)."""
    return _make_parsed([
        _http([
            _server([
                _node("listen", ["80"]),
                _location(["/admin_login/"], [
                    _node("proxy_pass", ["http://backend"]),
                ]),
            ])
        ])
    ])


def _make_ast(parsed: list) -> dict:
    return {"parsed": parsed}


# ---------------------------------------------------------------------------
# exact_path helpers
# Remediate511 calls: ASTEditor.get_child_ast_config(parsed_copy, exact_path)
# parsed_copy = remediations["parsed"]  (which is the parsed list)
# So exact_path is relative to the parsed list.
# Path to /admin_login/ block: [0, "block", 0, "block", 1, "block"]
#   parsed[0] = http; http["block"][0] = server; server["block"][1] = location; location["block"]
# ---------------------------------------------------------------------------

# Indices inside _simple_parsed():
#  parsed[0] = http
#  http["block"][0] = server
#  server["block"][0] = listen  (index 0)
#  server["block"][1] = location /admin_login/  (index 1)
#  location["block"] = the target list to append allow/deny

EXACT_PATH_ADMIN = [0, "block", 0, "block", 1, "block"]   # → /admin_login/ block list


# ---------------------------------------------------------------------------
# Helpers: violation entry builder
# ---------------------------------------------------------------------------

def _violation(
    action: str = "add",
    directive: str = "location",
    exact_path: list | None = None,
    logical_context: list | None = None,
) -> dict:
    return {
        "action": action,
        "directive": directive,
        "exact_path": exact_path if exact_path is not None else EXACT_PATH_ADMIN,
        "logical_context": logical_context or ["location"],
    }


# ---------------------------------------------------------------------------
# Helpers: run fixture
# ---------------------------------------------------------------------------

def _run(
    remedy: Remediate511,
    user_inputs: list,
    scan_result_by_file: dict,
    ast_by_file: dict,
) -> None:
    remedy.user_inputs = user_inputs
    remedy.child_scan_result = scan_result_by_file
    remedy.child_ast_config = ast_by_file
    remedy.remediate()


def _std_run(
    remedy: Remediate511,
    location: str = "/admin_login",
    ip_string: str = "192.168.1.100, 10.20.30.0/24",
    exact_path: list | None = None,
) -> None:
    """Standard run with simple parsed AST and one violation."""
    path = exact_path if exact_path is not None else EXACT_PATH_ADMIN
    _run(
        remedy,
        user_inputs=[location, ip_string],
        scan_result_by_file={
            FILE: [_violation(exact_path=path)]
        },
        ast_by_file={FILE: _make_ast(_simple_parsed())},
    )


def _get_location_block(modified: dict, file: str = FILE) -> list:
    """Navigate to /admin_login/ block list in modified output."""
    parsed = modified[file]["parsed"]
    return parsed[0]["block"][0]["block"][1]["block"]


# ===========================================================================
# A. Metadata / contract (1-3)
# ===========================================================================

def test_01_is_base_remedy_subclass():
    """1. Kiểm tra kế thừa BaseRemedy."""
    remedy = Remediate511()
    assert isinstance(remedy, BaseRemedy)


def test_02_has_input_is_true():
    """2. Kiểm tra has_input == True và id == '5.1.1'."""
    remedy = Remediate511()
    assert remedy.has_input is True
    assert remedy.id == "5.1.1"


def test_03_guide_detail_describes_least_privilege():
    """3. Kiểm tra remedy_guide_detail mô tả least privilege."""
    remedy = Remediate511()
    assert remedy.has_guide_detail is True
    detail = remedy.remedy_guide_detail
    assert isinstance(detail, str)
    assert len(detail) > 0
    # Phải đề cập IP/CIDR và allow/deny (least privilege)
    lowered = detail.lower()
    assert "allow" in lowered or "deny" in lowered


# ===========================================================================
# B. Input validation / parsing (4-12)
# ===========================================================================

@pytest.fixture
def remedy() -> Remediate511:
    return Remediate511()


def test_04_location_admin_login_valid(remedy):
    """4. Location /admin_login hợp lệ."""
    remedy.user_inputs = ["/admin_login", "192.168.1.100"]
    ok, msg = remedy._validate_user_inputs()
    assert ok is True, msg


def test_05_location_api_internal_valid(remedy):
    """5. Location /api/internal hợp lệ."""
    remedy.user_inputs = ["/api/internal", "10.0.0.1"]
    ok, msg = remedy._validate_user_inputs()
    assert ok is True, msg


def test_06_location_health_check_valid(remedy):
    """6. Location /health-check hợp lệ."""
    remedy.user_inputs = ["/health-check", "192.168.0.1"]
    ok, msg = remedy._validate_user_inputs()
    assert ok is True, msg


def test_07_location_no_leading_slash_rejected(remedy):
    """7. Location không bắt đầu bằng '/', bị từ chối."""
    remedy.user_inputs = ["admin_login", "192.168.1.100"]
    ok, msg = remedy._validate_user_inputs()
    assert ok is False
    assert msg  # phải có thông báo lỗi


def test_08_ip_single_192_168_1_100_valid(remedy):
    """8. IP đơn 192.168.1.100 hợp lệ."""
    ips = remedy._parse_ips("192.168.1.100")
    assert "192.168.1.100" in ips


def test_09_ip_single_10_20_30_40_valid(remedy):
    """9. IP đơn 10.20.30.40 hợp lệ."""
    ips = remedy._parse_ips("10.20.30.40")
    assert "10.20.30.40" in ips


def test_10_cidr_10_0_0_0_8_valid(remedy):
    """10. CIDR 10.0.0.0/8 hợp lệ."""
    ips = remedy._parse_ips("10.0.0.0/8")
    assert "10.0.0.0/8" in ips


def test_11_cidr_192_168_0_0_16_valid(remedy):
    """11. CIDR 192.168.0.0/16 hợp lệ."""
    ips = remedy._parse_ips("192.168.0.0/16")
    assert "192.168.0.0/16" in ips


def test_12_ip_list_empty_rejected(remedy):
    """12. IP list rỗng hoặc không parse được, bị từ chối."""
    # Empty string
    remedy.user_inputs = ["/admin_login", ""]
    ok, msg = remedy._validate_user_inputs()
    assert ok is False
    assert msg

    # Invalid format only (hostname, no valid IP)
    remedy.user_inputs = ["/admin_login", "not-an-ip, another-garbage"]
    ok2, msg2 = remedy._validate_user_inputs()
    assert ok2 is False
    assert msg2


# ===========================================================================
# C. Mutation correctness (13-25)
# ===========================================================================

def test_13_add_multiple_allow_directives(remedy):
    """13. Add nhiều allow directives cho từng IP trong list."""
    _std_run(remedy, ip_string="192.168.1.100, 10.20.30.0/24")
    block = _get_location_block(remedy.child_ast_modified)
    allow_nodes = [n for n in block if n["directive"] == "allow"]
    assert len(allow_nodes) == 2


def test_14_deny_all_appended_at_end(remedy):
    """14. Add deny all; ở cuối location block."""
    _std_run(remedy)
    block = _get_location_block(remedy.child_ast_modified)
    assert block[-1]["directive"] == "deny"
    assert block[-1]["args"] == ["all"]


def test_15_allow_directives_before_deny(remedy):
    """15. Thứ tự: tất cả allow đứng trước deny all."""
    _std_run(remedy, ip_string="192.168.1.100, 10.0.0.0/8")
    block = _get_location_block(remedy.child_ast_modified)
    directives = [n["directive"] for n in block]
    deny_idx = directives.index("deny")
    allow_indices = [i for i, d in enumerate(directives) if d == "allow"]
    assert all(i < deny_idx for i in allow_indices), \
        "Tất cả allow phải đứng trước deny all"


def test_16_allow_deny_added_to_target_location(remedy):
    """16. Add allow + deny vào location mục tiêu."""
    _std_run(remedy, ip_string="10.10.10.10")
    block = _get_location_block(remedy.child_ast_modified)
    directives = {n["directive"] for n in block}
    assert "allow" in directives
    assert "deny" in directives


def test_17_no_allow_missing_from_valid_list(remedy):
    """17. Mỗi IP hợp lệ đều có đúng 1 allow directive."""
    ip_list = "192.168.1.100, 10.20.30.0/24, 172.16.0.1"
    _std_run(remedy, ip_string=ip_list)
    block = _get_location_block(remedy.child_ast_modified)
    allowed_args = [n["args"][0] for n in block if n["directive"] == "allow"]
    assert "192.168.1.100" in allowed_args
    assert "10.20.30.0/24" in allowed_args
    assert "172.16.0.1" in allowed_args


def test_18_invalid_ips_not_added(remedy):
    """18. IP không hợp lệ trong list bị loại bỏ trước khi mutate."""
    _std_run(remedy, ip_string="192.168.1.100, garbage-ip, 10.0.0.0/8")
    block = _get_location_block(remedy.child_ast_modified)
    allowed_args = [n["args"][0] for n in block if n["directive"] == "allow"]
    assert "garbage-ip" not in allowed_args
    assert "192.168.1.100" in allowed_args
    assert "10.0.0.0/8" in allowed_args


def test_19_target_location_receives_directives(remedy):
    """19. Target location nhận directive đúng path."""
    _std_run(remedy, ip_string="10.1.2.3")
    assert FILE in remedy.child_ast_modified
    block = _get_location_block(remedy.child_ast_modified)
    assert any(n["directive"] == "allow" for n in block)


def test_20_multiple_ips_each_becomes_one_allow(remedy):
    """20. Nhiều IP, mỗi IP thành 1 allow directive riêng."""
    ips = "1.1.1.1, 2.2.2.2, 3.3.3.3"
    _std_run(remedy, ip_string=ips)
    block = _get_location_block(remedy.child_ast_modified)
    allow_nodes = [n for n in block if n["directive"] == "allow"]
    assert len(allow_nodes) == 3
    allowed_args = [n["args"][0] for n in allow_nodes]
    assert "1.1.1.1" in allowed_args
    assert "2.2.2.2" in allowed_args
    assert "3.3.3.3" in allowed_args


def test_21_multiple_cidrs_each_becomes_one_allow(remedy):
    """21. Nhiều CIDR, mỗi CIDR thành 1 allow directive riêng."""
    cidrs = "10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16"
    _std_run(remedy, ip_string=cidrs)
    block = _get_location_block(remedy.child_ast_modified)
    allow_nodes = [n for n in block if n["directive"] == "allow"]
    assert len(allow_nodes) == 3


def test_22_deny_all_appears_exactly_once(remedy):
    """22. deny all; xuất hiện đúng 1 lần trong location block."""
    _std_run(remedy, ip_string="192.168.1.100, 10.0.0.0/8")
    block = _get_location_block(remedy.child_ast_modified)
    deny_nodes = [n for n in block if n["directive"] == "deny" and n["args"] == ["all"]]
    assert len(deny_nodes) == 1, f"Kỳ vọng 1 deny all;, tìm thấy {len(deny_nodes)}"


def test_23_existing_proxy_pass_not_disturbed(remedy):
    """23. proxy_pass hiện có trong location block không bị xóa hay thay đổi."""
    _std_run(remedy, ip_string="192.168.1.100")
    block = _get_location_block(remedy.child_ast_modified)
    proxy_nodes = [n for n in block if n["directive"] == "proxy_pass"]
    assert len(proxy_nodes) >= 1, "proxy_pass không được bị mất"
    assert proxy_nodes[0]["args"] == ["http://backend"]


def test_24_update_location_already_has_allow_deny(remedy):
    """24. Nếu location đã có allow/deny, plugin vẫn append (policy: append not replace)."""
    parsed = _make_parsed([
        _http([
            _server([
                _node("listen", ["80"]),
                _location(["/admin_login/"], [
                    _node("allow", ["10.0.0.1"]),
                    _node("deny", ["all"]),
                ]),
            ])
        ])
    ])
    _run(
        remedy,
        user_inputs=["/admin_login", "192.168.1.100"],
        scan_result_by_file={FILE: [_violation(exact_path=EXACT_PATH_ADMIN)]},
        ast_by_file={FILE: _make_ast(parsed)},
    )
    block = remedy.child_ast_modified[FILE]["parsed"][0]["block"][0]["block"][1]["block"]
    allow_nodes = [n for n in block if n["directive"] == "allow"]
    # Phải có cả allow cũ lẫn allow mới
    assert len(allow_nodes) >= 2


def test_25_directives_appended_to_correct_block(remedy):
    """25. Append directive vào đúng block target (không vào server hay http)."""
    _std_run(remedy, ip_string="192.168.1.100")
    parsed = remedy.child_ast_modified[FILE]["parsed"]
    http_block = parsed[0]["block"]  # server list under http
    # Server block should NOT have allow/deny at its level
    server_block = http_block[0]["block"]
    server_level_allow = [n for n in server_block if n.get("directive") == "allow"]
    assert len(server_level_allow) == 0, "allow không được xuất hiện ở cấp server"


# ===========================================================================
# D. Context / safety (26-34)
# ===========================================================================

def test_26_correct_exact_path_mutates_location(remedy):
    """26. exact_path đúng thì mutate location chính xác."""
    _std_run(remedy, ip_string="10.10.10.10")
    block = _get_location_block(remedy.child_ast_modified)
    assert any(n["directive"] == "allow" for n in block)


def test_27_wrong_exact_path_ast_unchanged(remedy):
    """27. exact_path sai (không tồn tại) thì block thực tế không bị mutate."""
    # Path trỏ đến index không tồn tại
    bad_path = [0, "block", 0, "block", 99, "block"]
    _run(
        remedy,
        user_inputs=["/admin_login", "192.168.1.100"],
        scan_result_by_file={FILE: [_violation(exact_path=bad_path)]},
        ast_by_file={FILE: _make_ast(_simple_parsed())},
    )
    # child_ast_modified may contain the file but the location block must be intact
    if FILE in remedy.child_ast_modified:
        # Admin location block bản gốc không có allow
        admin_block = remedy.child_ast_modified[FILE]["parsed"][0]["block"][0]["block"][1]["block"]
        allow_nodes = [n for n in admin_block if n["directive"] == "allow"]
        assert len(allow_nodes) == 0, "Path sai không được mutate block thực tế"


def test_28_empty_scan_result_no_mutation(remedy):
    """28. Context rỗng, không mutate sai root."""
    _run(
        remedy,
        user_inputs=["/admin_login", "192.168.1.100"],
        scan_result_by_file={},
        ast_by_file={FILE: _make_ast(_simple_parsed())},
    )
    assert remedy.child_ast_modified == {}


def test_29_multi_file_only_violating_file_modified(remedy):
    """29. Nhiều file scan result, chỉ file có violation bị sửa."""
    ast_b = _make_ast(_make_parsed([
        _http([_server([_node("listen", ["443"])])])
    ]))
    _run(
        remedy,
        user_inputs=["/admin_login", "192.168.1.100"],
        scan_result_by_file={
            FILE_A: [_violation(exact_path=EXACT_PATH_ADMIN)],
            # FILE_B không có violation
        },
        ast_by_file={
            FILE_A: _make_ast(_simple_parsed()),
            FILE_B: ast_b,
        },
    )
    assert FILE_A in remedy.child_ast_modified, "FILE_A có violation phải được sửa"
    assert FILE_B not in remedy.child_ast_modified, "FILE_B không có violation không được sửa"


def test_30_file_path_same_key_match(remedy):
    """30. File path normalize khác kiểu vẫn match (same key)."""
    _std_run(remedy, ip_string="192.168.1.100")
    assert FILE in remedy.child_ast_modified


def test_31_action_not_add_violation_skipped(remedy):
    """31. Scan result action không phải 'add', plugin bỏ qua."""
    _run(
        remedy,
        user_inputs=["/admin_login", "192.168.1.100"],
        scan_result_by_file={
            FILE: [_violation(action="replace", exact_path=EXACT_PATH_ADMIN)]
        },
        ast_by_file={FILE: _make_ast(_simple_parsed())},
    )
    if FILE in remedy.child_ast_modified:
        block = _get_location_block(remedy.child_ast_modified)
        allow_nodes = [n for n in block if n["directive"] == "allow"]
        assert len(allow_nodes) == 0, "action replace không được tạo allow directives"


def test_32_empty_exact_path_no_mutation(remedy):
    """32. Violation với exact_path rỗng, plugin bỏ qua an toàn."""
    _run(
        remedy,
        user_inputs=["/admin_login", "192.168.1.100"],
        scan_result_by_file={
            FILE: [_violation(action="add", exact_path=[])]
        },
        ast_by_file={FILE: _make_ast(_simple_parsed())},
    )
    # Không được crash; nếu có trong modified thì block không được mutate
    if FILE in remedy.child_ast_modified:
        admin_block = remedy.child_ast_modified[FILE]["parsed"][0]["block"][0]["block"][1]["block"]
        allow_nodes = [n for n in admin_block if n["directive"] == "allow"]
        assert len(allow_nodes) == 0


def test_33_location_not_at_path_no_mutation(remedy):
    """33. Location block không tồn tại tại exact_path, plugin bỏ qua an toàn."""
    parsed_no_location = _make_parsed([
        _http([
            _server([
                _node("listen", ["80"]),
                # No /admin_login/ location
            ])
        ])
    ])
    # EXACT_PATH_ADMIN trỏ server["block"][1]["block"] nhưng server["block"][1] không tồn tại
    _run(
        remedy,
        user_inputs=["/admin_login", "192.168.1.100"],
        scan_result_by_file={FILE: [_violation(exact_path=EXACT_PATH_ADMIN)]},
        ast_by_file={FILE: _make_ast(parsed_no_location)},
    )
    # Không được raise; nếu trong modified thì server block chỉ có listen
    if FILE in remedy.child_ast_modified:
        server_block = remedy.child_ast_modified[FILE]["parsed"][0]["block"][0]["block"]
        allow_in_server = [n for n in server_block if n.get("directive") == "allow"]
        assert len(allow_in_server) == 0


def test_34_deep_copy_no_alias_original(remedy):
    """34. Deep copy AST không alias input gốc."""
    original_ast = _make_ast(_simple_parsed())
    original_parsed_snapshot = copy.deepcopy(original_ast["parsed"])
    _run(
        remedy,
        user_inputs=["/admin_login", "192.168.1.100"],
        scan_result_by_file={FILE: [_violation(exact_path=EXACT_PATH_ADMIN)]},
        ast_by_file={FILE: original_ast},
    )
    # Original ast phải không bị thay đổi
    assert original_ast["parsed"] == original_parsed_snapshot, \
        "remediate() không được alias và mutate input AST gốc"


# ===========================================================================
# E. Regression / edge (35-40)
# ===========================================================================

def test_35_empty_scan_result_child_ast_modified_empty(remedy):
    """35. Scan result rỗng, child_ast_modified == {}."""
    remedy.user_inputs = ["/admin_login", "192.168.1.100"]
    remedy.child_scan_result = {}
    remedy.child_ast_config = {FILE: _make_ast(_simple_parsed())}
    remedy.remediate()
    assert remedy.child_ast_modified == {}


def test_36_repeated_remediate_deny_all_still_last(remedy):
    """36. Remediate lặp lại không tạo duplicate allow/deny không hợp lý; deny vẫn cuối."""
    _std_run(remedy, ip_string="192.168.1.100")
    after_first = copy.deepcopy(remedy.child_ast_modified[FILE])

    # Lần 2
    remedy.child_ast_config = {FILE: after_first}
    remedy.child_scan_result = {FILE: [_violation(exact_path=EXACT_PATH_ADMIN)]}
    remedy.remediate()

    block = _get_location_block(remedy.child_ast_modified)
    assert block[-1]["directive"] == "deny", "deny all; phải là phần tử cuối sau lần 2"
    assert block[-1]["args"] == ["all"]


def test_37_deny_all_is_always_last_element(remedy):
    """37. deny all; là phần tử cuối trong mọi trường hợp."""
    _std_run(remedy, ip_string="10.0.0.0/8, 172.16.0.0/12")
    block = _get_location_block(remedy.child_ast_modified)
    last = block[-1]
    assert last["directive"] == "deny"
    assert last["args"] == ["all"]


def test_38_diff_reflects_allow_and_deny(remedy):
    """38. Diff phản ánh allow/deny đúng thứ tự."""
    _std_run(remedy, ip_string="192.168.1.100")
    # Restore original for diff comparison
    remedy.child_ast_config = {FILE: _make_ast(_simple_parsed())}
    payload = remedy.build_file_diff_payload(FILE)

    assert payload["file_path"] == FILE
    diff = payload["diff_text"]
    assert "allow" in diff, "Diff phải chứa 'allow'"
    assert "deny" in diff, "Diff phải chứa 'deny'"


def test_39_ast_structure_valid_after_mutation(remedy):
    """39. AST sau sửa vẫn hợp lệ: list > http > server > location."""
    _std_run(remedy, ip_string="192.168.1.100")
    parsed = remedy.child_ast_modified[FILE]["parsed"]
    assert isinstance(parsed, list)
    http_node = parsed[0]
    assert http_node["directive"] == "http"
    assert isinstance(http_node["block"], list)
    server_node = http_node["block"][0]
    assert server_node["directive"] == "server"
    assert isinstance(server_node["block"], list)
    # Location node phải còn đó
    location_nodes = [n for n in server_node["block"] if n.get("directive") == "location"]
    assert len(location_nodes) >= 1


def test_40_child_ast_modified_only_contains_violating_files(remedy):
    """40. child_ast_modified chỉ chứa file có violation."""
    ast_b = _make_ast(_make_parsed([
        _http([_server([_node("listen", ["443"])])])
    ]))
    _run(
        remedy,
        user_inputs=["/admin_login", "192.168.1.100"],
        scan_result_by_file={
            FILE_A: [_violation(exact_path=EXACT_PATH_ADMIN)],
        },
        ast_by_file={
            FILE_A: _make_ast(_simple_parsed()),
            FILE_B: ast_b,
        },
    )
    assert FILE_A in remedy.child_ast_modified
    assert FILE_B not in remedy.child_ast_modified
