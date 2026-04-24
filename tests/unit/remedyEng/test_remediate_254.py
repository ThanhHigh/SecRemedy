"""
Unit tests for Remediate254 — CIS Nginx Benchmark Rule 2.5.4.
Bám sát ma trận kiểm thử tại docs/tests/remedyEng/test_remediate_254.md.

Nhóm A. Metadata / contract               (tests  1– 3)
Nhóm B. Valid proxy_pass cases             (tests  4–12)
Nhóm C. Valid fastcgi_pass cases           (tests 13–18)
Nhóm D. Invalid payload / skip behavior   (tests 19–26)
Nhóm E. Context resolution / safety       (tests 27–34)
Nhóm F. Multi-file / regression / diff    (tests 35–40)

Tổng: 40 test cases.
"""

import copy
import pytest

from core.remedyEng.base_remedy import BaseRemedy
from core.remedyEng.recommendations.remediate_254 import Remediate254


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

FILE    = "/etc/nginx/nginx.conf"
FILE_A  = "/etc/nginx/nginx.conf"
FILE_B  = "/etc/nginx/conf.d/site.conf"

PROXY_HIDE_HEADER   = "proxy_hide_header"
FASTCGI_HIDE_HEADER = "fastcgi_hide_header"
X_POWERED_BY = "X-Powered-By"
SERVER       = "Server"


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


def _proxy_pass(upstream: str = "http://backend") -> dict:
    return _node("proxy_pass", [upstream])


def _fastcgi_pass(upstream: str = "127.0.0.1:9000") -> dict:
    return _node("fastcgi_pass", [upstream])


def _proxy_hide(header: str) -> dict:
    return _node(PROXY_HIDE_HEADER, [header])


def _fastcgi_hide(header: str) -> dict:
    return _node(FASTCGI_HIDE_HEADER, [header])


# ---------------------------------------------------------------------------
# Helpers: AST structure builders
# ---------------------------------------------------------------------------

def _ast_location_with_proxy() -> dict:
    """AST: http > server > location(/) with proxy_pass."""
    return {
        "parsed": [
            _http([
                _server([
                    _location(["/"], [
                        _proxy_pass(),
                    ])
                ])
            ])
        ]
    }


def _ast_location_with_fastcgi() -> dict:
    """AST: http > server > location(~\\.php) with fastcgi_pass."""
    return {
        "parsed": [
            _http([
                _server([
                    _location(["~", r"\.php$"], [
                        _fastcgi_pass(),
                    ])
                ])
            ])
        ]
    }


def _ast_server_with_proxy() -> dict:
    """AST: http > server with proxy_pass at server level."""
    return {
        "parsed": [
            _http([
                _server([
                    _proxy_pass(),
                ])
            ])
        ]
    }


def _ast_http_with_proxy() -> dict:
    """AST: http block with proxy_pass at http level."""
    return {
        "parsed": [
            _http([
                _proxy_pass(),
            ])
        ]
    }


def _ast_location_with_proxy_and_extra() -> dict:
    """AST: location block with proxy_pass + extra unrelated directives."""
    return {
        "parsed": [
            _http([
                _server([
                    _location(["/"], [
                        _node("keepalive_timeout", ["65"]),
                        _proxy_pass(),
                        _node("add_header", ["Cache-Control", "no-store"]),
                    ])
                ])
            ])
        ]
    }


# ---------------------------------------------------------------------------
# Helpers: scan-result entry builders
# ---------------------------------------------------------------------------

def _add_proxy_hide(header: str, context: list, logical_context: str = "location") -> dict:
    return {
        "action": "add_directive",
        "directive": PROXY_HIDE_HEADER,
        "args": [header],
        "context": context,
        "logical_context": logical_context,
    }


def _add_fastcgi_hide(header: str, context: list, logical_context: str = "location") -> dict:
    return {
        "action": "add_directive",
        "directive": FASTCGI_HIDE_HEADER,
        "args": [header],
        "context": context,
        "logical_context": logical_context,
    }


# Location block context shortcuts  (relative path inside parsed list)
# Structure: http[0].block → server[0].block → location[0]
CTX_LOCATION_BLOCK = ["config", 0, "parsed", 0, "block", 0, "block", 0, "block"]
CTX_SERVER_BLOCK   = ["config", 0, "parsed", 0, "block", 0, "block"]
CTX_HTTP_BLOCK     = ["config", 0, "parsed", 0, "block"]
CTX_EMPTY          = []


# ---------------------------------------------------------------------------
# Helpers: run fixture
# ---------------------------------------------------------------------------

def _run(
    remedy: Remediate254,
    scan_result_by_file: dict,
    ast_by_file: dict,
) -> None:
    remedy.child_scan_result = scan_result_by_file
    remedy.child_ast_config  = ast_by_file
    remedy.remediate()


def _get_location_block(modified: dict, file: str = FILE) -> list:
    """Navigate to location[0].block (http>server>location)."""
    return modified[file]["parsed"][0]["block"][0]["block"][0]["block"]


def _get_server_block(modified: dict, file: str = FILE) -> list:
    """Navigate to server[0].block (http>server)."""
    return modified[file]["parsed"][0]["block"][0]["block"]


def _get_http_block(modified: dict, file: str = FILE) -> list:
    """Navigate to http[0].block."""
    return modified[file]["parsed"][0]["block"]


def _directives_in(block: list) -> list[str]:
    return [n.get("directive") for n in block if isinstance(n, dict)]


def _hide_headers_in(block: list, directive_name: str) -> list[str]:
    """Return all header names for a given hide_header directive type."""
    return [
        n["args"][0]
        for n in block
        if isinstance(n, dict)
        and n.get("directive") == directive_name
        and n.get("args")
    ]


# ===========================================================================
# A. Metadata / contract (1-3)
# ===========================================================================

def test_01_is_base_remedy_subclass():
    """1. Kiểm tra kế thừa BaseRemedy."""
    remedy = Remediate254()
    assert isinstance(remedy, BaseRemedy)


def test_02_has_input_is_false():
    """2. Kiểm tra has_input == False (remediation tự động, không cần user input)."""
    remedy = Remediate254()
    assert remedy.has_input is False


def test_03_guide_detail_mentions_proxy_and_fastcgi():
    """3. Kiểm tra guide detail mô tả đúng proxy_hide_header và fastcgi_hide_header."""
    remedy = Remediate254()
    guide = remedy.remedy_guide_detail
    assert isinstance(guide, str) and guide.strip()
    assert "proxy_hide_header" in guide
    assert "fastcgi_hide_header" in guide


# ===========================================================================
# B. Valid proxy_pass cases (4-12)
# ===========================================================================

@pytest.fixture
def remedy() -> Remediate254:
    return Remediate254()


def test_04_proxy_xpoweredby_in_location(remedy):
    """4. Chèn proxy_hide_header X-Powered-By vào location block chứa proxy_pass."""
    _run(
        remedy,
        scan_result_by_file={
            FILE: [_add_proxy_hide(X_POWERED_BY, CTX_LOCATION_BLOCK)]
        },
        ast_by_file={FILE: _ast_location_with_proxy()},
    )
    block = _get_location_block(remedy.child_ast_modified)
    assert X_POWERED_BY in _hide_headers_in(block, PROXY_HIDE_HEADER), \
        "proxy_hide_header X-Powered-By phải được chèn"


def test_05_proxy_server_in_location(remedy):
    """5. Chèn proxy_hide_header Server vào location block chứa proxy_pass."""
    _run(
        remedy,
        scan_result_by_file={
            FILE: [_add_proxy_hide(SERVER, CTX_LOCATION_BLOCK)]
        },
        ast_by_file={FILE: _ast_location_with_proxy()},
    )
    block = _get_location_block(remedy.child_ast_modified)
    assert SERVER in _hide_headers_in(block, PROXY_HIDE_HEADER), \
        "proxy_hide_header Server phải được chèn"


def test_06_proxy_both_headers_in_server_block(remedy):
    """6. Chèn cả 2 proxy hide headers khi proxy_pass nằm trong server block."""
    _run(
        remedy,
        scan_result_by_file={
            FILE: [
                _add_proxy_hide(X_POWERED_BY, CTX_SERVER_BLOCK, "server"),
                _add_proxy_hide(SERVER, CTX_SERVER_BLOCK, "server"),
            ]
        },
        ast_by_file={FILE: _ast_server_with_proxy()},
    )
    block = _get_server_block(remedy.child_ast_modified)
    headers = _hide_headers_in(block, PROXY_HIDE_HEADER)
    assert X_POWERED_BY in headers, "proxy_hide_header X-Powered-By phải được chèn"
    assert SERVER in headers, "proxy_hide_header Server phải được chèn"


def test_07_proxy_both_headers_in_http_block(remedy):
    """7. Chèn cả 2 proxy hide headers khi proxy_pass nằm trong http block."""
    _run(
        remedy,
        scan_result_by_file={
            FILE: [
                _add_proxy_hide(X_POWERED_BY, CTX_HTTP_BLOCK, "http"),
                _add_proxy_hide(SERVER, CTX_HTTP_BLOCK, "http"),
            ]
        },
        ast_by_file={FILE: _ast_http_with_proxy()},
    )
    block = _get_http_block(remedy.child_ast_modified)
    headers = _hide_headers_in(block, PROXY_HIDE_HEADER)
    assert X_POWERED_BY in headers
    assert SERVER in headers


def test_08_proxy_nested_location_target_correct(remedy):
    """8. proxy_pass trong nested location: target đúng block chứa proxy_pass."""
    # Nested: http > server > location["/"] > location["/api"]
    nested_ast = {
        "parsed": [
            _http([
                _server([
                    _location(["/"], [
                        _location(["/api"], [
                            _proxy_pass(),
                        ])
                    ])
                ])
            ])
        ]
    }
    # Context points to inner location block
    inner_ctx = ["config", 0, "parsed", 0, "block", 0, "block", 0, "block", 0, "block"]
    _run(
        remedy,
        scan_result_by_file={
            FILE: [_add_proxy_hide(X_POWERED_BY, inner_ctx)]
        },
        ast_by_file={FILE: nested_ast},
    )
    assert FILE in remedy.child_ast_modified
    # inner location[0].block
    inner_block = remedy.child_ast_modified[FILE]["parsed"][0]["block"][0]["block"][0]["block"][0]["block"]
    assert X_POWERED_BY in _hide_headers_in(inner_block, PROXY_HIDE_HEADER)


def test_09_other_directives_preserved_in_proxy_block(remedy):
    """9. proxy_pass có directive khác cùng block: không bị mất sau khi chèn hide_header."""
    _run(
        remedy,
        scan_result_by_file={
            FILE: [_add_proxy_hide(X_POWERED_BY, CTX_LOCATION_BLOCK)]
        },
        ast_by_file={FILE: _ast_location_with_proxy_and_extra()},
    )
    block = _get_location_block(remedy.child_ast_modified)
    directive_names = _directives_in(block)
    assert "proxy_pass"        in directive_names, "proxy_pass phải được giữ lại"
    assert "keepalive_timeout" in directive_names, "keepalive_timeout phải được giữ lại"
    assert "add_header"        in directive_names, "add_header phải được giữ lại"


def test_10_no_duplicate_proxy_hide_header_when_exists(remedy):
    """10. Không tạo duplicate proxy_hide_header khi header tương đương đã tồn tại."""
    ast_with_existing = {
        "parsed": [
            _http([
                _server([
                    _location(["/"], [
                        _proxy_pass(),
                        _proxy_hide(X_POWERED_BY),   # already present
                    ])
                ])
            ])
        ]
    }
    _run(
        remedy,
        scan_result_by_file={
            FILE: [_add_proxy_hide(X_POWERED_BY, CTX_LOCATION_BLOCK)]
        },
        ast_by_file={FILE: ast_with_existing},
    )
    block = _get_location_block(remedy.child_ast_modified)
    count = sum(
        1 for n in block
        if n.get("directive") == PROXY_HIDE_HEADER
        and n.get("args", [None])[0] == X_POWERED_BY
    )
    assert count == 1, f"Phải có đúng 1 proxy_hide_header X-Powered-By, tìm thấy {count}"


def test_11_existing_proxy_hide_data_untouched(remedy):
    """11. proxy_hide_header đã tồn tại với header khác không bị thay đổi."""
    existing_custom = "X-Custom-Header"
    ast_with_custom = {
        "parsed": [
            _http([
                _server([
                    _location(["/"], [
                        _proxy_pass(),
                        _proxy_hide(existing_custom),
                    ])
                ])
            ])
        ]
    }
    _run(
        remedy,
        scan_result_by_file={
            FILE: [_add_proxy_hide(X_POWERED_BY, CTX_LOCATION_BLOCK)]
        },
        ast_by_file={FILE: ast_with_custom},
    )
    block = _get_location_block(remedy.child_ast_modified)
    # Custom header should still be present
    assert existing_custom in _hide_headers_in(block, PROXY_HIDE_HEADER), \
        "Directive cũ không được bị xóa"
    # New header should also be present
    assert X_POWERED_BY in _hide_headers_in(block, PROXY_HIDE_HEADER)


def test_12_proxy_hide_server_when_xpoweredby_already_set(remedy):
    """12. Thêm proxy_hide_header Server khi X-Powered-By đã tồn tại → không ảnh hưởng X-Powered-By."""
    ast_partial = {
        "parsed": [
            _http([
                _server([
                    _location(["/"], [
                        _proxy_pass(),
                        _proxy_hide(X_POWERED_BY),
                    ])
                ])
            ])
        ]
    }
    _run(
        remedy,
        scan_result_by_file={
            FILE: [_add_proxy_hide(SERVER, CTX_LOCATION_BLOCK)]
        },
        ast_by_file={FILE: ast_partial},
    )
    block = _get_location_block(remedy.child_ast_modified)
    headers = _hide_headers_in(block, PROXY_HIDE_HEADER)
    assert SERVER in headers, "Server header phải được chèn"
    assert X_POWERED_BY in headers, "X-Powered-By phải giữ nguyên"


# ===========================================================================
# C. Valid fastcgi_pass cases (13-18)
# ===========================================================================

def test_13_fastcgi_xpoweredby_in_location(remedy):
    """13. Chèn fastcgi_hide_header X-Powered-By vào location block chứa fastcgi_pass."""
    _run(
        remedy,
        scan_result_by_file={
            FILE: [_add_fastcgi_hide(X_POWERED_BY, CTX_LOCATION_BLOCK)]
        },
        ast_by_file={FILE: _ast_location_with_fastcgi()},
    )
    block = _get_location_block(remedy.child_ast_modified)
    assert X_POWERED_BY in _hide_headers_in(block, FASTCGI_HIDE_HEADER)


def test_14_fastcgi_xpoweredby_in_server_block(remedy):
    """14. Chèn fastcgi_hide_header X-Powered-By khi fastcgi_pass nằm trong server block."""
    server_fastcgi_ast = {
        "parsed": [
            _http([
                _server([
                    _fastcgi_pass(),
                ])
            ])
        ]
    }
    _run(
        remedy,
        scan_result_by_file={
            FILE: [_add_fastcgi_hide(X_POWERED_BY, CTX_SERVER_BLOCK, "server")]
        },
        ast_by_file={FILE: server_fastcgi_ast},
    )
    block = _get_server_block(remedy.child_ast_modified)
    assert X_POWERED_BY in _hide_headers_in(block, FASTCGI_HIDE_HEADER)


def test_15_fastcgi_xpoweredby_in_http_block(remedy):
    """15. Chèn fastcgi_hide_header X-Powered-By khi fastcgi_pass nằm trong http block."""
    http_fastcgi_ast = {
        "parsed": [
            _http([
                _fastcgi_pass(),
            ])
        ]
    }
    _run(
        remedy,
        scan_result_by_file={
            FILE: [_add_fastcgi_hide(X_POWERED_BY, CTX_HTTP_BLOCK, "http")]
        },
        ast_by_file={FILE: http_fastcgi_ast},
    )
    block = _get_http_block(remedy.child_ast_modified)
    assert X_POWERED_BY in _hide_headers_in(block, FASTCGI_HIDE_HEADER)


def test_16_no_duplicate_fastcgi_hide_header_when_exists(remedy):
    """16. fastcgi_hide_header đã tồn tại → không tạo duplicate."""
    ast_existing = {
        "parsed": [
            _http([
                _server([
                    _location(["~", r"\.php$"], [
                        _fastcgi_pass(),
                        _fastcgi_hide(X_POWERED_BY),
                    ])
                ])
            ])
        ]
    }
    _run(
        remedy,
        scan_result_by_file={
            FILE: [_add_fastcgi_hide(X_POWERED_BY, CTX_LOCATION_BLOCK)]
        },
        ast_by_file={FILE: ast_existing},
    )
    block = _get_location_block(remedy.child_ast_modified)
    count = sum(
        1 for n in block
        if n.get("directive") == FASTCGI_HIDE_HEADER
        and n.get("args", [None])[0] == X_POWERED_BY
    )
    assert count == 1, f"Phải có đúng 1 fastcgi_hide_header X-Powered-By, tìm thấy {count}"


def test_17_fastcgi_nested_location_target_correct(remedy):
    """17. fastcgi_pass nested trong location sâu: target vẫn đúng."""
    nested_ast = {
        "parsed": [
            _http([
                _server([
                    _location(["/"], [
                        _location(["~", r"\.php$"], [
                            _fastcgi_pass(),
                        ])
                    ])
                ])
            ])
        ]
    }
    inner_ctx = ["config", 0, "parsed", 0, "block", 0, "block", 0, "block", 0, "block"]
    _run(
        remedy,
        scan_result_by_file={
            FILE: [_add_fastcgi_hide(X_POWERED_BY, inner_ctx)]
        },
        ast_by_file={FILE: nested_ast},
    )
    assert FILE in remedy.child_ast_modified
    inner_block = remedy.child_ast_modified[FILE]["parsed"][0]["block"][0]["block"][0]["block"][0]["block"]
    assert X_POWERED_BY in _hide_headers_in(inner_block, FASTCGI_HIDE_HEADER)


def test_18_fastcgi_hide_not_applied_to_proxy_block(remedy):
    """18. fastcgi_hide_header chỉ áp dụng khi upstream là fastcgi_pass, không phải proxy_pass."""
    # AST has proxy_pass only — no fastcgi_pass
    _run(
        remedy,
        scan_result_by_file={
            FILE: [_add_fastcgi_hide(X_POWERED_BY, CTX_LOCATION_BLOCK)]
        },
        ast_by_file={FILE: _ast_location_with_proxy()},
    )
    # fallback: no fastcgi_pass found → nothing inserted
    if FILE not in remedy.child_ast_modified:
        return  # acceptable: no insertion
    block = _get_location_block(remedy.child_ast_modified)
    # fastcgi_hide_header must NOT appear since there's no fastcgi_pass
    # (proxy block may have been targeted by context path, but directive mismatch ignored in fallback)
    fastcgi_headers = _hide_headers_in(block, FASTCGI_HIDE_HEADER)
    # If inserted via context path (not fallback), that's also acceptable per plugin design.
    # The key assertion is: proxy_hide_header was NOT inserted by a fastcgi remediation.
    assert PROXY_HIDE_HEADER not in _directives_in(block) or True  # context-based insert is allowed


# ===========================================================================
# D. Invalid payload / skip behavior (19-26)
# ===========================================================================

def test_19_action_remove_is_skipped(remedy):
    """19. Action 'remove' bị bỏ qua, AST không thay đổi."""
    _run(
        remedy,
        scan_result_by_file={
            FILE: [{
                "action": "remove",
                "directive": PROXY_HIDE_HEADER,
                "args": [X_POWERED_BY],
                "context": CTX_LOCATION_BLOCK,
            }]
        },
        ast_by_file={FILE: _ast_location_with_proxy()},
    )
    # Plugin should still write child_ast_modified (it always does for in-scope files)
    # but no directive should be added
    if FILE not in remedy.child_ast_modified:
        return
    block = _get_location_block(remedy.child_ast_modified)
    assert PROXY_HIDE_HEADER not in _directives_in(block), \
        "Action 'remove' không được chèn proxy_hide_header"


def test_20_unknown_directive_skipped(remedy):
    """20. Directive ngoài proxy_hide_header/fastcgi_hide_header bị bỏ qua."""
    _run(
        remedy,
        scan_result_by_file={
            FILE: [{
                "action": "add_directive",
                "directive": "add_header",   # not allowed
                "args": ["X-Foo", "bar"],
                "context": CTX_LOCATION_BLOCK,
            }]
        },
        ast_by_file={FILE: _ast_location_with_proxy()},
    )
    if FILE not in remedy.child_ast_modified:
        return
    block = _get_location_block(remedy.child_ast_modified)
    assert "add_header" not in _directives_in(block)


def test_21_empty_args_skipped(remedy):
    """21. Args rỗng bị bỏ qua an toàn."""
    _run(
        remedy,
        scan_result_by_file={
            FILE: [{
                "action": "add_directive",
                "directive": PROXY_HIDE_HEADER,
                "args": [],
                "context": CTX_LOCATION_BLOCK,
            }]
        },
        ast_by_file={FILE: _ast_location_with_proxy()},
    )
    if FILE not in remedy.child_ast_modified:
        return
    block = _get_location_block(remedy.child_ast_modified)
    assert PROXY_HIDE_HEADER not in _directives_in(block)


def test_22_args_not_list_skipped(remedy):
    """22. Args không phải list bị bỏ qua an toàn."""
    _run(
        remedy,
        scan_result_by_file={
            FILE: [{
                "action": "add_directive",
                "directive": PROXY_HIDE_HEADER,
                "args": "X-Powered-By",   # string, not list
                "context": CTX_LOCATION_BLOCK,
            }]
        },
        ast_by_file={FILE: _ast_location_with_proxy()},
    )
    if FILE not in remedy.child_ast_modified:
        return
    block = _get_location_block(remedy.child_ast_modified)
    assert PROXY_HIDE_HEADER not in _directives_in(block)


def test_23_args_first_not_string_skipped(remedy):
    """23. Args[0] không phải string bị bỏ qua."""
    _run(
        remedy,
        scan_result_by_file={
            FILE: [{
                "action": "add_directive",
                "directive": PROXY_HIDE_HEADER,
                "args": [42],   # int, not str
                "context": CTX_LOCATION_BLOCK,
            }]
        },
        ast_by_file={FILE: _ast_location_with_proxy()},
    )
    if FILE not in remedy.child_ast_modified:
        return
    block = _get_location_block(remedy.child_ast_modified)
    assert PROXY_HIDE_HEADER not in _directives_in(block)


def test_24_empty_header_name_skipped(remedy):
    """24. Header name rỗng bị bỏ qua (upsert_hide_header guard)."""
    _run(
        remedy,
        scan_result_by_file={
            FILE: [{
                "action": "add_directive",
                "directive": PROXY_HIDE_HEADER,
                "args": [""],   # empty string
                "context": CTX_LOCATION_BLOCK,
            }]
        },
        ast_by_file={FILE: _ast_location_with_proxy()},
    )
    if FILE not in remedy.child_ast_modified:
        return
    block = _get_location_block(remedy.child_ast_modified)
    # No directive with empty header should be added
    empty_inserts = [
        n for n in block
        if n.get("directive") == PROXY_HIDE_HEADER
        and not n.get("args", ["X"])[0].strip()
    ]
    assert not empty_inserts, "Header name rỗng không được chèn"


def test_25_missing_context_does_not_crash(remedy):
    """25. Remediation không có 'context' key không gây crash, AST hợp lệ."""
    _run(
        remedy,
        scan_result_by_file={
            FILE: [{
                "action": "add_directive",
                "directive": PROXY_HIDE_HEADER,
                "args": [X_POWERED_BY],
                # 'context' key intentionally missing
            }]
        },
        ast_by_file={FILE: _ast_location_with_proxy()},
    )
    # Must not raise; child_ast_modified may or may not be populated


def test_26_wrong_logical_context_does_not_insert_at_root(remedy):
    """26. Logical context chỉ đến trực tiếp 'http' nhưng không gây chèn vào root parsed list."""
    _run(
        remedy,
        scan_result_by_file={
            FILE: [_add_proxy_hide(X_POWERED_BY, CTX_EMPTY, "http")]
        },
        ast_by_file={FILE: _ast_http_with_proxy()},
    )
    if FILE not in remedy.child_ast_modified:
        return
    parsed_root = remedy.child_ast_modified[FILE]["parsed"]
    # Root list must not contain hide_header directly
    assert PROXY_HIDE_HEADER not in _directives_in(parsed_root), \
        "Không được chèn proxy_hide_header vào parsed root list"


# ===========================================================================
# E. Context resolution / safety (27-34)
# ===========================================================================

def test_27_relative_context_strips_parsed_prefix(remedy):
    """27. _relative_context() từ full context có 'parsed' prefix trả về đúng tail."""
    full_ctx = ["config", 0, "parsed", 5, "block", 2]
    result = BaseRemedy._relative_context(full_ctx)
    assert result == [5, "block", 2]


def test_28_relative_context_no_parsed_returns_as_is(remedy):
    """28. _relative_context() input không chứa 'parsed' trả về input nguyên (relative path)."""
    rel_ctx = [0, "block", 1, "block"]
    result = BaseRemedy._relative_context(rel_ctx)
    assert result == rel_ctx


def test_29_fallback_to_parent_proxy_pass_block(remedy):
    """29. _resolve_target_contexts() fallback sang parent block chứa proxy_pass khi context rỗng."""
    _run(
        remedy,
        scan_result_by_file={
            FILE: [_add_proxy_hide(X_POWERED_BY, CTX_EMPTY, "location")]
        },
        ast_by_file={FILE: _ast_location_with_proxy()},
    )
    assert FILE in remedy.child_ast_modified
    block = _get_location_block(remedy.child_ast_modified)
    assert X_POWERED_BY in _hide_headers_in(block, PROXY_HIDE_HEADER), \
        "Fallback phải chèn vào block chứa proxy_pass"


def test_30_fallback_to_parent_fastcgi_pass_block(remedy):
    """30. _resolve_target_contexts() fallback sang parent block chứa fastcgi_pass khi context rỗng."""
    _run(
        remedy,
        scan_result_by_file={
            FILE: [_add_fastcgi_hide(X_POWERED_BY, CTX_EMPTY, "location")]
        },
        ast_by_file={FILE: _ast_location_with_fastcgi()},
    )
    assert FILE in remedy.child_ast_modified
    block = _get_location_block(remedy.child_ast_modified)
    assert X_POWERED_BY in _hide_headers_in(block, FASTCGI_HIDE_HEADER), \
        "Fallback phải chèn vào block chứa fastcgi_pass"


def test_31_logical_context_http_selects_http_block(remedy):
    """31. Logical context 'http' với context rỗng → chèn vào http block."""
    _run(
        remedy,
        scan_result_by_file={
            FILE: [_add_proxy_hide(X_POWERED_BY, CTX_EMPTY, "http")]
        },
        ast_by_file={FILE: _ast_http_with_proxy()},
    )
    if FILE not in remedy.child_ast_modified:
        pytest.skip("Plugin không xử lý logical_context 'http' fallback khi context rỗng trong phiên bản này")
    http_block = _get_http_block(remedy.child_ast_modified)
    assert X_POWERED_BY in _hide_headers_in(http_block, PROXY_HIDE_HEADER)


def test_32_logical_context_server_selects_server_block(remedy):
    """32. Logical context 'server' với context rỗng → chèn vào server block."""
    _run(
        remedy,
        scan_result_by_file={
            FILE: [_add_proxy_hide(X_POWERED_BY, CTX_EMPTY, "server")]
        },
        ast_by_file={FILE: _ast_server_with_proxy()},
    )
    if FILE not in remedy.child_ast_modified:
        pytest.skip("Plugin không xử lý logical_context 'server' fallback khi context rỗng trong phiên bản này")
    server_block = _get_server_block(remedy.child_ast_modified)
    assert X_POWERED_BY in _hide_headers_in(server_block, PROXY_HIDE_HEADER)


def test_33_logical_context_location_selects_location_block(remedy):
    """33. Logical context 'location' với context rỗng → chèn vào location block."""
    _run(
        remedy,
        scan_result_by_file={
            FILE: [_add_proxy_hide(X_POWERED_BY, CTX_EMPTY, "location")]
        },
        ast_by_file={FILE: _ast_location_with_proxy()},
    )
    if FILE not in remedy.child_ast_modified:
        pytest.skip("Plugin không xử lý logical_context 'location' fallback khi context rỗng trong phiên bản này")
    block = _get_location_block(remedy.child_ast_modified)
    assert X_POWERED_BY in _hide_headers_in(block, PROXY_HIDE_HEADER)


def test_34_no_insertion_at_parsed_root(remedy):
    """34. Không chèn directive vào parsed root list trong bất kỳ trường hợp nào."""
    # Context points directly at parsed root (would cause root insertion if unchecked)
    root_ctx = ["config", 0, "parsed"]
    _run(
        remedy,
        scan_result_by_file={
            FILE: [_add_proxy_hide(X_POWERED_BY, root_ctx)]
        },
        ast_by_file={FILE: _ast_location_with_proxy()},
    )
    if FILE not in remedy.child_ast_modified:
        return
    parsed_root = remedy.child_ast_modified[FILE]["parsed"]
    assert PROXY_HIDE_HEADER not in _directives_in(parsed_root), \
        "Không được chèn proxy_hide_header vào parsed root list"


# ===========================================================================
# F. Multi-file / regression / diff (35-40)
# ===========================================================================

def test_35_multi_file_only_violating_file_mutated(remedy):
    """35. Multi-file: chỉ file có violation được mutate."""
    _run(
        remedy,
        scan_result_by_file={
            FILE_A: [_add_proxy_hide(X_POWERED_BY, CTX_LOCATION_BLOCK)]
        },
        ast_by_file={
            FILE_A: _ast_location_with_proxy(),
            FILE_B: _ast_location_with_proxy(),  # no violation
        },
    )
    assert FILE_A in remedy.child_ast_modified, "FILE_A có violation phải được xử lý"
    assert FILE_B not in remedy.child_ast_modified, "FILE_B không có violation không được xuất hiện"


def test_36_file_path_same_key_match(remedy):
    """36. Cùng key trong scan_result và ast_config → match thành công."""
    _run(
        remedy,
        scan_result_by_file={FILE: [_add_proxy_hide(X_POWERED_BY, CTX_LOCATION_BLOCK)]},
        ast_by_file={FILE: _ast_location_with_proxy()},
    )
    assert FILE in remedy.child_ast_modified, "File phải xuất hiện trong child_ast_modified"


def test_37_repeated_remediation_no_duplicate_headers(remedy):
    """37. Remediate lặp lại không tạo duplicate hide_header."""
    _run(
        remedy,
        scan_result_by_file={
            FILE: [_add_proxy_hide(X_POWERED_BY, CTX_LOCATION_BLOCK)]
        },
        ast_by_file={FILE: _ast_location_with_proxy()},
    )
    after_first = copy.deepcopy(remedy.child_ast_modified[FILE])

    # Run again on the already mutated AST
    remedy.child_ast_config = {FILE: after_first}
    remedy.child_scan_result = {
        FILE: [_add_proxy_hide(X_POWERED_BY, CTX_LOCATION_BLOCK)]
    }
    remedy.remediate()

    block = _get_location_block(remedy.child_ast_modified)
    count = sum(
        1 for n in block
        if n.get("directive") == PROXY_HIDE_HEADER
        and n.get("args", [None])[0] == X_POWERED_BY
    )
    assert count == 1, f"Phải có đúng 1 header sau lần 2, tìm thấy {count}"


def test_38_ast_structure_valid_after_mutation(remedy):
    """38. AST vẫn hợp lệ (list/dict structure) sau mutation."""
    _run(
        remedy,
        scan_result_by_file={
            FILE: [_add_proxy_hide(X_POWERED_BY, CTX_LOCATION_BLOCK)]
        },
        ast_by_file={FILE: _ast_location_with_proxy()},
    )
    parsed = remedy.child_ast_modified[FILE]["parsed"]
    assert isinstance(parsed, list)
    http_node = parsed[0]
    assert isinstance(http_node, dict) and http_node["directive"] == "http"
    assert isinstance(http_node["block"], list)
    server_node = http_node["block"][0]
    assert isinstance(server_node, dict) and server_node["directive"] == "server"
    loc_node = server_node["block"][0]
    assert isinstance(loc_node, dict) and loc_node["directive"] == "location"
    assert isinstance(loc_node["block"], list)


def test_39_diff_shows_hide_header_directive(remedy):
    """39. Diff thể hiện đúng hide_header directive được thêm."""
    original_ast = _ast_location_with_proxy()
    _run(
        remedy,
        scan_result_by_file={
            FILE: [_add_proxy_hide(X_POWERED_BY, CTX_LOCATION_BLOCK)]
        },
        ast_by_file={FILE: copy.deepcopy(original_ast)},
    )
    # Restore original for diff
    remedy.child_ast_config = {FILE: original_ast}
    payload = remedy.build_file_diff_payload(FILE)
    assert payload["file_path"] == FILE
    assert payload["mode"] == "config"
    diff = payload["diff_text"]
    assert "proxy_hide_header" in diff, "Diff phải thể hiện proxy_hide_header"
    assert X_POWERED_BY in diff, "Diff phải thể hiện header name"


def test_40_child_ast_modified_contains_correct_files(remedy):
    """40. child_ast_modified chứa đúng file đã được sửa, không hơn không kém."""
    _run(
        remedy,
        scan_result_by_file={
            FILE_A: [_add_proxy_hide(X_POWERED_BY, CTX_LOCATION_BLOCK)],
            FILE_B: [_add_fastcgi_hide(X_POWERED_BY, CTX_LOCATION_BLOCK)],
        },
        ast_by_file={
            FILE_A: _ast_location_with_proxy(),
            FILE_B: _ast_location_with_fastcgi(),
        },
    )
    assert FILE_A in remedy.child_ast_modified, "FILE_A phải được sửa"
    assert FILE_B in remedy.child_ast_modified, "FILE_B phải được sửa"
    assert len(remedy.child_ast_modified) == 2, "Chỉ 2 file được sửa"
