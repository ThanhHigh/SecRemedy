"""
Debug script: so sánh mod_ast vs parser_output_after.

mod_ast              = AST sau khi remedy_engine inject + rewrite (in-memory snapshot).
parser_output_after  = AST sinh ra khi reparse hardened config đã push lên server.

Hai cái này phải tương đương (về cấu trúc directive). Khác nhau =>
  - injector sai (chèn nhầm vị trí / thiếu directive), hoặc
  - builder render sai (mất directive khi serialize), hoặc
  - rewrite path không khớp.

Usage:
  python check_mod_ast.py                  # check tất cả port
  python check_mod_ast.py --port 2220      # check 1 port
  python check_mod_ast.py --strict         # so cả line numbers (mặc định: bỏ qua line)
  python check_mod_ast.py --verbose        # in diff chi tiết khi mismatch
"""

import argparse
import json
import re
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
MOD_AST_DIR = BASE_DIR / "tmp" / "contracts" / "mod_asts"
AFTER_DIR = BASE_DIR / "tmp" / "contracts" / "parsers_output_after"

PORT_RE = re.compile(r"_(\d+)\.json$")


def load_json(path: Path) -> dict:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def normalize(node, drop_line: bool = True):
    """Strip noise fields => so sánh structural.
    Bỏ: line (reparse đổi line), status/errors top-level (metadata).
    Sort file list theo "file" => không phụ thuộc thứ tự parse."""
    if isinstance(node, dict):
        out = {}
        for k, v in node.items():
            if drop_line and k == "line":
                continue
            if k in ("status", "errors"):
                continue
            out[k] = normalize(v, drop_line)
        return out
    if isinstance(node, list):
        return [normalize(v, drop_line) for v in node]
    return node


def normalize_ast(ast: dict, drop_line: bool = True) -> dict:
    """Top-level: sort config[] theo file để 2 phía cùng order."""
    norm = normalize(ast, drop_line)
    if isinstance(norm, dict) and isinstance(norm.get("config"), list):
        norm["config"] = sorted(norm["config"], key=lambda c: c.get("file", ""))
    return norm


def diff_json(a, b, path: str = "$") -> list[str]:
    """Trả list diff. Mỗi entry = "<path>: <reason>"."""
    diffs: list[str] = []
    if type(a) is not type(b):
        diffs.append(f"{path}: type {type(a).__name__} vs {type(b).__name__}")
        return diffs
    if isinstance(a, dict):
        keys = set(a) | set(b)
        for k in sorted(keys):
            if k not in a:
                diffs.append(f"{path}.{k}: missing in mod_ast")
            elif k not in b:
                diffs.append(f"{path}.{k}: missing in after")
            else:
                diffs.extend(diff_json(a[k], b[k], f"{path}.{k}"))
    elif isinstance(a, list):
        if len(a) != len(b):
            diffs.append(f"{path}: len {len(a)} vs {len(b)}")
        for i, (x, y) in enumerate(zip(a, b)):
            diffs.extend(diff_json(x, y, f"{path}[{i}]"))
    else:
        if a != b:
            diffs.append(f"{path}: {a!r} vs {b!r}")
    return diffs


def list_ports() -> list[int]:
    ports = set()
    for p in MOD_AST_DIR.glob("mod_ast_*.json"):
        m = PORT_RE.search(p.name)
        if m:
            ports.add(int(m.group(1)))
    return sorted(ports)


def check_port(port: int, strict: bool, verbose: bool) -> tuple[bool, str]:
    mod_path = MOD_AST_DIR / f"mod_ast_{port}.json"
    after_path = AFTER_DIR / f"parser_output_{port}.json"

    if not mod_path.exists():
        return False, f"missing {mod_path.name}"
    if not after_path.exists():
        return False, f"missing parsers_output_after/parser_output_{port}.json"

    mod = normalize_ast(load_json(mod_path), drop_line=not strict)
    after = normalize_ast(load_json(after_path), drop_line=not strict)

    diffs = diff_json(mod, after)
    if not diffs:
        return True, "match"

    msg = f"{len(diffs)} diff(s)"
    if verbose:
        sample = "\n  ".join(diffs[:20])
        extra = f"\n  ... +{len(diffs) - 20} more" if len(diffs) > 20 else ""
        msg += f":\n  {sample}{extra}"
    return False, msg


def main() -> int:
    ap = argparse.ArgumentParser(description="Check mod_ast vs parser_output_after")
    ap.add_argument("--port", type=int, help="Check 1 port (default: all)")
    ap.add_argument("--strict", action="store_true", help="Compare line numbers too")
    ap.add_argument("--verbose", "-v", action="store_true", help="Show diff details")
    args = ap.parse_args()

    ports = [args.port] if args.port else list_ports()
    if not ports:
        print("[!] No mod_ast files found.")
        return 1

    pass_n = fail_n = 0
    for port in ports:
        ok, msg = check_port(port, args.strict, args.verbose)
        mark = "[OK]  " if ok else "[FAIL]"
        print(f"{mark} {port}: {msg}")
        if ok:
            pass_n += 1
        else:
            fail_n += 1

    print(f"\nTotal: {pass_n} pass / {fail_n} fail / {len(ports)} ports")
    return 0 if fail_n == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
