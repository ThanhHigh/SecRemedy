"""
Remedy Engine — Orchestrator (Member 2).

dry_run(port)  → Steps 1–5: đọc scan_result, inject AST, build hardened.conf, sinh diff.
execute(port)  → Step 6: SSH backup + SFTP push (chỉ gọi sau Approve Gate).

File I/O:
  INPUT   tmp/contracts/scan_result/scan_result_<port>.json
  INPUT   tmp/contracts/parsers_output/parser_output_<port>.json
  WORK    tmp/hardened_configs/<port>/
  OUTPUT  /etc/nginx/* trên target server (chỉ khi execute)

Usage (CLI):
    python -m core.remedyEng.remedy_engine --dry-run --port 2226
    python -m core.remedyEng.remedy_engine --execute --port 2226 \\
        --host 127.0.0.1 --ssh-port 2222 --user root --pass secret

Usage (Import):
    from core.remedyEng.remedy_engine import RemedyEngine
    engine = RemedyEngine()
    result = engine.dry_run(2226)
    print(result["diff"])
"""

import argparse
import copy
import json
import posixpath
import re
from pathlib import Path

from core.remedyEng.reader import ScanResultReader
from core.remedyEng.injector import ASTInjector
from core.remedyEng.builder import ConfigBuilder
from core.remedyEng.diff_generator import DiffGenerator
from core.remedyEng.executor import RemoteExecutor

BASE_DIR = Path(__file__).resolve().parent.parent.parent  # SecRemedy/

# Match "sites-enabled" chỉ khi đứng độc lập (không phải prefix của "sites-enabled-backup" v.v.).
# Lookaround loại trừ kế cận word-char hoặc dấu '-'.
_SITES_ENABLED_RE = re.compile(r"(?<![A-Za-z0-9_-])sites-enabled(?![A-Za-z0-9_-])")


def _path_sort_key(item) -> tuple:
    """
    Build sort key cho exact_path mixed int/str: (0, val) cho int, (1, val) cho str.
    Sắp theo key DESC → op tại index cao trong cùng parent_list chạy trước,
    tránh index-shift do delete/insert ở index thấp.
    """
    return tuple((0, x) if isinstance(x, int) else (1, x) for x in item.exact_path)


class RemedyEngine:
    def __init__(self) -> None:
        self._reader = ScanResultReader()
        self._injector = ASTInjector()
        self._builder = ConfigBuilder()
        self._diff_gen = DiffGenerator()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def dry_run(self, port: int) -> dict:
        """
        Steps 1–5.

        Returns:
          {
            "diff":          str   — unified diff text (empty nếu không có gì sửa),
            "hardened_dir":  str   — thư mục chứa hardened config,
            "output_files":  list  — các file đã ghi,
            "status":        str   — "pending" | "no_changes",
          }
        """
        scan_result_path = self._scan_result_path(port)
        ast_path = self._ast_path(port)
        hardened_dir = self._hardened_dir(port)

        # Step 1: Load remediations
        items = self._reader.load(str(scan_result_path))
        if not items:
            return {
                "diff": "",
                "hardened_dir": str(hardened_dir),
                "output_files": [],
                "status": "no_changes",
            }

        # Step 2-3: Load AST, deep-copy để giữ bản gốc, inject thay đổi
        with open(ast_path, encoding="utf-8") as f:
            original_ast = json.load(f)

        hardened_ast = copy.deepcopy(original_ast)

        # Sort theo exact_path DESC: op ở index cao chạy trước → delete/insert ở
        # index thấp không shift các path đã queue. Stable hơn line-based sort
        # vì line=0 không phản ánh vị trí trong block.
        items_sorted = sorted(items, key=_path_sort_key, reverse=True)
        skipped: list[dict] = []
        for item in items_sorted:
            try:
                self._injector.apply(hardened_ast, item)
            except (KeyError, IndexError, TypeError, ValueError) as e:
                # Scanner có thể sinh exact_path không hợp lệ (vd trỏ vào
                # directive đơn không có inner block). Skip + log để
                # Member 1 thấy item nào sai, không crash cả batch.
                reason = f"{type(e).__name__}: {e}"
                skipped.append({
                    "file": item.file,
                    "action": item.action,
                    "directive": item.directive,
                    "exact_path": item.exact_path,
                    "reason": reason,
                })
                print(f"[!] Skip invalid item: {item.action} {item.directive} "
                      f"path={item.exact_path} — {reason}")

        # Rewrite "sites-enabled" → "sites-available" trong toàn AST.
        # Nginx convention: sites-available giữ file thật, sites-enabled chỉ symlink.
        # Push hardened config vào sites-available để tránh ghi đè symlink.
        self._rewrite_sites_enabled(hardened_ast)

        # Dump modified AST → tmp/contracts/mod_asts/mod_ast_<port>.json.
        # Snapshot sau inject + rewrite, trước build → debug/audit injector output.
        self._write_mod_ast(port, hardened_ast)

        # Tính common base (vd "/etc/nginx") để strip khỏi cây hardened_dir.
        # Tránh tạo etc/nginx/... rỗng. Lưu marker để execute() prepend lại.
        remote_base = self._compute_remote_base(hardened_ast)
        self._write_remote_base(hardened_dir, remote_base)

        # Step 4: Build hardened config files
        output_files = self._builder.build(
            hardened_ast, str(hardened_dir), strip_prefix=remote_base
        )

        # Step 5: Generate unified diff
        diff = self._diff_gen.generate_from_ast(original_ast, hardened_ast)

        return {
            "diff": diff,
            "hardened_dir": str(hardened_dir),
            "output_files": output_files,
            "status": "pending",
            "skipped": skipped,
        }

    def execute(self, port: int, ssh_creds: dict) -> dict:
        """
        Step 6 — chỉ gọi sau Approve Gate.

        ssh_creds keys: host, port, username, password (opt), key_path (opt).

        Returns:
          {"status": "applied" | "failed", "error": str | None}
        """
        hardened_dir = self._hardened_dir(port)

        if not hardened_dir.exists() or not any(hardened_dir.iterdir()):
            return {"status": "failed", "error": "Hardened configs not found — run dry_run first"}

        executor = RemoteExecutor(
            host=ssh_creds["host"],
            port=ssh_creds["port"],
            username=ssh_creds["username"],
            password=ssh_creds.get("password"),
            key_path=ssh_creds.get("key_path"),
        )

        if not executor.backup():
            return {"status": "failed", "error": "SSH backup failed"}

        # hardened_dir mirror tương đối theo remote_base (vd /etc/nginx).
        # Đọc marker để prepend lại khi push remote. Bỏ qua file marker.
        remote_base = self._read_remote_base(hardened_dir)
        base = remote_base.rstrip("/") or ""
        local_files = {
            str(f): f"{base}/{f.relative_to(hardened_dir).as_posix()}"
            for f in hardened_dir.rglob("*")
            if f.is_file() and f.name != ".remote_base"
        }

        if not executor.push(local_files):
            return {"status": "failed", "error": "SFTP push failed"}

        return {"status": "applied", "error": None}

    # ------------------------------------------------------------------
    # AST rewriters
    # ------------------------------------------------------------------
    def _rewrite_sites_enabled(self, ast: dict) -> None:
        """Replace token "sites-enabled" => "sites-available" trong AST (in-place).
        Chỉ match token độc lập — "sites-enabled-backup" không bị đổi."""
        def sub(s: str) -> str:
            return _SITES_ENABLED_RE.sub("sites-available", s)

        def walk(node):
            if isinstance(node, dict):
                for k, v in node.items():
                    if isinstance(v, str):
                        node[k] = sub(v)
                    else:
                        walk(v)
            elif isinstance(node, list):
                for i, v in enumerate(node):
                    if isinstance(v, str):
                        node[i] = sub(v)
                    else:
                        walk(v)
        walk(ast)

    # ------------------------------------------------------------------
    # Remote base helpers
    # ------------------------------------------------------------------
    def _compute_remote_base(self, ast: dict) -> str:
        """Common parent dir của tất cả config file. Vd ["/etc/nginx/nginx.conf",
        "/etc/nginx/sites-available/x.conf"] → "/etc/nginx"."""
        files = [c["file"] for c in ast.get("config", []) if c.get("file")]
        if not files:
            return ""
        parents = [posixpath.dirname(f) or "/" for f in files]
        return posixpath.commonpath(parents) if len(parents) > 1 else parents[0]

    def _write_remote_base(self, hardened_dir: Path, base: str) -> None:
        hardened_dir.mkdir(parents=True, exist_ok=True)
        (hardened_dir / ".remote_base").write_text(base, encoding="utf-8")

    def _read_remote_base(self, hardened_dir: Path) -> str:
        marker = hardened_dir / ".remote_base"
        if not marker.exists():
            return ""
        return marker.read_text(encoding="utf-8").strip()

    # ------------------------------------------------------------------
    # Path helpers
    # ------------------------------------------------------------------
    def _scan_result_path(self, port: int) -> Path:
        return BASE_DIR / "tmp" / "contracts" / "scan_result" / f"scan_result_{port}.json"

    def _ast_path(self, port: int) -> Path:
        return BASE_DIR / "tmp" / "contracts" / "parsers_output" / f"parser_output_{port}.json"

    def _mod_ast_path(self, port: int) -> Path:
        return BASE_DIR / "tmp" / "contracts" / "mod_asts" / f"mod_ast_{port}.json"

    def _hardened_dir(self, port: int) -> Path:
        return BASE_DIR / "tmp" / "hardened_configs" / str(port)

    def _write_mod_ast(self, port: int, ast: dict) -> None:
        path = self._mod_ast_path(port)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(ast, f, indent=2, ensure_ascii=False)


# ---------------------------------------------------------------------------
# CLI Entry Point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="SecRemedy Remedy Engine — Safe Auto-Remediation"
    )
    parser.add_argument("--dry-run", action="store_true", help="Run Steps 1–5 (no remote push)")
    parser.add_argument("--execute", action="store_true", help="Run Step 6 (push hardened config)")
    parser.add_argument("--port", "-P", type=int, required=True, help="SSH port of target server")
    parser.add_argument("--host", default="127.0.0.1", help="Target server IP (execute only)")
    parser.add_argument("--ssh-port", type=int, default=22, help="SSH port for push (execute only)")
    parser.add_argument("--user", default="root", help="SSH username (execute only)")
    parser.add_argument("--pass", dest="password", default=None, help="SSH password (execute only)")
    parser.add_argument("--key", dest="key_path", default=None, help="SSH key path (execute only)")
    args = parser.parse_args()

    engine = RemedyEngine()

    if args.dry_run:
        print(f"[*] Dry-run port {args.port} ...")
        result = engine.dry_run(args.port)
        print(f"[+] Status : {result['status']}")
        print(f"[+] Output : {result['hardened_dir']}")
        if result.get("skipped"):
            print(f"[!] Skipped {len(result['skipped'])} invalid item(s) — see warnings above")
        if result["diff"]:
            print("\n--- UNIFIED DIFF ---")
            print(result["diff"])
        else:
            print("[=] No changes needed.")

    elif args.execute:
        creds = {
            "host": args.host,
            "port": args.ssh_port,
            "username": args.user,
            "password": args.password,
            "key_path": args.key_path,
        }
        print(f"[*] Execute port {args.port} → {args.host}:{args.ssh_port} ...")
        result = engine.execute(args.port, creds)
        print(f"[+] Status : {result['status']}")
        if result.get("error"):
            print(f"[-] Error  : {result['error']}")

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
