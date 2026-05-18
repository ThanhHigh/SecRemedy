"""
Remedy Engine — Orchestrator (Member 2).

dry_run(port)  → Steps 1–5: đọc scan_result, inject AST, build hardened.conf, sinh diff.
execute(port)  → Step 6: SSH backup + SFTP push (chỉ gọi sau Approve Gate).

File I/O:
  INPUT   tmp/contracts/scan_result/scan_result_<port>.json
  INPUT   tmp/contracts/parsers_output/parser_output_<port>.json
    WORK    tmp/remedy_passes/<port>/pass1/
    WORK    tmp/remedy_passes/<port>/pass2/
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
from core.scannerEng.scanner import Scanner

BASE_DIR = Path(__file__).resolve().parent.parent.parent  # SecRemedy/

# Match "sites-enabled" chỉ khi đứng độc lập (không phải prefix của "sites-enabled-backup" v.v.).
# Lookaround loại trừ kế cận word-char hoặc dấu '-'.
_SITES_ENABLED_RE = re.compile(r"(?<![A-Za-z0-9_-])sites-enabled(?![A-Za-z0-9_-])")

def _remedy_sort_key(item) -> tuple:
    """
    Composite sort key:
    1. Action: delete(0) < replace(1) < add(2)
    2. Directive (if add): location(0) < add_header(1) < others(2)
    3. Path: DESC (để tránh index-shift khi delete/insert)
    """
    # 1. Action priority
    act_map = {"delete": 0, "replace": 1, "add": 2}
    act_prio = act_map.get(item.action, 99)

    # 2. Directive priority (chỉ áp dụng cho 'add')
    dir_prio = 99
    if item.action == "add":
        if item.directive == "location":
            dir_prio = 0
        elif item.directive == "add_header":
            dir_prio = 1
        else:
            dir_prio = 2

    # 3. Path sort (DESC logic)
    # Invert integer indices: 10 -> -10 để sort ASC ra DESC.
    path_key = tuple((0, -x) if isinstance(x, int) else (1, x) for x in item.exact_path)

    # return (act_prio, dir_prio, path_key)
    return (act_prio, path_key)

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
    def dry_run(self, port: int, scanner_kwargs: dict | None = None) -> dict:
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

        first_pass_ast = copy.deepcopy(original_ast)

        # Sort theo exact_path DESC: op ở index cao chạy trước → delete/insert ở
        # index thấp không shift các path đã queue. Stable hơn line-based sort
        # vì line=0 không phản ánh vị trí trong block.
        items_sorted = sorted(items, key=_path_sort_key, reverse=True)

        # # NEW SORTING LOGIC
        # # Sort theo Action -> Directive -> Path DESC
        # items_sorted = sorted(items, key=_remedy_sort_key)

        def _item_to_jsonable(item):
            if hasattr(item, "model_dump"):
                return item.model_dump()
            if hasattr(item, "dict"):
                return item.dict()
            if hasattr(item, "__dict__"):
                return {
                    k: v for k, v in vars(item).items()
                    if not k.startswith("_")
                }
            return str(item)

        # print("[debug] pass1 items_sorted:")
        # print(
        #     json.dumps(
        #         [_item_to_jsonable(it) for it in items_sorted],
        #         ensure_ascii=False,
        #         indent=2,
        #         default=str,
        #     )
        # )

        skipped: list[dict] = []
        first_pass_skipped = self._apply_items(first_pass_ast, items_sorted)
        skipped.extend({**item, "pass": 1} for item in first_pass_skipped)

        # Rewrite "sites-enabled" → "sites-available" trong toàn AST.
        # Nginx convention: sites-available giữ file thật, sites-enabled chỉ symlink.
        # Push hardened config vào sites-available để tránh ghi đè symlink.
        self._rewrite_sites_enabled(first_pass_ast)

        # Dump modified AST pass 1 → tmp/remedy_passes/<port>/pass1/mod_ast.json.
        self._write_mod_ast(port, first_pass_ast, pass_index=1)

        # Step 2b-3b: re-scan pass 1 AST rồi remediate thêm lần nữa.
        second_scan_result = self._run_scan_against_ast(
            port,
            first_pass_ast,
            pass_index=2,
            scanner_kwargs=scanner_kwargs,
        )
        second_items = self._reader.load(str(self._scan_result_path(port, 2)))
        second_items_sorted = sorted(second_items, key=_path_sort_key, reverse=True)

        # print("[debug] pass2 items_sorted:")
        # print(
        #     json.dumps(
        #         [_item_to_jsonable(it) for it in second_items_sorted],
        #         ensure_ascii=False,
        #         indent=2,
        #         default=str,
        #     )
        # )

        final_ast = copy.deepcopy(first_pass_ast)
        second_pass_skipped = self._apply_items(final_ast, second_items_sorted)
        skipped.extend({**item, "pass": 2} for item in second_pass_skipped)

        self._rewrite_sites_enabled(final_ast)
        self._write_mod_ast(port, final_ast)

        # Tính common base (vd "/etc/nginx") để strip khỏi cây hardened_dir.
        # Tránh tạo etc/nginx/... rỗng. Lưu marker để execute() prepend lại.
        remote_base = self._compute_remote_base(final_ast)
        self._write_remote_base(hardened_dir, remote_base)

        # Step 4: Build hardened config files
        output_files = self._builder.build(
            final_ast, str(hardened_dir), strip_prefix=remote_base
        )

        # Step 5: Generate unified diff (per-file + gộp)
        file_diffs = self._diff_gen.generate_per_file_from_ast(original_ast, final_ast)
        diff = "".join(file_diffs.values())

        return {
            "diff": diff,
            "file_diffs": file_diffs,
            "hardened_dir": str(hardened_dir),
            "output_files": output_files,
            "status": "pending",
            "skipped": skipped,
            "passes": [
                {
                    "pass": 1,
                    "scan_result_path": str(scan_result_path),
                    "mod_ast_path": str(self._mod_ast_path(port, 1)),
                    "remediations": [_item_to_jsonable(it) for it in items],
                },
                {
                    "pass": 2,
                    "scan_result_path": str(self._scan_result_path(port, 2)),
                    "mod_ast_path": str(self._mod_ast_path(port)),
                    "scan_result": second_scan_result,
                    "remediations": [_item_to_jsonable(it) for it in second_items],
                },
            ],
        }

    def execute(
        self,
        port: int,
        ssh_creds: dict,
        approved_files: list[str] | None = None,
    ) -> dict:
        """
        Step 6 — chỉ gọi sau Approve Gate.

        ssh_creds keys: host, port, username, password (opt), key_path (opt).
        approved_files: danh sách remote path được approve (vd ["/etc/nginx/nginx.conf"]).
                        None = approve tất cả (hành vi cũ).

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

        if approved_files is not None:
            approved_set = set(approved_files)
            local_files = {lp: rp for lp, rp in local_files.items() if rp in approved_set}
            if not local_files:
                return {"status": "failed", "error": "No approved files match hardened configs"}

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

    def _apply_items(self, ast: dict, items: list) -> list[dict]:
        skipped: list[dict] = []
        for item in items:
            try:
                self._injector.apply(ast, item)
            except (KeyError, IndexError, TypeError, ValueError) as e:
                reason = f"{type(e).__name__}: {e}"
                skipped.append({
                    "file": item.file,
                    "action": item.action,
                    "directive": item.directive,
                    "exact_path": item.exact_path,
                    "reason": reason,
                })
                print(
                    f"[!] Skip invalid item: {item.action} {item.directive} "
                    f"path={item.exact_path} — {reason}"
                )
        return skipped

    def _build_scanner(self, port: int, scanner_kwargs: dict | None = None) -> Scanner:
        if scanner_kwargs:
            return Scanner(**scanner_kwargs)
        return Scanner(ssh_port=port)

    def _run_scan_against_ast(
        self,
        port: int,
        ast: dict,
        pass_index: int,
        scanner_kwargs: dict | None = None,
    ) -> dict:
        input_path = self._ast_path(port, pass_index)
        output_path = self._scan_result_path(port, pass_index)
        self._write_json(input_path, ast)
        scanner = self._build_scanner(port, scanner_kwargs)
        return scanner.run(str(input_path), str(output_path))

    def _write_json(self, path: Path, data: dict) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

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
    def _scan_result_path(self, port: int, pass_index: int | None = None) -> Path:
        if pass_index is None:
            return BASE_DIR / "tmp" / "contracts" / "scan_result" / f"scan_result_{port}.json"
        return self._pass_workspace(port, pass_index) / "scan_result.json"

    def _ast_path(self, port: int, pass_index: int | None = None) -> Path:
        if pass_index is None:
            return BASE_DIR / "tmp" / "contracts" / "parsers_output" / f"parser_output_{port}.json"
        return self._pass_workspace(port, pass_index) / "parser_output.json"

    def _mod_ast_path(self, port: int, pass_index: int | None = None) -> Path:
        if pass_index is None:
            return BASE_DIR / "tmp" / "contracts" / "mod_asts" / f"mod_ast_{port}.json"
        return self._pass_workspace(port, pass_index) / "mod_ast.json"

    def _hardened_dir(self, port: int) -> Path:
        return BASE_DIR / "tmp" / "hardened_configs" / str(port)

    def _pass_workspace(self, port: int, pass_index: int) -> Path:
        return BASE_DIR / "tmp" / "remedy_passes" / str(port) / f"pass{pass_index}"

    def _write_mod_ast(self, port: int, ast: dict, pass_index: int | None = None) -> None:
        self._write_json(self._mod_ast_path(port, pass_index), ast)


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
