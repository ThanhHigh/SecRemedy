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
from pathlib import Path

from core.remedyEng.reader import ScanResultReader
from core.remedyEng.injector import ASTInjector
from core.remedyEng.builder import ConfigBuilder
from core.remedyEng.diff_generator import DiffGenerator
from core.remedyEng.executor import RemoteExecutor

BASE_DIR = Path(__file__).resolve().parent.parent.parent  # SecRemedy/


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

        # Sort DESC by line → inject từ cuối file lên đầu, tránh index shift
        items_sorted = sorted(items, key=lambda x: x.line, reverse=True)
        for item in items_sorted:
            self._injector.apply(hardened_ast, item)

        # Step 4: Build hardened config files
        output_files = self._builder.build(hardened_ast, str(hardened_dir))

        # Step 5: Generate unified diff
        diff = self._diff_gen.generate_from_ast(original_ast, hardened_ast)

        return {
            "diff": diff,
            "hardened_dir": str(hardened_dir),
            "output_files": output_files,
            "status": "pending",
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

        local_files = {
            str(f): f"/etc/nginx/{f.name}"
            for f in hardened_dir.iterdir()
            if f.is_file()
        }

        if not executor.push(local_files):
            return {"status": "failed", "error": "SFTP push failed"}

        return {"status": "applied", "error": None}

    # ------------------------------------------------------------------
    # Path helpers
    # ------------------------------------------------------------------
    def _scan_result_path(self, port: int) -> Path:
        return BASE_DIR / "tmp" / "contracts" / "scan_result" / f"scan_result_{port}.json"

    def _ast_path(self, port: int) -> Path:
        return BASE_DIR / "tmp" / "contracts" / "parsers_output" / f"parser_output_{port}.json"

    def _hardened_dir(self, port: int) -> Path:
        return BASE_DIR / "tmp" / "hardened_configs" / str(port)


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
