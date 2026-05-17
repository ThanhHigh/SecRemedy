#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
run_remedy.py
Dry-run (or execute) remedy_engine on every port in before_remediation.json.
"""

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

def main():
    script_dir = Path(__file__).resolve().parent
    project_root = script_dir.parent
    config_file = project_root / "tests" / "configs" / "before_remediation.json"
    log_dir = project_root / "logs" / "remedy_runs"

    # Parse args
    parser = argparse.ArgumentParser(description="SecRemedy Batch Remedy Engine")
    parser.add_argument("--execute", action="store_true", help="Execute all ports (SSH push)")
    parser.add_argument("--host")
    parser.add_argument("--ssh-port")
    parser.add_argument("--user")
    parser.add_argument("--pass", dest="password")
    parser.add_argument("--key")

    args, unknown = parser.parse_known_args()

    mode = "--execute" if args.execute else "--dry-run"

    extra_args = []
    if args.host: extra_args.extend(["--host", args.host])
    if args.ssh_port: extra_args.extend(["--ssh-port", args.ssh_port])
    if args.user: extra_args.extend(["--user", args.user])
    if args.password: extra_args.extend(["--pass", args.password])
    if args.key: extra_args.extend(["--key", args.key])

    if not config_file.exists():
        print(f"[ERROR] Config not found: {config_file}", file=sys.stderr)
        sys.exit(1)

    log_dir.mkdir(parents=True, exist_ok=True)

    # Python json mod > jq subprocess
    with open(config_file) as f:
        config = json.load(f)

    ports = [str(server["port"]) for server in config.get("servers", [])]
    total = len(ports)

    print("========================================")
    print(" SecRemedy Batch Remedy Engine")
    print(f" Mode    : {mode}")
    print(f" Servers : {total}")
    print(f" Config  : {config_file}")
    print(f" Logs    : {log_dir}")
    print("========================================")
    print()

    ok = 0
    failed = 0
    no_changes = 0

    python_exe = os.environ.get("PYTHON", "python")

    for port in ports:
        log_file = log_dir / f"remedy_{port}.log"
        print(f"[*] Port {port:<6} > ", end="", flush=True)

        cmd = [python_exe, "-m", "core.remedyEng.remedy_engine", mode, "--port", port] + extra_args

        try:
            result = subprocess.run(cmd, cwd=project_root, capture_output=True, text=True)
            output = result.stdout + result.stderr

            log_file.write_text(output)

            if result.returncode != 0:
                print(f"FAILED  (exit {result.returncode}) — see {log_file}")
                failed += 1
            else:
                if "no_changes" in output or "No changes needed" in output:
                    print("NO_CHANGES")
                    no_changes += 1
                else:
                    match = re.search(r"Status\s*:\s*(\S+)", output)
                    status = match.group(1) if match else "ok"
                    print(f"OK  [{status}]")
                    ok += 1
        except Exception as e:
            print(f"FAILED (Error: {e})")
            failed += 1

    print("\n========================================")
    print(" Summary")
    print(f"   Total     : {total}")
    print(f"   OK        : {ok}")
    print(f"   No changes: {no_changes}")
    print(f"   Failed    : {failed}")
    print("========================================")

    sys.exit(1 if failed > 0 else 0)

if __name__ == "__main__":
    main()
