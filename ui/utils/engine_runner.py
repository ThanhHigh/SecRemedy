import os
import sys
import paramiko

_BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, _BASE)

from core.scannerEng.fetcher import NginxFetcher
from core.scannerEng.parser import NginxParser
from core.scannerEng.scanner import Scanner
from core.remedyEng.remedy_engine import RemedyEngine
from ui.utils.path_helpers import parser_output_path, scan_result_path


def run_precheck(server: dict) -> dict:
    """SSH vào server, chạy `nginx -t`, trả về {"ok": bool, "stderr": str}."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            hostname=server["ip"],
            port=server["port"],
            username=server["user"],
            password=server["pass"],
            timeout=10,
        )
        _, stdout, stderr = client.exec_command("nginx -t")
        stdout.channel.recv_exit_status()
        err_text = stderr.read().decode().strip()
        ok = "syntax is ok" in err_text and "test is successful" in err_text
        return {"ok": ok, "stderr": err_text}
    except Exception as e:
        return {"ok": False, "stderr": str(e)}
    finally:
        client.close()


def run_fetch_and_parse(server: dict) -> str:
    """Fetch /etc/nginx từ server, parse AST, ghi parser_output JSON.
    Returns parser_output_path (str).
    """
    port = server["port"]
    local_raw_dir = os.path.join(_BASE, f"tmp/raw_configs/nginx_raw_{port}")
    output_path = parser_output_path(port)

    fetcher = NginxFetcher(
        host=server["ip"],
        port=port,
        username=server["user"],
        password=server["pass"],
    )
    fetcher.connect()
    fetcher.fetch_config(remote_dir="/etc/nginx", local_extract_dir=local_raw_dir)
    fetcher.disconnect()

    parser = NginxParser(base_config_path=local_raw_dir, remote_dir="/etc/nginx")
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    parser.export_to_contract(output_file=output_path)

    return output_path


def run_scan(server: dict) -> dict:
    """Chạy CIS scanner, ghi scan_result JSON. Returns scan_result dict."""
    port = server["port"]
    input_path = parser_output_path(port)
    output_path = scan_result_path(port)

    scanner = Scanner(
        server_ip=server["ip"],
        ssh_port=port,
        ssh_user=server["user"],
        ssh_pass=server["pass"],
        strict_private=server.get("strict_private", False),
        authorized_ports=server.get("authorized_ports"),
        authorized_ips=server.get("authorized_ips"),
    )
    return scanner.run(input_path=input_path, output_path=output_path)


def run_dry_run(port: int, server: dict | None = None) -> dict:
    """Chạy Remediation Engine dry-run. Returns {"diff", "hardened_dir", "output_files", "status"}."""
    scanner_kwargs = None
    if server:
        scanner_kwargs = {
            "server_ip": server.get("ip", "0.0.0.0"),
            "ssh_port": port,
            "ssh_user": server.get("user", "root"),
            "ssh_pass": server.get("pass"),
            "ssh_key": server.get("key"),
            "strict_private": server.get("strict_private", False),
            "authorized_ports": server.get("authorized_ports"),
            "authorized_ips": server.get("authorized_ips"),
        }
    return RemedyEngine().dry_run(port=port, scanner_kwargs=scanner_kwargs)


def run_execute(port: int, ssh_creds: dict) -> dict:
    """Chạy execute sau Approve. Returns {"status": "applied"|"failed", "error"}."""
    return RemedyEngine().execute(port=port, ssh_creds=ssh_creds)
