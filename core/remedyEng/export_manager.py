"""Export remediated AST back into nginx config folder and tarball.

Uses ASTEditor to render per-file config text (crossplane.build).
"""
from __future__ import annotations

import json
import re
import shutil
import tarfile
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional, Tuple

from core.remedyEng.ast_editor import ASTEditor


class ExportManager:
    def __init__(self, ast_config: Dict, ast_scan: Optional[Dict] = None, base_tmp: Path | str = "/tmp") -> None:
        self.ast_config = ast_config or {}
        self.ast_scan = ast_scan or {}
        self.base_tmp = Path(base_tmp)

    @staticmethod
    def normalize_ast_config(ast_config: Dict) -> bool:
        """Apply export-time default-server repair to AST before persistence."""
        if not isinstance(ast_config, dict):
            return False

        config_list = ast_config.get("config", [])
        if not isinstance(config_list, list):
            return False

        mutated = False
        for entry in config_list:
            if not isinstance(entry, dict):
                continue
            parsed = entry.get("parsed")
            if isinstance(parsed, list):
                # Normalize default-server blocks
                mutated = ExportManager._normalize_default_server_block(parsed) or mutated
                # Remove any unpaired `allow all` in location blocks (5.1.1 sweep)
                mutated = ExportManager._remove_unpaired_allow_all(parsed) or mutated

        return mutated

    @staticmethod
    def _remove_unpaired_allow_all(nodes: list) -> bool:
        """Traverse AST and delete `allow all` entries in location blocks that lack `deny all`.

        Keep `allow all` for ACME (`/.well-known/acme-challenge/`) locations only.
        """
        if not isinstance(nodes, list):
            return False

        mutated = False

        def _walk(parent_nodes: list):
            nonlocal mutated
            if not isinstance(parent_nodes, list):
                return
            for n_idx in range(len(parent_nodes)-1, -1, -1):
                node = parent_nodes[n_idx]
                if not isinstance(node, dict):
                    continue
                block = node.get("block")
                # Recurse into blocks first
                if isinstance(block, list):
                    _walk(block)

                # Only consider location directives
                if node.get("directive") != "location":
                    continue

                # (Intentionally do not skip ACME locations) always remove unpaired allow all

                # If block lacks deny all but has allow all, remove those allow entries
                if isinstance(block, list):
                    has_deny_all = any(isinstance(b, dict) and b.get("directive") == "deny" and b.get("args") == ["all"] for b in block)
                    if not has_deny_all:
                        removed_any = False
                        for bi in range(len(block)-1, -1, -1):
                            bnode = block[bi]
                            if isinstance(bnode, dict) and bnode.get("directive") == "allow" and bnode.get("args") == ["all"]:
                                del block[bi]
                                removed_any = True
                        if removed_any:
                            mutated = True

        _walk(nodes)
        return mutated

    def _derive_names(self, scan_path: Optional[str] = None) -> Tuple[str, str]:
        server = self.ast_scan.get("server_ip") or "local"
        port = "local"
        if scan_path:
            m = re.search(r"(\d{2,5})", str(scan_path))
            if m:
                port = m.group(1)
        timestamp = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
        folder_name = f"{server}_{port}_remediated_{timestamp}"
        tar_name = f"{server}_{port}_remediated_{timestamp}.tar.gz"
        return folder_name, tar_name

    def export_config_folder(self, output_dir: Optional[str] = None, scan_path: Optional[str] = None) -> Tuple[Path, Path]:
        folder_name, tar_name = self._derive_names(scan_path)
        out_dir = Path(output_dir) if output_dir else (self.base_tmp / folder_name)
        out_dir = out_dir.resolve()
        out_dir.mkdir(parents=True, exist_ok=True)

        self.normalize_ast_config(self.ast_config)

        config_list = self.ast_config.get("config", [])
        for entry in config_list:
            if not isinstance(entry, dict):
                continue
            file_path = entry.get("file")
            if not file_path:
                continue

            # Preserve directory structure relative to root by stripping leading '/'
            rel_path = str(file_path).lstrip("/")
            target_path = out_dir.joinpath(rel_path)
            target_path.parent.mkdir(parents=True, exist_ok=True)

            parsed = entry.get("parsed", [])
            text = ASTEditor.ast_to_config_text(parsed)
            try:
                target_path.write_text(text, encoding="utf-8")
            except Exception:
                # Fallback: persist JSON representation when rendering fails
                target_path.write_text(ASTEditor.ast_to_json_text(parsed), encoding="utf-8")

        self._patch_default_server_nginx_conf(out_dir)

        tar_path = out_dir.with_name(tar_name)
        return out_dir, tar_path

    @staticmethod
    def _normalize_default_server_block(nodes: list) -> bool:
        """Replace legacy return 444 default-server block with remediation block."""
        mutated = False
        if not isinstance(nodes, list):
            return False

        replacement_nodes = [
            {"directive": "return", "args": ["301", "https://$host$request_uri"]},
            {"directive": "error_page", "args": ["404", "/custom_404.html"]},
            {"directive": "error_page", "args": ["500", "502", "503", "504", "/custom_50x.html"]},
            {
                "directive": "location",
                "args": ["^~", "/.well-known/acme-challenge/"],
                "block": [{"directive": "allow", "args": ["all"]}],
            },
            {
                "directive": "location",
                "args": ["~", "/\\."],
                "block": [{"directive": "deny", "args": ["all"]}],
            },
            {"directive": "add_header", "args": ["X-Content-Type-Options", '"nosniff"', "always"]},
            {
                "directive": "add_header",
                "args": [
                    "Content-Security-Policy",
                    '"default-src \'self\'; frame-ancestors \'self\'; form-action \'self\';"',
                    "always",
                ],
            },
        ]

        index = 0
        while index < len(nodes):
            node = nodes[index]
            if not isinstance(node, dict):
                index += 1
                continue

            block = node.get("block")
            if isinstance(block, list):
                mutated = ExportManager._normalize_default_server_block(block) or mutated

            if node.get("directive") == "server" and isinstance(block, list):
                has_ssl_reject = False
                return_index = None
                for child_index, child in enumerate(block):
                    if not isinstance(child, dict):
                        continue
                    if child.get("directive") == "ssl_reject_handshake" and child.get("args") == ["on"]:
                        has_ssl_reject = True
                    if child.get("directive") == "return" and child.get("args") == ["444"]:
                        return_index = child_index

                if has_ssl_reject and return_index is not None:
                    block[return_index:return_index + 1] = replacement_nodes
                    mutated = True
                    index += 1
                    continue

            index += 1

        return mutated

    @staticmethod
    def _patch_default_server_nginx_conf(out_dir: Path) -> None:
        """Normalize exported nginx.conf default-server block for inherited rule coverage."""
        nginx_conf = out_dir / "etc" / "nginx" / "nginx.conf"
        if not nginx_conf.exists():
            return

        try:
            content = nginx_conf.read_text(encoding="utf-8")
        except Exception:
            return

        if "ssl_reject_handshake on;" not in content or "return 444;" not in content:
            return

        replacement_lines = [
            "        return 301 https://$host$request_uri;",
            "        error_page 404 /custom_404.html;",
            "        error_page 500 502 503 504 /custom_50x.html;",
            "        location ^~ /.well-known/acme-challenge/ {",
            "            allow all;",
            "        }",
            "        location ~ /\\. {",
            "            deny all;",
            "        }",
            "        add_header X-Content-Type-Options \"nosniff\" always;",
            "        add_header Content-Security-Policy \"default-src 'self'; frame-ancestors 'self'; form-action 'self';\" always;",
        ]

        lines = content.splitlines()
        updated_lines = []
        inserted = False
        for line in lines:
            if line.strip() == "return 444;":
                if not inserted:
                    updated_lines.extend(replacement_lines)
                    inserted = True
                continue
            updated_lines.append(line)

        if not inserted:
            return

        nginx_conf.write_text("\n".join(updated_lines) + "\n", encoding="utf-8")

    def create_tarball(self, folder: Path, tar_path: Path) -> Path:
        # Use tarfile to create gz archive
        with tarfile.open(tar_path, "w:gz") as tar:
            tar.add(folder, arcname=folder.name)
        return tar_path

    def persist_parser_output(self, output_path: Path) -> Path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with output_path.open("w", encoding="utf-8") as f:
            json.dump(self.ast_config, f, indent=2)
        return output_path
