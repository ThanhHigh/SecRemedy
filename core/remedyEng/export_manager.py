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

        tar_path = out_dir.with_name(tar_name)
        return out_dir, tar_path

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
