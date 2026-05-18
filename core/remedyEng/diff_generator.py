"""
Step 5 — Diff Generator

So sánh original AST vs hardened AST (cả hai được build bởi crossplane)
để sinh Unified Diff text gửi lên Frontend UI.

Dùng crossplane.build() để serialize cả hai AST trước khi diff,
đảm bảo format nhất quán và diff chỉ phản ánh thay đổi ngữ nghĩa.
"""

import difflib
import crossplane
from pathlib import Path


class DiffGenerator:
    def generate_per_file_from_ast(self, original_ast: dict, hardened_ast: dict) -> dict[str, str]:
        """
        Build cả hai AST → so sánh từng cặp file → trả dict {remote_path: diff_text}.
        Key là đường dẫn remote (vd /etc/nginx/nginx.conf), value là unified diff (rỗng nếu không đổi).
        """
        result: dict[str, str] = {}

        orig_configs = original_ast.get("config", [])
        hard_configs = hardened_ast.get("config", [])

        for orig_cfg, hard_cfg in zip(orig_configs, hard_configs):
            remote_path = orig_cfg["file"]
            filename = Path(remote_path).name
            orig_lines = crossplane.build(orig_cfg["parsed"]).splitlines(keepends=True)
            hard_lines = crossplane.build(hard_cfg["parsed"]).splitlines(keepends=True)

            diff = difflib.unified_diff(
                orig_lines,
                hard_lines,
                fromfile=f"original/{filename}",
                tofile=f"hardened/{filename}",
            )
            result[remote_path] = "".join(diff)

        return result

    def generate_from_ast(self, original_ast: dict, hardened_ast: dict) -> str:
        """
        Build cả hai AST → so sánh từng cặp file → ghép thành 1 unified diff string.
        """
        return "".join(self.generate_per_file_from_ast(original_ast, hardened_ast).values())

    def generate(self, original_path: str, hardened_path: str) -> str:
        """Diff hai file text trực tiếp (dùng khi đã có file trên disk)."""
        orig = Path(original_path).read_text(encoding="utf-8").splitlines(keepends=True)
        hard = Path(hardened_path).read_text(encoding="utf-8").splitlines(keepends=True)
        filename = Path(original_path).name
        diff = difflib.unified_diff(
            orig,
            hard,
            fromfile=f"original/{filename}",
            tofile=f"hardened/{filename}",
        )
        return "".join(diff)
