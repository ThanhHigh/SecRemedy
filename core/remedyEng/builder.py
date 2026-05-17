"""
Step 4 — Config Builder

crossplane.build() serialize AST đã chỉnh thành text Nginx config.
Build tất cả file trong ast["config"], ghi ra output_dir.
Trả về list đường dẫn file đã ghi.
"""

import crossplane
from pathlib import Path


class ConfigBuilder:
    def build(self, ast: dict, output_dir: str) -> list[str]:
        """
        Build mỗi config_obj trong ast["config"] thành file text.

        output_dir: thư mục chứa file hardened (sẽ được tạo nếu chưa có).
        Trả về: list[str] — absolute path các file đã ghi.
        """
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)

        output_paths: list[str] = []
        for config_obj in ast.get("config", []):
            content = crossplane.build(config_obj["parsed"])
            filename = Path(config_obj["file"]).name
            dest = out / filename
            dest.write_text(content, encoding="utf-8")
            output_paths.append(str(dest))

        return output_paths
