"""
Step 4 — Config Builder

crossplane.build() serialize AST đã chỉnh thành text Nginx config.
Build tất cả file trong ast["config"], ghi ra output_dir.
Trả về list đường dẫn file đã ghi.
"""

import crossplane
from pathlib import Path, PurePosixPath


class ConfigBuilder:
    def build(self, ast: dict, output_dir: str, strip_prefix: str = "") -> list[str]:
        """
        Build mỗi config_obj trong ast["config"] thành file text.

        output_dir: thư mục chứa file hardened (sẽ được tạo nếu chưa có).
        strip_prefix: posix prefix bỏ khỏi file path trước khi mirror
                      (vd "/etc/nginx" → tránh tạo cây etc/nginx/... rỗng).
        Trả về: list[str] — absolute path các file đã ghi.

        Mirror cấu trúc thư mục TƯƠNG ĐỐI dưới output_dir để tránh va chạm
        tên khi cùng filename xuất hiện ở nhiều folder (vd sites-available
        vs conf.d).
        """
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)

        strip = PurePosixPath(strip_prefix) if strip_prefix else None

        output_paths: list[str] = []
        for config_obj in ast.get("config", []):
            content = crossplane.build(config_obj["parsed"])

            src = PurePosixPath(config_obj["file"])

            rel_posix: PurePosixPath | None = None
            if strip is not None:
                try:
                    rel_posix = src.relative_to(strip)
                except ValueError:
                    rel_posix = None
            if rel_posix is None:
                rel_posix = PurePosixPath(*src.parts[1:]) if src.is_absolute() else src

            rel = Path(*rel_posix.parts)
            dest = out / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(content, encoding="utf-8")
            output_paths.append(str(dest))

        return output_paths
