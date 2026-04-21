from typing import Dict, List, Any, Optional
from core.scannerEng.base_recom import BaseRecom, RecomID


class Detector511(BaseRecom):
    def __init__(self):
        super().__init__(RecomID.CIS_5_1_1)

    def scan(self, parser_output: Dict[str, Any]) -> List[Dict[str, Any]]:
        uncompliances = []

        # Dùng enumerate để lấy được index của config_file (VD: 0, 1, 2...)
        for config_idx, config_file in enumerate(parser_output.get("config", [])):
            filepath = config_file.get("file", "")

            # Chỉ xử lý các file có đuôi .conf
            if not filepath.endswith(".conf"):
                continue

            parsed_ast = config_file.get("parsed", [])

            # Khởi tạo Exact Path gốc cho file này.
            # VD: ["config", 0, "parsed"]
            base_exact_path = ["config", config_idx, "parsed"]

            # Logic chính của detector 5.1.1

        # Gộp các uncompliance trùng file thành 1 entry duy nhất,
        # gom tất cả remediations lại. Khớp với JSON Contract (scan_result.json).
        return self._group_by_file(uncompliances)
