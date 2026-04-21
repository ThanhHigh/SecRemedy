from typing import Dict, List, Any, Optional
from core.scannerEng.base_recom import BaseRecom
from core.recom_registry import RecomID


class Detector242(BaseRecom):
    def __init__(self):
        super().__init__(RecomID.CIS_2_4_2)

    def scan(self, parser_output: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Hàm chính được gọi bởi Scanner Engine.
        Nhận vào toàn bộ AST của các file cấu hình và trả về danh sách các uncompliances.
        Kết quả được gộp theo file (mỗi file 1 entry) để khớp với JSON Contract.
        """
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

            # Logic chính của detector 2.4.2

        # Gộp các uncompliance trùng file thành 1 entry duy nhất,
        # gom tất cả remediations lại. Khớp với JSON Contract (scan_result.json).
        return self._group_by_file(uncompliances)