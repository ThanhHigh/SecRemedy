from typing import List, Dict, Any, Optional


class BaseRecom:
    def __init__(self):
        self.id = "0.0.0"
        self.title = "Base Recommendation Title"
        self.description = "Base Recommendation Description"
        self.audit_procedure = "Base Recommendation Audit Procedure"
        self.impact = "Base Recommendation Impact"
        self.remediation = "Base Recommendation Remediation"

    def scan(self, parser_output: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Hàm chính được gọi bởi Scanner Engine.
        Nhận vào toàn bộ AST của các file cấu hình và trả về danh sách các uncompliances.
        Các class luật cụ thể BẮT BUỘC phải ghi đè hàm này.
        """
        raise NotImplementedError("Phải ghi đè hàm scan() trong class con.")

    @staticmethod
    def _group_by_file(uncompliances: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Gộp các uncompliance có cùng 'file' thành một entry duy nhất
        với danh sách 'remediations' được gom lại.
        VD: [{"file": "a.conf", "remediations": [r1]}, {"file": "a.conf", "remediations": [r2]}]
         => [{"file": "a.conf", "remediations": [r1, r2]}]
        """
        grouped: Dict[str, Dict[str, Any]] = {}
        for item in uncompliances:
            filepath = item.get("file", "")
            if filepath not in grouped:
                grouped[filepath] = {
                    "file": filepath,
                    "remediations": []
                }
            grouped[filepath]["remediations"].extend(
                item.get("remediations", [])
            )
        return list(grouped.values())
