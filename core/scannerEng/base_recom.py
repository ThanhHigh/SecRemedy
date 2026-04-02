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

            # Bắt đầu duyệt đệ quy
            self._traverse_ast(
                directives=parsed_ast,
                filepath=filepath,
                # Dành cho Thành viên 1 (VD: ['http', 'server'])
                logical_context=[],
                # Dành cho Thành viên 2 (VD: ['config', 0, 'parsed'])
                exact_path=base_exact_path,
                uncompliances=uncompliances
            )

        # [P2] Gộp các uncompliance trùng file thành 1 entry duy nhất,
        # gom tất cả remediations lại. Khớp với JSON Contract (scan_result.json).
        return self._group_by_file(uncompliances)

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

    def _traverse_ast(self, directives: List[Dict], filepath: str, logical_context: List[str], exact_path: List[Any], uncompliances: List[Dict]):
        """
        Thuật toán duyệt đệ quy (Recursive Traversal) cây AST.
        """
        # Dùng enumerate để lấy index của directive trong list hiện tại
        for idx, directive in enumerate(directives):

            # 1. Tính toán Exact Path cho directive hiện tại
            # VD: ["config", 0, "parsed"] + [5] => ["config", 0, "parsed", 5]
            current_exact_path = exact_path + [idx]

            # 2. Giao directive hiện tại cho Class con đánh giá
            uncompliance = self.evaluate(
                directive, filepath, logical_context, current_exact_path)
            if uncompliance:
                uncompliances.append(uncompliance)

            # 3. Nếu directive này có chứa block con, gọi đệ quy đi sâu vào trong
            if "block" in directive:
                # Cập nhật Logical Context (VD: thêm 'server' vào ['http'])
                new_logical_context = logical_context + \
                    [directive["directive"]]

                # Cập nhật Exact Path (VD: thêm 'block' vào path hiện tại)
                # => ["config", 0, "parsed", 5, "block"]
                new_exact_path = current_exact_path + ["block"]

                self._traverse_ast(
                    directives=directive["block"],
                    filepath=filepath,
                    logical_context=new_logical_context,
                    exact_path=new_exact_path,
                    uncompliances=uncompliances
                )

    def evaluate(self, directive: Dict, filepath: str, logical_context: List[str], exact_path: List[Any]) -> Optional[Dict]:
        """
        Hàm trừu tượng (Abstract method). 
        Các class luật cụ thể BẮT BUỘC phải ghi đè hàm này.
        """
        raise NotImplementedError(
            "Phải ghi đè hàm evaluate() trong class con.")
