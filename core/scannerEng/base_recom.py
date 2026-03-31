from typing import List, Dict, Any


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
        Nhận vào toàn bộ AST của các file cấu hình và trả về danh sách các recommendation 
        """
        uncompliances = []

        # Duyệt qua từng file cấu hình trong AST
        for config_file in parser_output.get("config", []):
            filepath = config_file.get("file", "")

            # Chỉ xử lý các file có đuôi .conf (bao gồm cả nginx.conf)
            # Bỏ qua các file như mime.types, fastcgi_params, v.v.
            if not filepath.endswith(".conf"):
                continue

            parsed_ast = config_file.get("parsed", [])

            # Bắt đầu duyệt đệ quy vào cây AST của file này
            self._traverse_ast(parsed_ast, filepath,
                               context=[], uncompliances=uncompliances)

        return uncompliances

    def _traverse_ast(self, directives: List[Dict], filepath: str, context: List[str], uncompliances: List[Dict]):
        """
        Thuật toán duyệt đệ quy (Recursive Traversal) cây AST.
        - context: Lưu vết đường đi (VD: ['http', 'server']) để biết directive đang nằm ở đâu.
        """
        for directive in directives:
            # 1. Giao directive hiện tại cho Class con đánh giá
            violation = self.evaluate(directive, filepath, context)
            if violation:
                uncompliances.append(violation)

            # 2. Nếu directive này có chứa block con (VD: http { ... }, server { ... })
            # thì gọi đệ quy để đi sâu vào trong.
            if "block" in directive:
                # Cập nhật context để biết đang đi vào block nào
                new_context = context + [directive["directive"]]
                self._traverse_ast(
                    directive["block"], filepath, new_context, uncompliances)

    def evaluate(self, directive: Dict, filepath: str, context: List[str]) -> Dict:
        """
        Hàm trừu tượng (Abstract method). 
        Các class luật cụ thể (như Detector241) BẮT BUỘC phải ghi đè hàm này.
        """
        raise NotImplementedError(
            "Phải ghi đè hàm evaluate() trong class con.")
