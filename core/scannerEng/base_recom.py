from typing import List, Dict, Any, Optional
from core.recom_registry import RecomID, RECOMMENDATION_REGISTRY


class BaseRecom:
    def __init__(self, recom_id: RecomID):
        recom = RECOMMENDATION_REGISTRY.get(recom_id)
        if not recom:
            raise ValueError(
                f"Recommendation ID {recom_id} not found in registry.")

        self.id = recom.id.value
        self.title = recom.title
        self.description = recom.description
        self.audit_procedure = recom.audit_procedure
        self.impact = recom.impact
        self.remediation = recom.remediation_procedure

    def _should_skip_block(self, node: Dict[str, Any]) -> bool:
        """
        Kiểm tra xem một block có nên bị bỏ qua khi scan không.
        Mặc định bỏ qua các block 'upstream' hoặc các 'server' block chỉ dùng để redirect HTTPS hoặc drop connection.
        Các detector có thể ghi đè (override) hàm này nếu có logic riêng.
        """
        if not isinstance(node, dict):
            return False

        dir_name = node.get("directive")
        # Bỏ qua upstream blocks vì một số luật chỉ áp dụng cho Virtual Host
        if dir_name == "upstream":
            return True

        if dir_name != "server":
            return False

        block = node.get("block", [])
        has_return_444 = False
        has_return_403 = False
        has_https_redirect = False
        has_catch_all_server_name = False

        for child in block:
            if not isinstance(child, dict):
                continue
            child_dir = child.get("directive")
            args = child.get("args", [])

            if child_dir == "server_name" and len(args) > 0 and args[0] == "_":
                has_catch_all_server_name = True

            if child_dir == "return":
                if len(args) >= 2 and args[0] in ("301", "302", "307", "308") and args[1].startswith("https://"):
                    has_https_redirect = True
                elif len(args) == 1 and args[0].startswith("https://"):
                    has_https_redirect = True
                elif len(args) == 1 and args[0] == "444":
                    has_return_444 = True
                elif len(args) == 1 and args[0] == "403":
                    has_return_403 = True

        return has_return_444 or has_https_redirect or (has_return_403 and has_catch_all_server_name)

    def scan(self, parser_output: Dict[str, Any]) -> List[Dict[str, Any]]:
        raise NotImplementedError("Các detector phải override hàm này")

    def traverse_directive(self, target_directive: str, directives: List[Dict], filepath: str, logical_context: List[str], exact_path: List[Any], state: Any = None) -> List[Dict[str, Any]]:
        """
        Duyệt đệ quy cây AST để tìm các block/directive có tên là `target_directive`.
        Trả về danh sách các matches kèm context và state để dễ dàng xử lý kế thừa ở hàm scan().
        """
        matches = []
        # Dùng enumerate để lấy index của directive trong list hiện tại
        for idx, directive in enumerate(directives):
            line = directive.get("line", 0)
            # Tính toán Exact Path cho directive hiện tại
            # VD: ["config", 0, "parsed"] + [5] => ["config", 0, "parsed", 5]
            current_exact_path = exact_path + [idx]

            # Nếu tìm thấy directive cần tìm
            if directive.get("directive") == target_directive:
                matches.append({
                    "directive": directive,
                    "line": line,
                    "filepath": filepath,
                    "logical_context": logical_context,
                    "exact_path": current_exact_path,
                    "state": state
                })

            # Nếu directive này có chứa block con, gọi đệ quy đi sâu vào trong
            if "block" in directive:
                # Cập nhật Logical Context (VD: thêm 'server' vào ['http'])
                new_logical_context = logical_context + \
                    [directive["directive"]]

                # Cập nhật Exact Path (VD: thêm 'block' vào path hiện tại)
                # => ["config", 0, "parsed", 5, "block"]
                new_exact_path = current_exact_path + ["block"]

                matches.extend(self.traverse_directive(
                    target_directive=target_directive,
                    directives=directive["block"],
                    filepath=filepath,
                    logical_context=new_logical_context,
                    exact_path=new_exact_path,
                    state=state
                ))
        return matches

    @staticmethod
    def _dir(directive: str, args: list = None, block: list = None, line: int = 0) -> dict:
        d = {"directive": directive, "args": args or [], "line": line}
        if block is not None:
            d["block"] = block
        return d

    @staticmethod
    def _group_by_file(uncompliances: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Gộp các uncompliance có cùng 'file' thành một entry duy nhất
        với danh sách 'remediations' được gom lại.
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
