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

            # Tính toán Exact Path cho directive hiện tại
            # VD: ["config", 0, "parsed"] + [5] => ["config", 0, "parsed", 5]
            current_exact_path = exact_path + [idx]

            # Nếu tìm thấy directive cần tìm
            if directive.get("directive") == target_directive:
                matches.append({
                    "directive": directive,
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
    def _dir(directive: str, args: list = None, block: list = None) -> dict:
        d = {"directive": directive, "args": args or []}
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
