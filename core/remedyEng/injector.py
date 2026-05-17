"""
Step 3 — AST Injector

Thực thi action (add / replace / delete) trực tiếp trên AST in-memory.
Gọi ASTLocator để tìm parent_list + index, rồi modify in-place.

Thứ tự apply: caller phải sort remediations DESC by line
để tránh index-shift khi có nhiều thay đổi trong cùng 1 block.
"""

from core.remedyEng.reader import RemediationItem
from core.remedyEng.locator import ASTLocator


class ASTInjector:
    def __init__(self) -> None:
        self._locator = ASTLocator()

    def apply(self, ast: dict, item: RemediationItem) -> None:
        """Modify ast in-place theo item.action."""
        parent, index = self._locator.locate(ast, item.exact_path)

        if item.action == "add":
            self._add(parent, index, item)
        elif item.action == "replace":
            self._replace(parent, index, item)
        elif item.action == "delete":
            self._delete(parent, index, item)
        else:
            raise ValueError(f"Unknown action: {item.action!r}")

    # ------------------------------------------------------------------
    def _build_node(self, item: RemediationItem) -> dict:
        node: dict = {"directive": item.directive, "args": item.args}
        if item.block:
            node["block"] = item.block
        return node

    def _add(self, parent: list, index: int | None, item: RemediationItem) -> None:
        node = self._build_node(item)
        if index is None:
            parent.append(node)
        else:
            parent.insert(index, node)

    def _replace(self, parent: list, index: int | None, item: RemediationItem) -> None:
        if index is None:
            raise ValueError(
                f"replace requires integer index in exact_path — directive={item.directive!r}"
            )
        parent[index] = self._build_node(item)

    def _delete(self, parent: list, index: int | None, item: RemediationItem) -> None:
        if index is None:
            raise ValueError(
                f"delete requires integer index in exact_path — directive={item.directive!r}"
            )
        parent.pop(index)
