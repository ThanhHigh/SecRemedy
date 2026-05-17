"""
Step 2 — AST Locator

Navigate exact_path trong AST dict để tìm parent_list + index
cần thao tác cho Injector.

exact_path format (từ scan_result.json):
  - Ends with int  → parent = navigate(path[:-1]), index = path[-1]
  - Ends with str  → parent = navigate(path),       index = None (append)
"""

from typing import Any


class ASTLocator:
    def locate(self, ast: dict, exact_path: list) -> tuple[list, int | None]:
        """
        Trả về (parent_list, index).

        parent_list: list cần thao tác (insert / pop / set item).
        index:       vị trí trong list; None => append.
        """
        last = exact_path[-1]
        if isinstance(last, int):
            parent = self._navigate(ast, exact_path[:-1])
            return parent, last
        else:
            parent = self._navigate(ast, exact_path)
            return parent, None

    @staticmethod
    def _navigate(node: Any, path: list) -> Any:
        for key in path:
            node = node[key]
        return node
