from core.recom_registry import RECOMMENDATION_REGISTRY, RecomID
from core.remedyEng.base_remedy import BaseRemedy
from core.remedyEng.ast_editor import ASTEditor
import copy

REMEDY_FIX_EXAMPLE = "error_page 404 /404.html;\nerror_page 500 502 503 504 /50x.html;\n\nlocation = /50x.html {\n    root /var/www/html/errors;\n    internal;\n}"
REMEDY_INPUT_REQUIRE = [
    "error_page_40x", 
    "error_page_50x", 
    "location_50x_root",
]


class Remediate252(BaseRemedy):
    def __init__(self) -> None:
        super().__init__(RECOMMENDATION_REGISTRY[RecomID.CIS_2_5_2])
        self.has_input = True
        self.has_guide_detail = True
        self.remedy_guide_detail = REMEDY_FIX_EXAMPLE
        self.remedy_input_require = REMEDY_INPUT_REQUIRE

    def remediate(self) -> None:
        """Apply remediation for Rule 2.5.2 by adding/updating custom error_page directives."""
        self.child_ast_modified = {}
        if not isinstance(self.child_ast_config, dict) or not self.child_ast_config:
            return

        err_40x = self.user_inputs[0].strip() if len(self.user_inputs) > 0 else ""
        err_50x = self.user_inputs[1].strip() if len(self.user_inputs) > 1 else ""
        root_50x = self.user_inputs[2].strip() if len(self.user_inputs) > 2 else ""

        for file_path, file_data in self.child_ast_config.items():
            if file_path not in self.child_scan_result:
                continue
            parsed = file_data.get("parsed") if isinstance(file_data, dict) else None
            if not isinstance(parsed, list):
                continue

            parsed_copy = copy.deepcopy(parsed)
            for remediation in self.child_scan_result[file_path]:
                if not isinstance(remediation, dict):
                    continue
                if remediation.get("action") not in {"add", "add_directive"}:
                    continue
                if remediation.get("directive") != "error_page":
                    continue

                rel_ctx = self._relative_context(remediation.get("context", []))
                target_list = ASTEditor.get_child_ast_config(parsed_copy, rel_ctx)
                if not isinstance(target_list, list):
                    continue

                args = remediation.get("args", [])
                if not isinstance(args, list) or not args:
                    continue

                # Optional user override by category.
                if args and args[0] == "404" and err_40x:
                    args = ["404", err_40x]
                elif args and args[0] == "500" and err_50x:
                    args = ["500", "502", "503", "504", err_50x]

                self._upsert_error_page(target_list, args)

                # Optional location block for custom 50x page root.
                if root_50x:
                    target_50x = err_50x if err_50x else "/custom_50x.html"
                    self._upsert_location_50x(target_list, target_50x, root_50x)

            self.child_ast_modified[file_path] = {"parsed": parsed_copy}

    @staticmethod
    def _relative_context(full_context):
        if not isinstance(full_context, list):
            return []
        try:
            idx = full_context.index("parsed")
            return full_context[idx + 1 :]
        except (ValueError, IndexError):
            return []

    @staticmethod
    def _upsert_error_page(block_list, args):
        if not isinstance(block_list, list):
            return
        key = tuple(args[:-1])
        for item in block_list:
            if not isinstance(item, dict) or item.get("directive") != "error_page":
                continue
            cur_args = item.get("args", [])
            if isinstance(cur_args, list) and tuple(cur_args[:-1]) == key:
                item["args"] = copy.deepcopy(args)
                return
        block_list.append({"directive": "error_page", "args": copy.deepcopy(args)})

    @staticmethod
    def _upsert_location_50x(block_list, page_uri, root_path):
        if not isinstance(block_list, list):
            return
        location_args = ["=", page_uri]
        target = None
        for item in block_list:
            if not isinstance(item, dict):
                continue
            if item.get("directive") == "location" and item.get("args") == location_args:
                target = item
                break
        if target is None:
            target = {"directive": "location", "args": location_args, "block": []}
            block_list.append(target)
        loc_block = target.get("block")
        if not isinstance(loc_block, list):
            target["block"] = []
            loc_block = target["block"]

        Remediate252._upsert_simple(loc_block, "root", [root_path])
        Remediate252._upsert_simple(loc_block, "internal", [])

    @staticmethod
    def _upsert_simple(block_list, directive, args):
        for item in block_list:
            if isinstance(item, dict) and item.get("directive") == directive:
                item["args"] = copy.deepcopy(args)
                return
        block_list.append({"directive": directive, "args": copy.deepcopy(args)})