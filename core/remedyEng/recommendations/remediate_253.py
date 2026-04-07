from core.recom_registry import RECOMMENDATION_REGISTRY, RecomID
from core.remedyEng.base_remedy import BaseRemedy
from core.remedyEng.ast_editor import ASTEditor
import copy

REMEDY_FIX_EXAMPLE = "# Allow Let's Encrypt validation (must be before the deny rule)\nlocation ^~ /.well-known/acme-challenge/ {\n    allow all;\n    default_type \"text/plain\";\n}\n\n# Deny access to all other hidden files\nlocation ~ /\\. {\n    deny all;\n    return 404;\n}"
REMEDY_INPUT_REQUIRE = [
    "server_name",
    "root_path",
]


class Remediate253(BaseRemedy):
    def __init__(self) -> None:
        super().__init__(RECOMMENDATION_REGISTRY[RecomID.CIS_2_5_3])
        self.has_input = True
        self.has_guide_detail = True
        self.remedy_guide_detail = REMEDY_FIX_EXAMPLE
        self.remedy_input_require = REMEDY_INPUT_REQUIRE

    def remediate(self) -> None:
        """Apply remediation for Rule 2.5.3 by adding hidden-file deny location blocks."""
        self.child_ast_modified = {}
        if not isinstance(self.child_ast_config, dict) or not self.child_ast_config:
            return

        server_name = self.user_inputs[0].strip() if len(self.user_inputs) > 0 else ""
        root_path = self.user_inputs[1].strip() if len(self.user_inputs) > 1 else ""

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
                if remediation.get("action") != "add_block":
                    continue
                if remediation.get("directive") != "location":
                    continue

                rel_ctx = self._relative_context(remediation.get("context", []))
                target_list = ASTEditor.get_child_ast_config(parsed_copy, rel_ctx)
                if not isinstance(target_list, list):
                    continue

                location_args = remediation.get("args", ["~", "/\\."])
                location_block = remediation.get("block", [])
                if not isinstance(location_args, list) or not isinstance(location_block, list):
                    continue

                # Optional user-driven extension while preserving scanner baseline.
                block_copy = copy.deepcopy(location_block)
                if root_path:
                    self._upsert_in_block(block_copy, "root", [root_path])

                self._upsert_location_block(target_list, location_args, block_copy)

                # Optional server_name override in same parent block if requested.
                if server_name:
                    self._upsert_in_block(target_list, "server_name", [server_name])

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
    def _upsert_location_block(block_list, args, location_block):
        for item in block_list:
            if not isinstance(item, dict):
                continue
            if item.get("directive") == "location" and item.get("args") == args:
                item["block"] = copy.deepcopy(location_block)
                return
        block_list.append(
            {
                "directive": "location",
                "args": copy.deepcopy(args),
                "block": copy.deepcopy(location_block),
            }
        )

    @staticmethod
    def _upsert_in_block(block_list, directive, args):
        for item in block_list:
            if isinstance(item, dict) and item.get("directive") == directive:
                item["args"] = copy.deepcopy(args)
                return
        block_list.append({"directive": directive, "args": copy.deepcopy(args)})