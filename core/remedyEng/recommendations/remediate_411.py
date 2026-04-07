from core.recom_registry import RECOMMENDATION_REGISTRY, RecomID
from core.remedyEng.base_remedy import BaseRemedy
from core.remedyEng.ast_editor import ASTEditor
import copy

REMEDY_FIX_EXAMPLE = "server {\n    listen 80;\n\n    server_name cisecurity.org;\n\n    return 301 https://$host$request_uri;\n}"
REMEDY_INPUT_REQUIRE = [
    "server_name",
    "redirect_code",
    "redirect_target"
]


class Remediate411(BaseRemedy):
    def __init__(self) -> None:
        super().__init__(RECOMMENDATION_REGISTRY[RecomID.CIS_4_1_1])
        self.has_input = True
        self.has_guide_detail = True
        self.remedy_guide_detail = REMEDY_FIX_EXAMPLE
        self.remedy_input_require = REMEDY_INPUT_REQUIRE

    def remediate(self) -> None:
        """Apply remediation for Rule 4.1.1 by adding/updating HTTP->HTTPS return directives."""
        self.child_ast_modified = {}
        if not isinstance(self.child_ast_config, dict) or not self.child_ast_config:
            return

        server_name = self.user_inputs[0].strip() if len(self.user_inputs) > 0 else ""
        redirect_code = self.user_inputs[1].strip() if len(self.user_inputs) > 1 else ""
        redirect_target = self.user_inputs[2].strip() if len(self.user_inputs) > 2 else ""

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
                if remediation.get("action") not in {"add", "add_directive", "modify_directive", "replace"}:
                    continue
                if remediation.get("directive") != "return":
                    continue

                rel_ctx = self._relative_context(remediation.get("context", []))
                target = ASTEditor.get_child_ast_config(parsed_copy, rel_ctx)

                args = remediation.get("args", [])
                if redirect_code and redirect_target:
                    args = [redirect_code, redirect_target]
                if not isinstance(args, list) or len(args) < 2:
                    continue

                # Context can point to directive list or to existing directive.
                if isinstance(target, list):
                    self._upsert_in_block(target, "return", args)
                    if server_name:
                        self._upsert_in_block(target, "server_name", [server_name])
                elif isinstance(target, dict):
                    if target.get("directive") == "return":
                        target["args"] = copy.deepcopy(args)
                    # If context is exact directive, also upsert server_name in parent block.
                    if server_name and rel_ctx:
                        parent = ASTEditor.get_child_ast_config(parsed_copy, rel_ctx[:-1])
                        if isinstance(parent, list):
                            self._upsert_in_block(parent, "server_name", [server_name])

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
    def _upsert_in_block(block_list, directive, args):
        for item in block_list:
            if isinstance(item, dict) and item.get("directive") == directive:
                item["args"] = copy.deepcopy(args)
                return
        block_list.append({"directive": directive, "args": copy.deepcopy(args)})
        