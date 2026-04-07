from core.recom_registry import RECOMMENDATION_REGISTRY, RecomID
from core.remedyEng.base_remedy import BaseRemedy
from core.remedyEng.ast_editor import ASTEditor
import copy

REMEDY_FIX_EXAMPLE = "# Log errors to a specific file with the 'notice' level\nerror_log /var/log/nginx/error.log notice;\n\nhttp {\n    # ...\n}"
REMEDY_INPUT_REQUIRE = [
    "Scope (global/per_server/location)\nLog level (debug/info/notice/warn/error/crit/alert/emerg)\nLog file path\nFORMAT <scope>:<log_file_path>:<log_level>",
]


class Remediate33(BaseRemedy):
    def __init__(self) -> None:
        super().__init__(RECOMMENDATION_REGISTRY[RecomID.CIS_3_3])
        self.has_input = True
        self.has_guide_detail = True
        self.remedy_guide_detail = REMEDY_FIX_EXAMPLE
        self.remedy_input_require = REMEDY_INPUT_REQUIRE

    def remediate(self) -> None:
        """
        Apply remediation for Rule 3.3 (error logging enabled and level set).

        Uses user_inputs[0] format:
        - "<scope>:<log_file_path>:<log_level>"
        - Optional multi-entry: "global:/var/log/nginx/error.log:info,per_server:/var/log/nginx/s1.error.log:notice"
        """
        self.child_ast_modified = {}
        if not isinstance(self.child_ast_config, dict) or not self.child_ast_config:
            return

        spec = self.user_inputs[0] if len(self.user_inputs) > 0 else ""
        scope_map = self._parse_scope_level_map(spec)

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
                if remediation.get("directive") != "error_log":
                    continue

                context = remediation.get("context", [])
                rel_ctx = self._relative_context(context)
                if not rel_ctx:
                    continue

                scope = self._infer_scope(rel_ctx)
                args = self._args_for_scope(scope_map, scope)
                if not args:
                    args = remediation.get("args", [])
                if not isinstance(args, list) or len(args) < 2:
                    continue

                action = remediation.get("action")
                if action in {"modify_directive", "replace"}:
                    target = ASTEditor.get_child_ast_config(parsed_copy, rel_ctx)
                    if isinstance(target, dict) and target.get("directive") == "error_log":
                        target["args"] = copy.deepcopy(args)
                elif action in {"add", "add_directive"}:
                    target_list = ASTEditor.get_child_ast_config(parsed_copy, rel_ctx)
                    if isinstance(target_list, list):
                        self._upsert_in_block(target_list, "error_log", args)

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
    def _infer_scope(relative_context) -> str:
        if not isinstance(relative_context, list):
            return "global"
        block_count = relative_context.count("block")
        if block_count <= 1:
            return "global"
        if block_count == 2:
            return "per_server"
        return "location"

    @staticmethod
    def _parse_scope_level_map(raw_spec: str):
        """Parse 'scope:path:level' entries to {'scope': [path, level]}."""
        result = {}
        if not isinstance(raw_spec, str):
            return result
        items = [item.strip() for item in raw_spec.split(",") if item.strip()]
        for item in items:
            parts = [p.strip() for p in item.split(":")]
            if len(parts) >= 3:
                scope = parts[0].lower()
                path = parts[1]
                level = parts[2]
                if scope and path and level:
                    result[scope] = [path, level]
            elif len(parts) == 2:
                # fallback if scope omitted in user input: path:level
                path = parts[0]
                level = parts[1]
                if path and level:
                    result["default"] = [path, level]
        return result

    @staticmethod
    def _args_for_scope(scope_map, scope: str):
        if not isinstance(scope_map, dict):
            return []
        for key in (scope, "global", "default"):
            if key in scope_map and isinstance(scope_map[key], list):
                return copy.deepcopy(scope_map[key])
        return []

    @staticmethod
    def _upsert_in_block(block_list, directive, args):
        if not isinstance(block_list, list):
            return
        for item in block_list:
            if isinstance(item, dict) and item.get("directive") == directive:
                item["args"] = copy.deepcopy(args)
                return
        block_list.append({"directive": directive, "args": copy.deepcopy(args)})