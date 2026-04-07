from core.recom_registry import RECOMMENDATION_REGISTRY, RecomID
from core.remedyEng.base_remedy import BaseRemedy
from core.remedyEng.ast_editor import ASTEditor
import copy

REMEDY_FIX_EXAMPLE = "http {\n\n    # Enable global logging using the detailed JSON format from Rec 3.1\n    access_log /var/log/nginx/access.json main_access_json;\n\n    server {\n\n        # Inherits the global log setting, or can be overridden:\n        access_log /var/log/nginx/example.com.access.json main_access_json;\n\n        location / {\n            # ...\n        }\n\n        # Exception: Disable logging for favicon to reduce noise (Optional)\n        location = /favicon.ico {\n            access_log      off;\n            log_not_found   off;\n        }\n    }\n}"
REMEDY_INPUT_REQUIRE = [
    "log_file_path (scope can be global/per_server/location. \nUse format<scope>: path to log file, <scope>: other path log file), ...",
    "log_not_found_control"
]


class Remediate32(BaseRemedy):
    def __init__(self) -> None:
        super().__init__(RECOMMENDATION_REGISTRY[RecomID.CIS_3_2])
        self.has_input = True
        self.has_guide_detail = True
        self.remedy_guide_detail = REMEDY_FIX_EXAMPLE
        self.remedy_input_require = REMEDY_INPUT_REQUIRE

    def remediate(self) -> None:
        """
        Apply remediation for Rule 3.2 (access logging enabled).

        Uses:
        - user_inputs[0]: scoped access_log spec, ex: "global:/var/log/nginx/access.log combined,per_server:/var/log/nginx/srv.log combined"
        - user_inputs[1]: log_not_found control (on/off), optional
        """
        self.child_ast_modified = {}
        if not isinstance(self.child_ast_config, dict) or not self.child_ast_config:
            return

        scoped_spec = self.user_inputs[0] if len(self.user_inputs) > 0 else ""
        log_not_found_value = self.user_inputs[1].strip() if len(self.user_inputs) > 1 else ""
        scope_map = self._parse_scope_map(scoped_spec)

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
                if remediation.get("directive") != "access_log":
                    continue

                context = remediation.get("context", [])
                rel_ctx = self._relative_context(context)
                if not rel_ctx:
                    continue

                scope = self._infer_scope(rel_ctx)
                user_args = self._access_log_args_for_scope(scope_map, scope)
                args = user_args if user_args else remediation.get("args", [])
                if not isinstance(args, list) or not args:
                    continue

                # modify_directive/replace: update target directive args.
                if remediation.get("action") in {"modify_directive", "replace"}:
                    target = ASTEditor.get_child_ast_config(parsed_copy, rel_ctx)
                    if isinstance(target, dict) and target.get("directive") == "access_log":
                        target["args"] = copy.deepcopy(args)

                        # Optional log_not_found control at same block level.
                        if log_not_found_value in {"on", "off"}:
                            self._upsert_sibling_directive(
                                parsed_copy,
                                rel_ctx,
                                "log_not_found",
                                [log_not_found_value],
                            )

                # add/add_directive: add access_log into target directive list.
                elif remediation.get("action") in {"add", "add_directive"}:
                    target_list = ASTEditor.get_child_ast_config(parsed_copy, rel_ctx)
                    if isinstance(target_list, list):
                        self._upsert_in_block(target_list, "access_log", args)
                        if log_not_found_value in {"on", "off"}:
                            self._upsert_in_block(target_list, "log_not_found", [log_not_found_value])

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
    def _parse_scope_map(raw_input: str):
        """Parse 'scope:value,scope:value' to {'scope': ['args', ...]} for access_log."""
        result = {}
        if not isinstance(raw_input, str):
            return result
        items = [item.strip() for item in raw_input.split(",") if item.strip()]
        for item in items:
            if ":" in item:
                scope, value = item.split(":", 1)
                scope_key = scope.strip().lower()
                value_tokens = value.strip().split()
                if scope_key and value_tokens:
                    result[scope_key] = value_tokens
            else:
                fallback_tokens = item.split()
                if fallback_tokens:
                    result["default"] = fallback_tokens
        return result

    @staticmethod
    def _access_log_args_for_scope(scope_map, scope: str):
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

    @staticmethod
    def _upsert_sibling_directive(parsed_data, target_context, directive, args):
        """Upsert sibling directive inside the parent list of target_context."""
        if not isinstance(target_context, list) or not target_context:
            return
        parent_context = target_context[:-1]
        sibling_list = ASTEditor.get_child_ast_config(parsed_data, parent_context)
        if isinstance(sibling_list, list):
            Remediate32._upsert_in_block(sibling_list, directive, args)