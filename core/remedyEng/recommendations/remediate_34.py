from core.recom_registry import RECOMMENDATION_REGISTRY, RecomID
from core.remedyEng.base_remedy import BaseRemedy
from core.remedyEng.ast_editor import ASTEditor
import copy

REMEDY_FIX_EXAMPLE = "location / {\n\n    # Use 'https' for Zero Trust environments (requires proxy_ssl_verify configuration)\n    # Use 'http' for standard TLS offloading (upstream traffic is unencrypted)\n    proxy_pass <protocol>://example_backend_application;\n\n    # Standard header: Appends the client IP to the list of proxies\n    proxy_set_header X-Forwarded-For    $proxy_add_x_forwarded_for;\n\n    # NGINX-specific header: Sets the direct client IP (useful for apps expecting a single value)\n    proxy_set_header X-Real-IP          $remote_addr;\n\n    # Recommended: Forward the protocol (http vs https)\n    proxy_set_header X-Forwarded-Proto $scheme;\n}"
REMEDY_INPUT_REQUIRE = [
    "proxy_pass",
]


class Remediate34(BaseRemedy):
    def __init__(self) -> None:
        super().__init__(RECOMMENDATION_REGISTRY[RecomID.CIS_3_4])
        self.has_input = True
        self.has_guide_detail = True
        self.remedy_guide_detail = REMEDY_FIX_EXAMPLE
        self.remedy_input_require = REMEDY_INPUT_REQUIRE

    def remediate(self) -> None:
        """
        Apply remediation for Rule 3.4 (forward source IP to upstream).

        Uses user_inputs[0] for proxy_pass value, while applying scanner-provided
        proxy_set_header directives at exact contexts.
        """
        self.child_ast_modified = {}
        if not isinstance(self.child_ast_config, dict) or not self.child_ast_config:
            return

        proxy_pass_value = self.user_inputs[0].strip() if len(self.user_inputs) > 0 else ""

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

                action = remediation.get("action")
                context = remediation.get("context", [])
                rel_ctx = self._relative_context(context)
                if not rel_ctx:
                    continue

                target_list = ASTEditor.get_child_ast_config(parsed_copy, rel_ctx)
                if not isinstance(target_list, list):
                    continue

                # add/add_directive for proxy_set_header from scan result context.
                if action in {"add", "add_directive"} and remediation.get("directive") == "proxy_set_header":
                    args = remediation.get("args", [])
                    if isinstance(args, list) and len(args) >= 2:
                        header_name = args[0]
                        self._upsert_proxy_header(target_list, header_name, args)

                # Keep proxy_pass aligned with user input at the same proxying block.
                if proxy_pass_value:
                    self._upsert_proxy_pass(target_list, proxy_pass_value)

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
    def _upsert_proxy_header(block_list, header_name, args):
        for item in block_list:
            if not isinstance(item, dict):
                continue
            if item.get("directive") != "proxy_set_header":
                continue
            current_args = item.get("args", [])
            if isinstance(current_args, list) and current_args and current_args[0] == header_name:
                item["args"] = copy.deepcopy(args)
                return
        block_list.append({"directive": "proxy_set_header", "args": copy.deepcopy(args)})

    @staticmethod
    def _upsert_proxy_pass(block_list, proxy_pass_value: str):
        args = [proxy_pass_value]
        for item in block_list:
            if isinstance(item, dict) and item.get("directive") == "proxy_pass":
                item["args"] = copy.deepcopy(args)
                return
        block_list.append({"directive": "proxy_pass", "args": copy.deepcopy(args)})