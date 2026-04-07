from core.recom_registry import RECOMMENDATION_REGISTRY, RecomID
from core.remedyEng.base_remedy import BaseRemedy
from core.remedyEng.ast_editor import ASTEditor
import copy

REMEDY_FIX_EXAMPLE = "server {\n\n    # Listen on standard ports for IPv4 and IPv6\n    listen 80 default_server;\n    listen [::]:80 default_server;\n\n    # Listen for HTTPS (TCP) and QUIC (UDP)\n    listen 443 ssl default_server;\n    listen [::]:443 ssl default_server;\n    listen 443 quic default_server;\n    listen [::]:443 quic default_server;\n\n    # Reject SSL Handshake for unknown domains (Prevents cert leakage)\n    ssl_reject_handshake on;\n\n    # Catch-all name\n    server_name _;\n\n    # Close connection without response (Non-standard code 444)\n    return 444;\n}"
REMEDY_INPUT_REQUIRE = ["server_name"]


class Remediate242(BaseRemedy):
    def __init__(self) -> None:
        super().__init__(RECOMMENDATION_REGISTRY[RecomID.CIS_2_4_2])
        self.has_input = True
        self.has_guide_detail = True
        self.remedy_guide_detail = REMEDY_FIX_EXAMPLE
        self.remedy_input_require = REMEDY_INPUT_REQUIRE

    def remediate(self) -> None:
        """Apply remediation for Rule 2.4.2 at exact scanner contexts."""
        self.child_ast_modified = {}
        if not isinstance(self.child_ast_config, dict) or not self.child_ast_config:
            return

        server_name_override = self.user_inputs[0].strip() if len(self.user_inputs) > 0 else ""

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

                context = remediation.get("context", [])
                rel_ctx = self._relative_context(context)
                target_list = ASTEditor.get_child_ast_config(parsed_copy, rel_ctx)
                if not isinstance(target_list, list):
                    continue

                directive = remediation.get("directive")
                args = remediation.get("args", [])
                if directive in {"return", "ssl_reject_handshake"} and isinstance(args, list):
                    self._upsert_in_block(target_list, directive, args)

                # Optional server_name override for catch-all/default block.
                if server_name_override:
                    self._upsert_in_block(target_list, "server_name", [server_name_override])

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
        if not isinstance(block_list, list):
            return
        for item in block_list:
            if isinstance(item, dict) and item.get("directive") == directive:
                item["args"] = copy.deepcopy(args)
                return
        block_list.append({"directive": directive, "args": copy.deepcopy(args)})