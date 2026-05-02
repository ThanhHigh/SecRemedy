from core.recom_registry import RECOMMENDATION_REGISTRY, RecomID
from core.remedyEng.base_remedy import BaseRemedy
from core.remedyEng.ast_editor import ASTEditor
import copy

REMEDY_FIX_EXAMPLE = """Rule 2.5.1 Example (Disable Server Tokens):

Prevents nginx from advertising its version in response headers
and error pages.

This is a simple directive with no user configuration needed.

Result: server_tokens off;
placed in the http block (or server block for local override)

Verify:
✓ curl -I http://your-server | grep -i server
  (Header should NOT show nginx/version)
✓ Request error page (404, 500, etc.)
  (Should NOT show "nginx" or version)
"""
REMEDY_INPUT_REQUIRE = []


class Remediate251(BaseRemedy):
    def __init__(self) -> None:
        super().__init__(RECOMMENDATION_REGISTRY[RecomID.CIS_2_5_1])
        self.has_input = False
        self.has_guide_detail = True
        self.remedy_guide_detail = REMEDY_FIX_EXAMPLE
        self.remedy_input_require = REMEDY_INPUT_REQUIRE

    def remediate(self) -> None:
        """
        Apply remediation for Rule 2.5.1: Ensure server_tokens directive is set to off.
        
        Action: REPLACE - Sets server_tokens args to ["off"]
        This has no user input - automatically fixes to "off"
        """
        self.child_ast_modified = {}

        # Process each file that has violations
        for file_path, remediations in self.child_ast_config.items():
            if file_path not in self.child_scan_result:
                continue
            
            if not isinstance(remediations, dict) or "parsed" not in remediations:
                continue
            
            # Deep copy the parsed section for modification
            parsed_copy = copy.deepcopy(remediations["parsed"])
            
            # Get violations for this file
            file_violations = self.child_scan_result[file_path]
            if not isinstance(file_violations, list):
                continue
            
            patches = []
            for violation in file_violations:
                if not isinstance(violation, dict):
                    continue

                action = violation.get("action", "")
                context = violation.get("context", [])
                directive = violation.get("directive", "")
                args = violation.get("args", [])

                if directive != "server_tokens":
                    continue
                
                # Only process replace/modify actions - "add" is not relevant for server_tokens
                if action not in {"replace", "modify", "modify_directive"}:
                    continue

                # Convert context to relative path within this file
                relative_context = self._relative_context(context)
                target_contexts = [relative_context] if relative_context else self._find_directive_contexts(parsed_copy, "server_tokens")

                for target_context in target_contexts:
                    if not target_context:
                        continue

                    target = ASTEditor.get_child_ast_config(parsed_copy, target_context)
                    if not isinstance(target, dict) and not isinstance(target, list):
                        continue
                    if isinstance(target, dict) and target.get("directive") != "server_tokens":
                        continue

                    patches.append(
                        {
                            "action": "upsert",
                            "exact_path": target_context,
                            "directive": "server_tokens",
                            "args": args if isinstance(args, list) and args else ["off"],
                            "priority": 0,
                        }
                    )

            parsed_copy = ASTEditor.apply_reverse_path_patches(parsed_copy, patches)
            
            # Store modified config
            self.child_ast_modified[file_path] = {
                "parsed": parsed_copy
            }

    @staticmethod
    def _upsert_in_block(block_list, directive, args):
        if not isinstance(block_list, list):
            return
        for item in block_list:
            if isinstance(item, dict) and item.get("directive") == directive:
                item["args"] = copy.deepcopy(args)
                return
        block_list.append({"directive": directive, "args": copy.deepcopy(args)})

    def get_user_guidance(self) -> str:
        """Return guidance for server_tokens rule."""
        return """Rule 2.5.1 (Disable Server Tokens):

This rule has NO user input - it's automatic.

What it does:
├─ Adds directive: server_tokens off;
├─ Placed in http block (global default)
└─ Can be overridden per server block if needed

Purpose:
├─ Hides nginx version in response headers
├─ Won't display version on error pages
└─ Reduces attack surface (less fingerprinting info)

Result - nginx.conf will contain:
http {
  ...
  server_tokens off;
  ...
}

Verify:
✓ curl -I http://your-server | grep -i server
  (Should NOT show: "Server: nginx/version")
✓ Navigate to 404 page
  (Should NOT mention "nginx")

Impact: No performance impact, purely informational.
"""
