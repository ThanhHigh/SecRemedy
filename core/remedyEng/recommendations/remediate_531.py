from core.recom_registry import RECOMMENDATION_REGISTRY, RecomID
from core.remedyEng.base_remedy import BaseRemedy
from core.remedyEng.ast_editor import ASTEditor
import copy

REMEDY_FIX_EXAMPLE = """Rule 5.3.1 Example (X-Content-Type-Options Header):

Prevents MIME type confusion attacks by instructing browsers
to strictly follow declared Content-Type headers.

This header prevents drive-by download and MIME-sniffing attacks.

Result: add_header X-Content-Type-Options "nosniff" always;
placed in the http, server, or location block

Verify:
✓ curl -I http://your-server | grep -i 'X-Content-Type-Options'
  (Should show: "X-Content-Type-Options: nosniff")
✓ nginx -T 2>/dev/null | grep -i 'X-Content-Type-Options'
  (Should display the directive with "always" parameter)

Impact: Low. Ensures correct MIME types are configured in mime.types.
"""
REMEDY_INPUT_REQUIRE = ["Add X-Content-Type-Options header? (yes/no):"]


class Remediate531(BaseRemedy):
    def __init__(self) -> None:
        super().__init__(RECOMMENDATION_REGISTRY[RecomID.CIS_5_3_1])
        self.has_input = True
        self.has_guide_detail = True
        self.remedy_guide_detail = REMEDY_FIX_EXAMPLE
        self.remedy_input_require = REMEDY_INPUT_REQUIRE

    def remediate(self) -> None:
        """
        Apply remediation for Rule 5.3.1: Ensure X-Content-Type-Options header is configured.
        
        Action: ADD/REPLACE - Adds or replaces add_header X-Content-Type-Options "nosniff" always;
        User must confirm before applying.
        """
        self.child_ast_modified = {}
        
        # Check user confirmation
        if not self.user_inputs:
            return
        
        user_response = self.user_inputs[0].strip().lower()
        if user_response not in ["yes", "y", "true", "1"]:
            # User declined
            return
        
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
            
            # Apply each violation fix
            for violation in file_violations:
                if not isinstance(violation, dict):
                    continue
                
                action = violation.get("action", "")
                directive = violation.get("directive", "")
                args = violation.get("args", [])
                exact_path = violation.get("exact_path", [])
                
                # For rule 5.3.1, handle both "add" and "replace" actions
                if directive != "add_header" or not exact_path:
                    continue
                
                if action == "add":
                    # Add the header directive
                    parent_path = exact_path[:-1] if exact_path else []
                    parent = ASTEditor.get_child_ast_config(parsed_copy, parent_path)
                    
                    if parent and isinstance(parent, list):
                        # Create the new directive
                        new_directive = {
                            "directive": "add_header",
                            "args": args if args else ["X-Content-Type-Options", '"nosniff"', "always"]
                        }
                        parent.append(new_directive)
                
                elif action == "replace":
                    # Replace an existing invalid header
                    target = ASTEditor.get_child_ast_config(parsed_copy, exact_path)
                    if target and isinstance(target, dict) and target.get("directive") == "add_header":
                        target["args"] = args if args else ["X-Content-Type-Options", '"nosniff"', "always"]
            
            # Store modified config
            self.child_ast_modified[file_path] = {
                "parsed": parsed_copy
            }

    def get_user_guidance(self) -> str:
        """Return guidance for X-Content-Type-Options rule."""
        return """Rule 5.3.1 (X-Content-Type-Options Header):

This rule requires your confirmation before applying.

What it does:
├─ Adds header: add_header X-Content-Type-Options "nosniff" always;
├─ Applied to http, server, or location blocks
└─ Prevents MIME type sniffing attacks

Purpose:
├─ Instructs browsers to follow declared Content-Type
├─ Prevents drive-by download attacks
└─ Blocks MIME-confusion vulnerabilities

Result - nginx.conf will contain:
http {
  ...
  add_header X-Content-Type-Options "nosniff" always;
  ...
}

Verify:
✓ curl -I http://your-server | grep -i 'X-Content-Type-Options'
  (Should show: "X-Content-Type-Options: nosniff")
✓ Request an error page (404, 500, etc.)
  (Header should be present even on error responses)

Impact: Very low. Enhances security with minimal performance impact.
Prerequisite: Ensure correct MIME types are configured in mime.types.
"""
