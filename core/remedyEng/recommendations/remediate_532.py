from core.recom_registry import RECOMMENDATION_REGISTRY, RecomID
from core.remedyEng.base_remedy import BaseRemedy
from core.remedyEng.ast_editor import ASTEditor
import copy

REMEDY_FIX_EXAMPLE = """Rule 5.3.2 Example (Content Security Policy Header):

Implements a robust CSP to prevent XSS and data injection attacks.

Default baseline policy (high security):
  default-src 'self'; frame-ancestors 'self'; form-action 'self';

This can be customized based on your application's needs.

Result: add_header Content-Security-Policy "<policy>" always;
placed in the http, server, or location block

Verify:
✓ curl -I http://your-server | grep -i 'Content-Security-Policy'
  (Should show the CSP header)
✓ Browser DevTools Console
  (Check for CSP violations for resources not in whitelist)

Impact: Medium. Risk of breaking application if CSP is too strict.
Recommendation: Start with Report-Only mode to debug violations.
"""
REMEDY_INPUT_REQUIRE = [
    "Use secure CSP baseline? (yes/no) [default: yes]:",
    "Enter custom CSP policy (or leave blank for baseline):"
]


class Remediate532(BaseRemedy):
    def __init__(self) -> None:
        super().__init__(RECOMMENDATION_REGISTRY[RecomID.CIS_5_3_2])
        self.has_input = True
        self.has_guide_detail = True
        self.remedy_guide_detail = REMEDY_FIX_EXAMPLE
        self.remedy_input_require = REMEDY_INPUT_REQUIRE
        self.default_csp = "default-src 'self'; frame-ancestors 'self'; form-action 'self';"

    def _get_csp_policy(self) -> str:
        """
        Determine which CSP policy to use based on user input.
        
        Returns:
            CSP policy string
        """
        if not self.user_inputs or len(self.user_inputs) < 2:
            return self.default_csp
        
        use_baseline = self.user_inputs[0].strip().lower()
        custom_csp = self.user_inputs[1].strip() if len(self.user_inputs) > 1 else ""
        
        # If user provided custom CSP, use it
        if custom_csp:
            return custom_csp
        
        # Otherwise use baseline (default behavior if user didn't explicitly reject it)
        if use_baseline in ["no", "n", "false", "0"]:
            # User explicitly rejected baseline and provided no custom - use minimal policy
            return "default-src 'self';"
        
        return self.default_csp

    def remediate(self) -> None:
        """
        Apply remediation for Rule 5.3.2: Ensure CSP is enabled and properly configured.
        
        Action: ADD/REPLACE - Adds or replaces Content-Security-Policy header
        User can choose between secure baseline or custom policy.
        """
        self.child_ast_modified = {}
        
        # Get the CSP policy to use
        csp_policy = self._get_csp_policy()
        
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
                
                # For rule 5.3.2, handle both "add" and "replace" actions
                if directive != "add_header":
                    continue

                exact_path = self._relative_context(violation.get("exact_path", []))
                if not exact_path:
                    continue

                if action == "add":
                    # For add: exact_path points to the index where we should insert
                    # Extract parent path (all but last element) and target index
                    parent_path = exact_path[:-1] if len(exact_path) > 1 else []
                    parent = ASTEditor.get_child_ast_config(parsed_copy, parent_path) if parent_path else parsed_copy
                    
                    if isinstance(parent, list):
                        self._upsert_in_block(parent, "add_header", ["Content-Security-Policy", f'"{csp_policy}"', "always"])
                    elif isinstance(parent, dict) and isinstance(parent.get("block"), list):
                        self._upsert_in_block(parent["block"], "add_header", ["Content-Security-Policy", f'"{csp_policy}"', "always"])
                
                elif action == "replace":
                    # For replace: exact_path points directly to the directive to replace
                    target = ASTEditor.get_child_ast_config(parsed_copy, exact_path)
                    if target and isinstance(target, dict) and target.get("directive") == "add_header":
                        target["args"] = ["Content-Security-Policy", f'"{csp_policy}"', "always"]
            
            # Store modified config
            self.child_ast_modified[file_path] = {
                "parsed": parsed_copy
            }

    @staticmethod
    def _upsert_in_block(block_list, directive, args):
        """
        Upsert a directive in a block list.
        For add_header, only updates if the header name matches (compare args[0]).
        Otherwise, appends a new directive.
        """
        if not isinstance(block_list, list) or not args:
            return
        
        # For add_header, match by header name (args[0])
        if directive == "add_header" and len(args) > 0:
            header_name = args[0]
            for item in block_list:
                if (isinstance(item, dict) and 
                    item.get("directive") == directive and 
                    len(item.get("args", [])) > 0 and 
                    item["args"][0] == header_name):
                    # Found existing header with same name, update it
                    item["args"] = copy.deepcopy(args)
                    return
            # No matching header found, append new one
            block_list.append({"directive": directive, "args": copy.deepcopy(args)})
        else:
            # For other directives, use original logic
            for item in block_list:
                if isinstance(item, dict) and item.get("directive") == directive:
                    item["args"] = copy.deepcopy(args)
                    return
            block_list.append({"directive": directive, "args": copy.deepcopy(args)})

    def get_user_guidance(self) -> str:
        """Return guidance for CSP rule."""
        return """Rule 5.3.2 (Content Security Policy - CSP):

This rule requires your input to configure CSP.

What it does:
├─ Adds header: add_header Content-Security-Policy "<policy>" always;
├─ Configurable CSP directives per your application
└─ Applied to http, server, or location blocks

Secure Baseline Policy (Recommended):
├─ default-src 'self'           → Block everything except same-origin
├─ frame-ancestors 'self'       → Prevent clickjacking
└─ form-action 'self'           → Restrict form submissions

Purpose:
├─ Mitigates XSS (Cross-Site Scripting) attacks
├─ Prevents data injection attacks
├─ Replaces X-Frame-Options (more flexible)
└─ Provides visibility via CSP reports

Result - nginx.conf will contain:
http {
  ...
  add_header Content-Security-Policy "default-src 'self'; frame-ancestors 'self'; form-action 'self';" always;
  ...
}

IMPORTANT Risk & Recommendations:
├─ RISK: Strict CSP can break legitimate application resources
├─ SOLUTION 1: Start with Report-Only mode
│  └─ Use: add_header Content-Security-Policy-Report-Only "..."
│  └─ This logs violations without blocking
│
├─ SOLUTION 2: Customize CSP for your app
│  └─ img-src 'self' https://cdn.example.com;
│  └─ script-src 'self' https://trusted-domain.com;
│  └─ style-src 'self' 'unsafe-inline'; (avoid unsafe-inline if possible)
│
└─ Always avoid: unsafe-inline, unsafe-eval (they weaken protection)

Customization Example (if CDN used):
  default-src 'self'; img-src 'self' https://cdn.example.com; 
  frame-ancestors 'self'; form-action 'self';

Verify:
✓ curl -I http://your-server | grep -i 'Content-Security-Policy'
  (Should show the policy)
✓ Browser DevTools Console
  (Check for CSP violations on resources)

Impact: Medium-High. Test thoroughly with Report-Only first!
"""
