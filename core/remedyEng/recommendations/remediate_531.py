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
REMEDY_INPUT_DEFAULTS = ["yes"]


class Remediate531(BaseRemedy):
    def __init__(self) -> None:
        super().__init__(RECOMMENDATION_REGISTRY[RecomID.CIS_5_3_1])
        self.has_input = True
        self.has_guide_detail = True
        self.remedy_guide_detail = REMEDY_FIX_EXAMPLE
        self.remedy_input_require = REMEDY_INPUT_REQUIRE
        self.remedy_input_defaults = REMEDY_INPUT_DEFAULTS

    @staticmethod
    def _generate_sweep_patches(nodes: list, header_args: list) -> list:
        """Generate patches for all server/location blocks missing X-Content-Type-Options."""
        patches: list = []
        INJECTABLE_SCOPES = {"server", "location"}
        header_name = header_args[0] if header_args else ""
        csp_baseline = [
            "Content-Security-Policy",
            "\"default-src 'self'; frame-ancestors 'self'; form-action 'self';\"",
            "always",
        ]

        def _sweep(node_list, path_prefix):
            if not isinstance(node_list, list):
                return
            for idx, node in enumerate(node_list):
                if not isinstance(node, dict):
                    continue
                directive = node.get("directive", "")
                block = node.get("block")

                if directive in INJECTABLE_SCOPES and isinstance(block, list):
                    has_header = any(
                        isinstance(item, dict)
                        and item.get("directive") == "add_header"
                        and isinstance(item.get("args"), list)
                        and len(item["args"]) > 0
                        and item["args"][0] == header_name
                        for item in block
                    )

                    if not has_header:
                        current_path = path_prefix + [idx, "block"]
                        patches.append({
                            "action": "add",
                            "exact_path": current_path,
                            "directive": "add_header",
                            "args": copy.deepcopy(header_args),
                            "priority": 1,
                        })

                    # Repair invalid CSP header when present as empty/legacy value.
                    has_csp = False
                    for child_idx, item in enumerate(block):
                        if not isinstance(item, dict) or item.get("directive") != "add_header":
                            continue
                        args = item.get("args", [])
                        if not isinstance(args, list) or not args:
                            continue
                        if str(args[0]).lower() != "content-security-policy":
                            continue
                        has_csp = True
                        csp_value = str(args[1]).lower() if len(args) >= 2 else ""
                        is_valid = (
                            len(args) >= 3
                            and str(args[-1]).lower() == "always"
                            and "default-src" in csp_value
                            and "frame-ancestors" in csp_value
                            and "unsafe-inline" not in csp_value
                            and "unsafe-eval" not in csp_value
                        )
                        if not is_valid:
                            patches.append({
                                "action": "upsert",
                                "exact_path": path_prefix + [idx, "block", child_idx],
                                "directive": "add_header",
                                "args": copy.deepcopy(csp_baseline),
                                "priority": 1,
                            })
                    if not has_csp:
                        patches.append({
                            "action": "add",
                            "exact_path": path_prefix + [idx, "block"],
                            "directive": "add_header",
                            "args": copy.deepcopy(csp_baseline),
                            "priority": 1,
                        })

                if isinstance(block, list):
                    _sweep(block, path_prefix + [idx, "block"])

        _sweep(nodes, [])
        return patches

    def remediate(self) -> None:
        """
        Apply remediation for Rule 5.3.1: Ensure X-Content-Type-Options header is configured.
        
        Action: ADD/REPLACE - Adds or replaces add_header X-Content-Type-Options "nosniff" always;
        User must confirm before applying.

        Two-phase approach:
        Phase 1 - Process violations listed in the scan result (handles replace actions too).
        Phase 2 - Sweep-walk the entire AST and inject the header into any server/location
                   block that does not have it yet. This covers blocks added by earlier
                   remedies (e.g. 2.4.2 catch-all server, 2.5.3 location blocks) that were
                   not present when the original scan was taken.
        """
        # self.child_ast_modified = {}
        
        # # Check user confirmation
        # if not self.user_inputs:
        #     return
        
        # user_response = self.user_inputs[0].strip().lower()
        # if user_response not in ["yes", "y", "true", "1"]:
        #     # User declined
        #     return
        
        # HEADER_ARGS = ["X-Content-Type-Options", '"nosniff"', "always"]

        # # Process each file that has violations
        # for file_path, remediations in self.child_ast_config.items():
        #     if file_path not in self.child_scan_result:
        #         continue
            
        #     if not isinstance(remediations, dict) or "parsed" not in remediations:
        #         continue
            
        #     # Deep copy the parsed section for modification
        #     parsed_copy = copy.deepcopy(remediations["parsed"])
            
        #     # Get violations for this file
        #     file_violations = self.child_scan_result[file_path]
        #     if not isinstance(file_violations, list):
        #         continue
            
        #     # -- Phase 1: Process violations from scan result --
        #     for violation in file_violations:
        #         if not isinstance(violation, dict):
        #             continue
                
        #         action = violation.get("action", "")
        #         directive = violation.get("directive", "")
        #         args = violation.get("args", [])
        #         header_args = args if args else HEADER_ARGS
                
        #         # For rule 5.3.1, handle both "add" and "replace" actions
        #         if directive != "add_header":
        #             continue
                
        #         exact_path = self._relative_context(violation.get("exact_path", []))
        #         if not exact_path:
        #             continue

        #         if action == "add":
        #             # For add: exact_path points to the block list
        #             parent_path = exact_path[:-1] if len(exact_path) > 1 else []
        #             parent = ASTEditor.get_child_ast_config(parsed_copy, parent_path) if parent_path else parsed_copy
                    
        #             if isinstance(parent, list):
        #                 self._upsert_in_block(parent, "add_header", header_args)
        #             elif isinstance(parent, dict) and isinstance(parent.get("block"), list):
        #                 self._upsert_in_block(parent["block"], "add_header", header_args)
                
        #         elif action == "replace":
        #             # For replace: exact_path points directly to the directive to replace
        #             target = ASTEditor.get_child_ast_config(parsed_copy, exact_path)
        #             if target and isinstance(target, dict) and target.get("directive") == "add_header":
        #                 target["args"] = copy.deepcopy(header_args)
            
        #     # -- Phase 2: Sweep entire AST for any server/location missing the header --
        #     # Covers blocks added by earlier remedies not present in original scan.
        #     self._inject_header_to_all_eligible_blocks(parsed_copy, HEADER_ARGS)

        #     # Store modified config
        #     self.child_ast_modified[file_path] = {
        #         "parsed": parsed_copy
        #     }

        self.child_ast_modified = {}

        self.resolve_user_inputs()

        if not self.user_inputs:
            return

        for file_path, patches in self._build_patches_531().items():
            parsed_copy = copy.deepcopy(self.child_ast_config[file_path]["parsed"])
            parsed_copy = ASTEditor.apply_reverse_path_patches(parsed_copy, patches)
            self.child_ast_modified[file_path] = {"parsed": parsed_copy}

    def _build_patches_531(self):
        result = {}
        if not self.user_inputs:
            return result

        user_response = self.user_inputs[0].strip().lower()
        if user_response not in ["yes", "y", "true", "1"]:
            return result

        HEADER_ARGS = ["X-Content-Type-Options", '"nosniff"', "always"]

        for file_path, remediations in self.child_ast_config.items():
            if file_path not in self.child_scan_result:
                continue

            if not isinstance(remediations, dict) or "parsed" not in remediations:
                continue

            parsed_copy = copy.deepcopy(remediations["parsed"])
            file_violations = self.child_scan_result[file_path]
            if not isinstance(file_violations, list):
                continue

            header_violations = [
                v for v in file_violations
                if isinstance(v, dict) and v.get("directive") == "add_header"
            ]
            if not header_violations:
                continue

            patches = []

            for violation in header_violations:
                action = violation.get("action", "")
                args = violation.get("args", [])

                raw_path = ASTEditor._extract_context_path(violation)
                exact_path = self._relative_context(raw_path) if raw_path else []
                if not exact_path or not ASTEditor.path_is_valid(parsed_copy, exact_path):
                    continue

                header_args = args if args else HEADER_ARGS

                if action == "add":
                    patches.append({
                        "action": "add",
                        "exact_path": exact_path,
                        "directive": "add_header",
                        "args": header_args,
                        "priority": 0,
                    })
                elif action == "replace":
                    patches.append({
                        "action": "upsert",
                        "exact_path": exact_path,
                        "directive": "add_header",
                        "args": header_args,
                        "priority": 0,
                    })

            if header_violations and not patches:
                continue

            sweep_patches = self._generate_sweep_patches(parsed_copy, HEADER_ARGS)
            patches.extend(sweep_patches)

            if patches:
                result[file_path] = patches

        return result

    def collect_patches(self):
        self.resolve_user_inputs()
        return self._build_patches_531()

    @staticmethod
    def _inject_header_to_all_eligible_blocks(nodes: list, header_args: list) -> None:
        r"""
        Recursively walk all server and location blocks in the AST and inject
        add_header X-Content-Type-Options if not already present.

        Only injects into blocks that are valid nginx scopes for security headers:
          - server blocks
          - location blocks
        (http blocks are handled by the scan violations path above)

        Skips blocks that already have the header set.
        """
        if not isinstance(nodes, list):
            return

        INJECTABLE_SCOPES = {"server", "location"}
        header_name = header_args[0] if header_args else ""

        def _walk(node_list: list) -> None:
            if not isinstance(node_list, list):
                return
            for node in node_list:
                if not isinstance(node, dict):
                    continue
                directive = node.get("directive", "")
                block = node.get("block")
                if directive in INJECTABLE_SCOPES and isinstance(block, list):
                    # Check if header already present
                    has_header = any(
                        isinstance(item, dict)
                        and item.get("directive") == "add_header"
                        and isinstance(item.get("args"), list)
                        and len(item["args"]) > 0
                        and item["args"][0] == header_name
                        for item in block
                    )
                    if not has_header:
                        block.append({
                            "directive": "add_header",
                            "args": copy.deepcopy(header_args),
                        })
                    # Always recurse to cover nested location blocks
                    _walk(block)

        _walk(nodes)

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
