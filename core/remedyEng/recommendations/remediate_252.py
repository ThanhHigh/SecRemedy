from core.recom_registry import RECOMMENDATION_REGISTRY, RecomID
from core.remedyEng.base_remedy import BaseRemedy
from core.remedyEng.ast_editor import ASTEditor
import copy
import re

REMEDY_FIX_EXAMPLE = "error_page 404 /404.html;\nerror_page 500 502 503 504 /50x.html;\n\nlocation = /50x.html {\n    root /var/www/html/errors;\n    internal;\n}"
REMEDY_INPUT_REQUIRE = [
    "error_page_40x", 
    "error_page_50x", 
    "location_50x_root",
]
REMEDY_INPUT_DEFAULTS = [
    "/404.html",
    "/50x.html",
    "/var/www/html/errors",
]


class Remediate252(BaseRemedy):
    def __init__(self) -> None:
        super().__init__(RECOMMENDATION_REGISTRY[RecomID.CIS_2_5_2])
        self.has_input = True
        self.has_guide_detail = True
        self.remedy_guide_detail = REMEDY_FIX_EXAMPLE
        self.remedy_input_require = REMEDY_INPUT_REQUIRE
        self.remedy_input_defaults = REMEDY_INPUT_DEFAULTS

    def remediate(self) -> None:
        """Apply remediation for Rule 2.5.2 by adding/updating custom error_page directives."""
        # self.child_ast_modified = {}

        # self.resolve_user_inputs()
        
        # # Validate user inputs first
        # is_valid, error_msg = self._validate_user_inputs()
        # if not is_valid:
        #     print(f"  Validation error: {error_msg}")
        #     return
        
        # if not isinstance(self.child_ast_config, dict) or not self.child_ast_config:
        #     return

        # err_40x = self.user_inputs[0].strip() if len(self.user_inputs) > 0 else ""
        # err_50x = self.user_inputs[1].strip() if len(self.user_inputs) > 1 else ""
        # root_50x = self.user_inputs[2].strip() if len(self.user_inputs) > 2 else ""

        # for file_path, file_data in self.child_ast_config.items():
        #     if file_path not in self.child_scan_result:
        #         continue
        #     parsed = file_data.get("parsed") if isinstance(file_data, dict) else None
        #     if not isinstance(parsed, list):
        #         continue

        #     parsed_copy = copy.deepcopy(parsed)
        #     for remediation in self.child_scan_result[file_path]:
        #         if not isinstance(remediation, dict):
        #             continue
        #         if remediation.get("action") not in {"add", "add_directive"}:
        #             continue
        #         if remediation.get("directive") != "error_page":
        #             continue

        #         rel_ctx = self._relative_context(remediation.get("context", []))
        #         target_list = ASTEditor.get_child_ast_config(parsed_copy, rel_ctx)

        #         # Empty relative context maps to parsed root list; do not insert there.
        #         if isinstance(target_list, list) and rel_ctx == []:
        #             target_list = None

        #         # Context can point to a directive object; if so, try mutating its block list.
        #         if not isinstance(target_list, list) and isinstance(rel_ctx, list):
        #             block_ctx = rel_ctx + ["block"]
        #             block_target = ASTEditor.get_child_ast_config(parsed_copy, block_ctx)
        #             if isinstance(block_target, list):
        #                 rel_ctx = block_ctx
        #                 target_list = block_target

        #         # Fallback to logical nginx scopes. Never inject error_page at AST root.
        #         if not isinstance(target_list, list):
        #             http_blocks = self._find_block_contexts(parsed_copy, "http")
        #             if http_blocks:
        #                 rel_ctx = http_blocks[0]
        #                 target_list = ASTEditor.get_child_ast_config(parsed_copy, rel_ctx)
        #         if not isinstance(target_list, list):
        #             server_blocks = self._find_block_contexts(parsed_copy, "server")
        #             if server_blocks:
        #                 rel_ctx = server_blocks[0]
        #                 target_list = ASTEditor.get_child_ast_config(parsed_copy, rel_ctx)
        #         if not isinstance(target_list, list):
        #             continue

        #         args = remediation.get("args", [])
        #         if not isinstance(args, list) or not args:
        #             continue

        #         # Optional user override by category.
        #         if args and args[0] == "404" and err_40x:
        #             args = ["404", err_40x]
        #         elif args and args[0] == "500" and err_50x:
        #             args = ["500", "502", "503", "504", err_50x]

        #         self._upsert_error_page(target_list, args)

        #         # Optional location block for custom 50x page root.
        #         # Place location in a server block only; location is not valid in http/root.
        #         if root_50x:
        #             target_50x = err_50x if err_50x else "/custom_50x.html"
        #             server_blocks = self._find_block_contexts(parsed_copy, "server")
        #             if server_blocks:
        #                 server_target = ASTEditor.get_child_ast_config(parsed_copy, server_blocks[0])
        #                 if isinstance(server_target, list):
        #                     self._upsert_location_50x(server_target, target_50x, root_50x)

        #     self.child_ast_modified[file_path] = {"parsed": parsed_copy}
        self.child_ast_modified = {}

        self.resolve_user_inputs()
        
        is_valid, error_msg = self._validate_user_inputs()
        if not is_valid:
            print(f"  Validation error: {error_msg}")
            return
        
        if not isinstance(self.child_ast_config, dict) or not self.child_ast_config:
            return

        err_40x = self.user_inputs[0].strip() if len(self.user_inputs) > 0 else ""
        err_50x = self.user_inputs[1].strip() if len(self.user_inputs) > 1 else ""
        root_50x = self.user_inputs[2].strip() if len(self.user_inputs) > 2 else ""

        default_root = "/var/www/html/errors"
        if getattr(self, "remedy_input_defaults", None) and len(self.remedy_input_defaults) > 2:
            default_root = self.remedy_input_defaults[2]

        for file_path, file_data in self.child_ast_config.items():
            if file_path not in self.child_scan_result:
                continue
            file_violations = self.child_scan_result[file_path]
            if not isinstance(file_violations, list) or not file_violations:
                continue
            parsed = file_data.get("parsed") if isinstance(file_data, dict) else None
            if not isinstance(parsed, list):
                continue

            parsed_copy = copy.deepcopy(parsed)
            patches = []
            
            for remediation in file_violations:
                if not isinstance(remediation, dict):
                    continue
                
                action = remediation.get("action", "")
                directive = remediation.get("directive", "")
                context = remediation.get("context", [])
                args = remediation.get("args", [])
                
                if action not in {"add", "add_directive"}:
                    continue
                
                rel_ctx = self._relative_context(context)
                if not rel_ctx:
                    if directive == "error_page":
                        http_blocks = self._find_block_contexts(parsed_copy, "http")
                        if http_blocks:
                            rel_ctx = http_blocks[0]
                    elif directive == "location":
                        server_blocks = self._find_block_contexts(parsed_copy, "server")
                        if server_blocks:
                            rel_ctx = server_blocks[0]
                
                if not rel_ctx:
                    continue

                # error_page directive: add or upsert
                if directive == "error_page":
                    final_args = copy.deepcopy(args)
                    if args and args[0] == "404" and err_40x:
                        final_args = ["404", err_40x]
                    elif args and args[0] == "500" and err_50x:
                        final_args = ["500", "502", "503", "504", err_50x]
                    
                    patches.append({
                        "action": "upsert",
                        "exact_path": rel_ctx,
                        "directive": "error_page",
                        "args": final_args,
                        "priority": 0,
                    })
                
                # location block for 50x: create or update (root falls back to guide default when empty)
                elif directive == "location" and err_50x:
                    root_path = root_50x if root_50x else default_root
                    loc_block = {
                        "directive": "location",
                        "args": ["=", err_50x],
                        "block": [
                            {"directive": "root", "args": [root_path]},
                            {"directive": "internal", "args": []},
                        ]
                    }
                    patches.append({
                        "action": "add_block",
                        "exact_path": rel_ctx,
                        "directive": "location",
                        "block": loc_block,
                        "priority": 0,
                    })

            # 50x location wrapper: scanner often emits only error_page; add or update location = URI for err_50x.
            if err_50x:
                root_path = root_50x if root_50x else default_root
                loc_path = Remediate252._find_location_path_for_uri(parsed_copy, err_50x)
                if loc_path is None:
                    server_blocks = self._find_block_contexts(parsed_copy, "server")
                    if server_blocks:
                        rel_loc = server_blocks[0]
                        loc_block = {
                            "directive": "location",
                            "args": ["=", err_50x],
                            "block": [
                                {"directive": "root", "args": [root_path]},
                                {"directive": "internal", "args": []},
                            ]
                        }
                        patches.append({
                            "action": "add_block",
                            "exact_path": rel_loc,
                            "directive": "location",
                            "block": loc_block,
                            "priority": 0,
                        })
                else:
                    loc_node = ASTEditor.get_child_ast_config(parsed_copy, loc_path)
                    if isinstance(loc_node, dict):
                        inner = loc_node.get("block")
                        if isinstance(inner, list):
                            for ri, child in enumerate(inner):
                                if isinstance(child, dict) and child.get("directive") == "root":
                                    patches.append({
                                        "action": "upsert",
                                        "exact_path": loc_path + ["block", ri],
                                        "directive": "root",
                                        "args": [root_path],
                                        "priority": 0,
                                    })
                                    break

            parsed_copy = ASTEditor.apply_reverse_path_patches(parsed_copy, patches)
            self.child_ast_modified[file_path] = {"parsed": parsed_copy}

    @staticmethod
    def _find_location_path_for_uri(parsed: list, uri: str) -> list | None:
        """Return relative path indices to a location node with args ['=', uri], or None."""

        def walk(nodes: list, prefix: list) -> list | None:
            if not isinstance(nodes, list):
                return None
            for idx, node in enumerate(nodes):
                if not isinstance(node, dict):
                    continue
                if node.get("directive") == "location" and node.get("args") == ["=", uri]:
                    return prefix + [idx]
                blk = node.get("block")
                if isinstance(blk, list):
                    hit = walk(blk, prefix + [idx, "block"])
                    if hit is not None:
                        return hit
            return None

        return walk(parsed, [])

    @staticmethod
    def _upsert_error_page(block_list, args):
        if not isinstance(block_list, list):
            return
        key = tuple(args[:-1])
        for item in block_list:
            if not isinstance(item, dict) or item.get("directive") != "error_page":
                continue
            cur_args = item.get("args", [])
            if isinstance(cur_args, list) and tuple(cur_args[:-1]) == key:
                item["args"] = copy.deepcopy(args)
                return
        block_list.append({"directive": "error_page", "args": copy.deepcopy(args)})

    @staticmethod
    def _upsert_location_50x(block_list, page_uri, root_path):
        if not isinstance(block_list, list):
            return
        location_args = ["=", page_uri]
        target = None
        for item in block_list:
            if not isinstance(item, dict):
                continue
            if item.get("directive") == "location" and item.get("args") == location_args:
                target = item
                break
        if target is None:
            target = {"directive": "location", "args": location_args, "block": []}
            block_list.append(target)
        loc_block = target.get("block")
        if not isinstance(loc_block, list):
            target["block"] = []
            loc_block = target["block"]

        Remediate252._upsert_simple(loc_block, "root", [root_path])
        Remediate252._upsert_simple(loc_block, "internal", [])

    @staticmethod
    def _upsert_simple(block_list, directive, args):
        for item in block_list:
            if isinstance(item, dict) and item.get("directive") == directive:
                item["args"] = copy.deepcopy(args)
                return
        block_list.append({"directive": directive, "args": copy.deepcopy(args)})

    @staticmethod
    def _is_valid_error_page_uri(path: str) -> bool:
        """Validate nginx error_page URI (must be an absolute URI path)."""
        if not isinstance(path, str):
            return False
        value = path.strip()
        if not value:
            return False
        if value.startswith("./"):
            return False
        if not value.startswith("/"):
            return False
        if "://" in value:
            return False
        return True

    @staticmethod
    def _is_valid_root_path(path: str) -> bool:
        """Validate filesystem root path for location root directive."""
        if not isinstance(path, str):
            return False
        value = path.strip()
        if not value:
            return False
        if not value.startswith("/"):
            return False
        if "://" in value:
            return False
        if re.search(r"\s", value):
            return False
        return True
    
    def _validate_user_inputs(self) -> tuple[bool, str]:
        """
        Validate user inputs for Rule 2.5.2 (custom error pages).
        
        Validates paths are not empty and warns if they contain "nginx" (branding).
        """
        err_40x = self.user_inputs[0].strip() if len(self.user_inputs) > 0 else ""
        err_50x = self.user_inputs[1].strip() if len(self.user_inputs) > 1 else ""
        root_50x = self.user_inputs[2].strip() if len(self.user_inputs) > 2 else ""
        
        # At least one error page path required
        if not err_40x and not err_50x:
            return (False, "At least one error page path required (40x or 50x)")
        
        # Validate URI formats.
        if err_40x and not self._is_valid_error_page_uri(err_40x):
            return (False, f"Invalid 40x error_page URI '{err_40x}'. Use absolute URI path like '/404.html'")
        if err_50x and not self._is_valid_error_page_uri(err_50x):
            return (False, f"Invalid 50x error_page URI '{err_50x}'. Use absolute URI path like '/50x.html'")
        if root_50x and not self._is_valid_root_path(root_50x):
            return (False, f"Invalid 50x root path '{root_50x}'. Use absolute filesystem path like '/var/www/html'")

        # Check for nginx branding in error pages
        if err_40x and "nginx" in err_40x.lower():
            print(f"  Warning: Error page may contain nginx branding. Consider: {err_40x}")
        if err_50x and "nginx" in err_50x.lower():
            print(f"  Warning: Error page may contain nginx branding. Consider: {err_50x}")
        
        return (True, "")
    
    def get_user_guidance(self) -> str:
        """
        Provide step-by-step guidance for Rule 2.5.2 user input.
        
        Explains how to create custom error pages to replace default
        nginx error pages.
        """
        guidance = """
╔══════════════════════════════════════════════════════════════════════════════╗
║                  Rule 2.5.2: Replace Default Error Pages                    ║
╚══════════════════════════════════════════════════════════════════════════════╝

WHY THIS MATTERS:
  Default nginx error pages show:
    • Server version (e.g., "nginx/1.24.0")
    • Nginx branding
    • Minimal HTML
  
  This reveals information to attackers and looks unprofessional. This rule
  replaces defaults with custom HTML that:
    • Hides server version and brand
    • Shows professional branded error messages
    • Improves user experience with helpful links/support info

WHAT THIS RULE DOES:
  Adds error_page directives that point to custom HTML files:
    • error_page 404 /404.html;        → Custom 404 Not Found page
    • error_page 500 502 503 504 /50x.html;
                                       → Custom server error page (5xx)
  
  Also creates location block with root and internal flag for serving error pages

STEP-BY-STEP INSTRUCTIONS:

  [STEP 1] 404 Error Page Path
    This is the path to your custom "Not Found" page.
    
    Options:
      • /404.html        → Simple path (creates public location = /404.html)
      • /errors/404.html → Nested in errors directory
      • /static/404.html → In static assets folder
      • Leave blank      → Auto-use /40x.html
    
    Examples:
      ✓ /404.html                      (Simple path at domain root)
      ✓ /errors/404.html               (Organized in subdirectory)
      ✗ /var/www/html/404.html         (Don't use filesystem path - use web path)
      ✗ https://example.com/404.html   (Don't use absolute URL - use relative web path)
      ✗ error404.html                  (Missing leading / - must be absolute web path)

  [STEP 2] 5xx Error Page Path
    This is the path to your custom "Server Error" page (500, 502, 503, 504).
    
    IMPORTANT: These error codes all map to ONE file (not different files).
    This is why nginx groups them: error_page 500 502 503 504 /50x.html;
    
    Options:
      • /50x.html        → Standard name
      • /error.html      → Generic error page
      • /errors/50x.html → In errors directory
      • Leave blank      → Auto-use /50x.html
    
    Examples:
      ✓ /50x.html                      (Standard naming)
      ✓ /error.html                    (Generic handler)
      ✗ /500.html,/502.html,/503.html  (Wrong - must be single path for all 5xx)
      ✗ internal/error.html            (Relative paths not supported - must start with /)

  [STEP 3] 5xx Error Page Root Directory
    Where nginx should find the 50x error page file on disk.
    
    CRITICAL: The root path MUST match your nginx configuration structure.
    
    Common patterns:
    
    PATTERN A: Static files in /var/www/html
      Enter: /var/www/html
      Config result:
        ────────────────────────────────────────
        error_page 500 502 503 504 /50x.html;
        location = /50x.html {
            root /var/www/html;
            internal;
        }
        ────────────────────────────────────────
      File location on disk: /var/www/html/50x.html
    
    PATTERN B: Errors in dedicated subdirectory
      Enter: /var/www/html/errors
      File location on disk: /var/www/html/errors/50x.html
    
    PATTERN C: Per-domain static files
      Enter: /var/www/example.com/public
      File location on disk: /var/www/example.com/public/50x.html
    
    Examples:
      ✓ /var/www/html              (Standard web root)
      ✓ /var/www/example.com/public (Domain-specific root)
      ✗ /var/www                   (Too broad, files not here)
      ✗ /etc/nginx/html            (Nginx config directory, not web files)
      ✗ html                       (Relative path, must be absolute)

CREATE ERROR PAGE FILES:

  On your server, create the HTML files:
  
    # Create 404 error page
    cat > /var/www/html/404.html << 'EOF'
    <!DOCTYPE html>
    <html>
    <head>
        <title>Page Not Found</title>
        <style>
            body { font-family: Arial; text-align: center; margin-top: 100px; }
            h1 { color: #333; }
            p { color: #666; }
        </style>
    </head>
    <body>
        <h1>404 - Page Not Found</h1>
        <p>Sorry, the page you're looking for doesn't exist.</p>
        <p><a href="/">Return to Home</a></p>
    </body>
    </html>
    EOF
    
    # Create 50x error page
    cat > /var/www/html/50x.html << 'EOF'
    <!DOCTYPE html>
    <html>
    <head>
        <title>Server Error</title>
        <style>
            body { font-family: Arial; text-align: center; margin-top: 100px; }
            h1 { color: #c00; }
            p { color: #666; }
        </style>
    </head>
    <body>
        <h1>500 - Server Error</h1>
        <p>Something went wrong on our end. Please try again later.</p>
        <p><a href="/">Return to Home</a></p>
    </body>
    </html>
    EOF

VERIFICATION & TESTING:

  After remediation, check nginx config:
    grep -A 5 "error_page" nginx.conf
  
    Expected output:
    ────────────────────────────────────────────────────────────────
    http {
        ...
        error_page 404 /404.html;
        error_page 500 502 503 504 /50x.html;
        
        location = /50x.html {
            root /var/www/html;
            internal;
        }
    }
    ────────────────────────────────────────────────────────────────
  
    Syntax-oriented checks in remediation flow:
        - run nginx -t in the built-in validation loop
        - review generated diff includes error_page directives and location = /50x.html block

COMMON MISTAKES:
  ✗ Using filesystem paths:      /var/www/html/404.html  (should be /404.html)
  ✗ Absolute URLs:               https://example.com/404  (should be relative /404)
  ✗ Relative paths:              errors/404.html          (should be /errors/404.html)
  ✗ Different files per 5xx code: error_page 500 /500.html 502 /502.html
                                  (nginx only supports one path for all 5xx)
  ✗ Wrong root directory:         root /etc/nginx          (should be web root, not config dir)
  ✗ Missing 'internal' flag:      Exposes internal error pages to anyone

BRANDING BEST PRACTICE:
  Your custom error pages should:
    ✓ Match your site branding (logo, colors)
    ✓ Be helpful (search box, site map link, support contact)
    ✓ NOT reveal server software version
    ✓ NOT contain "nginx", "Apache", "IIS", etc.
  
  Examples of good error messages:
    "Something went wrong. Our team is on it. Email support@example.com"
    "Page not found. Try searching or visit our home page."
    "Service temporarily unavailable. Check back in a few minutes."

────────────────────────────────────────────────────────────────────────────────
PROMPT: Enter comma-separated values:
        1. 404 error page path (e.g., /404.html)
        2. 5xx error page path (e.g., /50x.html)
        3. Root directory for error pages (e.g., /var/www/html)
        """
        return guidance.strip()