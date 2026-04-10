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

    def _validate_user_inputs(self) -> tuple[bool, str]:
        """
        Validate user inputs for proxy configuration (optional).
        
        Returns:
            (is_valid: bool, error_message: str)
        """
        if len(self.user_inputs) > 0 and self.user_inputs[0].strip():
            proxy_pass = self.user_inputs[0].strip()
            # Basic validation
            if not ("://" in proxy_pass or proxy_pass.startswith("unix:")):
                return (False, f"proxy_pass format invalid: {proxy_pass}. Use format: http://backend or https://backend:port")
        return (True, "")
    
    def get_user_guidance(self) -> str:
        """
        Provide step-by-step guidance for Rule 3.4 user input.
        
        Explains how to configure proxy headers to forward client source IP
        to upstream backend services.
        """
        guidance = """
╔══════════════════════════════════════════════════════════════════════════════╗
║                    Rule 3.4: Forward Source IP to Upstream                  ║
╚══════════════════════════════════════════════════════════════════════════════╝

WHY THIS MATTERS:
  When nginx acts as a reverse proxy, backend servers need to know the CLIENT's
  IP address (not nginx's). By default, they see nginx as the client. This rule
  adds HTTP headers to preserve source IP information.

WHAT THIS RULE DOES:
  Adds three proxy_set_header directives to location blocks with proxy_pass:
    • X-Forwarded-For      → Client's original IP (can be multiple IPs in chain)
    • X-Real-IP            → Client's direct IP (nginx proxy convention)
    • X-Forwarded-Proto    → Original protocol (http or https)
  This allows backend (Java app, Python Flask, etc.) to log real client IP.

STEP-BY-STEP INSTRUCTIONS:
  
  [STEP 1] Identify Backend Upstream Address
    The "proxy_pass" value tells nginx where to send traffic. Examples:
      • http://backend-server:8080        (HTTP backend)
      • https://backend-api.example.com   (HTTPS backend across network)
      • http://127.0.0.1:3000             (Local socket)
      • unix:/tmp/backend.sock             (Unix socket)
    
  [STEP 2] Provide Upstream Address (OPTION A: Auto-detected)
    If your nginx config ALREADY has proxy_pass directives, leave input BLANK.
    The scanner will auto-detect and add headers to existing proxy_pass blocks.
    
    → Just press Enter to auto-detect
  
  [STEP 3] OR Provide Explicit Backend (OPTION B: Manual)
    If you want to add headers to a NEW location block:
      Enter: http://backend-api:8080
      OR:    https://internal-api.local
      OR:    unix:/tmp/app.sock
    
    Must contain "://" or start with "unix:" to be valid.
    Examples:
      ✓ http://api.local:3000          (Valid - HTTP backend)
      ✓ https://secure-api.local       (Valid - HTTPS backend)
      ✓ unix:/var/run/backend.sock     (Valid - Unix socket)
      ✗ api.local:3000                 (Invalid - missing protocol)
      ✗ ftp://server                   (Invalid - FTP not supported for proxying)

VERIFICATION & TESTING:
  
  After remediation, check nginx config:
    # Look for headers added to location blocks
    grep -A 5 "proxy_pass http" nginx.conf
    
    Expected result in http/server/location block:
    ────────────────────────────────────────────────────────────────
    location /api/ {
        proxy_pass http://backend-api:8080;
        
        # Headers added by Rule 3.4:
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
    ────────────────────────────────────────────────────────────────
  
  Syntax-oriented checks in remediation flow:
    - run nginx -t in the built-in validation loop
    - review generated diff to confirm proxy_set_header directives were inserted

COMMON MISTAKES:
  ✗ Forgetting protocol prefix:     api.example.com  (should be http://api.example.com)
  ✗ Wrong proxy_pass format:         @backend         (should be http://... or unix:)
  ✗ Only providing hostname:         api              (should include :port if non-standard)
  ✗ Mixing protocols inconsistently: some http://, some https://

NGINX VARIABLES EXPLAINED (Reference):
  $proxy_add_x_forwarded_for  → Client IP + nginx's received IPs (chain of proxies)
  $remote_addr                → Client IP directly connecting to nginx
  $scheme                     → Protocol (http or https) from original request

BACKEND INTEGRATION NOTES:
  • Python Flask: Use flask.request.headers['X-Real-IP']
  • Node.js Express: Use req.header('x-real-ip') or req.ip (if configured)
  • Java Spring: Use request.getHeader("X-Real-IP")
  • PHP: Use $_SERVER['HTTP_X_REAL_IP']

────────────────────────────────────────────────────────────────────────────────
PROMPT: Enter upstream address (http://..., https://..., or unix:...) or press
        Enter to auto-detect from existing proxy_pass directives.
        """
        return guidance.strip()

    def remediate(self) -> None:
        """
        Apply remediation for Rule 3.4: Forward source IP headers to upstream.

        Adds proxy_set_header directives for X-Forwarded-For, X-Real-IP, X-Forwarded-Proto.
        Optional: user_inputs[0] for proxy_pass value (auto-detected if already in config)
        """
        self.child_ast_modified = {}
        
        # Validate user inputs first
        is_valid, error_msg = self._validate_user_inputs()
        if not is_valid:
            print(f"  Validation error: {error_msg}")
            return
        
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