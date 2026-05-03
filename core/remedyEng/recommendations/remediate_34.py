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

    # Valid upstream protocols for nginx proxy_pass (CIS 3.4)
    _VALID_PROXY_PROTOCOLS = {"http://", "https://", "grpc://", "grpcs://"}

    def _validate_user_inputs(self) -> tuple[bool, str]:
        """
        Validate user inputs for proxy configuration (optional).

        Accepts: http://, https://, grpc://, grpcs://, unix:
        Rejects: ftp://, no-protocol strings, whitespace-only.

        Returns:
            (is_valid: bool, error_message: str)
        """
        if len(self.user_inputs) > 0 and self.user_inputs[0].strip():
            proxy_pass = self.user_inputs[0].strip()
            # Must start with a valid nginx upstream protocol
            if proxy_pass.startswith("unix:"):
                return (True, "")
            if any(proxy_pass.startswith(proto) for proto in self._VALID_PROXY_PROTOCOLS):
                return (True, "")
            return (
                False,
                f"proxy_pass format invalid: '{proxy_pass}'. "
                "Use http://, https://, grpc://, grpcs://, or unix:"
            )
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

    def _build_patches_34(self, all_ast_config=None):
        result = {}
        if not isinstance(self.child_ast_config, dict) or not self.child_ast_config:
            return result

        proxy_pass_value = self.user_inputs[0].strip() if len(self.user_inputs) > 0 else ""

        # Process scan-violated files first
        for file_path, file_data in self.child_ast_config.items():
            if file_path not in self.child_scan_result:
                continue
            parsed = file_data.get("parsed") if isinstance(file_data, dict) else None
            if not isinstance(parsed, list):
                continue

            parsed_copy = copy.deepcopy(parsed)
            patches = []
            for remediation in self.child_scan_result[file_path]:
                if not isinstance(remediation, dict):
                    continue

                action = remediation.get("action")
                directive_name = remediation.get("directive")
                raw_path = ASTEditor._extract_context_path(remediation)
                rel_ctx = self._relative_context(raw_path)
                if not rel_ctx:
                    continue

                target_list = ASTEditor.get_child_ast_config(parsed_copy, rel_ctx)
                if not isinstance(target_list, list):
                    continue

                if action in {"add", "add_directive"} and directive_name in {"proxy_set_header", "fastcgi_param", "grpc_set_header"}:
                    args = remediation.get("args", [])
                    if isinstance(args, list) and len(args) >= 2:
                        patches.append({
                            "action": "upsert",
                            "exact_path": rel_ctx,
                            "directive": directive_name,
                            "args": copy.deepcopy(args),
                            "priority": 0,
                        })

                if proxy_pass_value:
                    patches.append({
                        "action": "upsert",
                        "exact_path": rel_ctx,
                        "directive": "proxy_pass",
                        "args": [proxy_pass_value],
                        "priority": 1,
                    })

            if patches:
                result[file_path] = patches

        # Proactive sweep across ALL config files: ensure every proxy_pass location
        # carries required X-Forwarded-For and X-Real-IP headers.
        def _sweep(nodes, prefix):
            sweep_patches = []
            if not isinstance(nodes, list):
                return sweep_patches
            for idx, node in enumerate(nodes):
                if not isinstance(node, dict):
                    continue
                block = node.get("block")
                if isinstance(block, list):
                    has_proxy_pass = any(
                        isinstance(c, dict) and c.get("directive") == "proxy_pass" for c in block
                    )
                    if has_proxy_pass:
                        loc_ctx = prefix + [idx, "block"]
                        sweep_patches.append({
                            "action": "upsert",
                            "exact_path": loc_ctx,
                            "directive": "proxy_set_header",
                            "args": ["X-Forwarded-For", "$proxy_add_x_forwarded_for"],
                            "priority": 1,
                        })
                        sweep_patches.append({
                            "action": "upsert",
                            "exact_path": loc_ctx,
                            "directive": "proxy_set_header",
                            "args": ["X-Real-IP", "$remote_addr"],
                            "priority": 1,
                        })
                    sweep_patches.extend(_sweep(block, prefix + [idx, "block"]))
            return sweep_patches

        sweep_source = all_ast_config if isinstance(all_ast_config, dict) else None
        config_list = sweep_source.get("config", []) if sweep_source else []
        if not isinstance(config_list, list):
            config_list = []

        for cfg_entry in config_list:
            if not isinstance(cfg_entry, dict):
                continue
            fp = cfg_entry.get("file", "")
            parsed = cfg_entry.get("parsed")
            if not isinstance(parsed, list):
                continue

            sweep_patches = _sweep(parsed, [])
            if sweep_patches:
                if fp not in result:
                    result[fp] = []
                result[fp].extend(sweep_patches)

        return result

    def collect_patches(self):
        self.resolve_user_inputs()
        is_valid, _ = self._validate_user_inputs()
        if not is_valid:
            return {}
        return self._build_patches_34(all_ast_config=self._full_ast_config)

    def remediate(self) -> None:
        """
        Apply remediation for Rule 3.4: Forward source IP headers to upstream.

        Adds proxy_set_header directives for X-Forwarded-For, X-Real-IP, X-Forwarded-Proto.
        Optional: user_inputs[0] for proxy_pass value (auto-detected if already in config)
        """
        self.child_ast_modified = {}

        self.resolve_user_inputs()

        is_valid, error_msg = self._validate_user_inputs()
        if not is_valid:
            print(f"  Validation error: {error_msg}")
            return

        for file_path, patches in self._build_patches_34().items():
            parsed_copy = copy.deepcopy(self.child_ast_config[file_path]["parsed"])
            parsed_copy = ASTEditor.apply_reverse_path_patches(parsed_copy, patches)
            self.child_ast_modified[file_path] = {"parsed": parsed_copy}
