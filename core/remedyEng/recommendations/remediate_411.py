from core.recom_registry import RECOMMENDATION_REGISTRY, RecomID
from core.remedyEng.base_remedy import BaseRemedy
from core.remedyEng.ast_editor import ASTEditor
import copy

REMEDY_FIX_EXAMPLE = """Rule 4.1.1 Example (HTTP to HTTPS Redirect):

Redirects unencrypted HTTP requests to encrypted HTTPS.

Typical server block that listens on port 80:
server {
  listen 80;
  listen [::]:80;
  
  server_name example.com www.example.com;
  
  return 301 https://$host$request_uri;
}

This ensures:
├─ All queries to http://example.com → https://example.com
├─ Preserves original URI via $request_uri
├─ Uses 301 (permanent redirect) for SEO benefits
└─ Clients cache the redirect (performance benefit)

Redirect codes:
├─ 301 = Permanent Redirect (clients cache, better for SEO)
├─ 302 = Found/Temporary Redirect (clients don't cache)
├─ 307 = Temporary Redirect (preserves POST method)
└─ CIS recommends: 301 for permanent setup
"""
REMEDY_INPUT_REQUIRE = [
    "Redirect code (301=permanent, 302=temporary, default: 301)",
    "Redirect target (e.g., https://$host$request_uri)",
]


class Remediate411(BaseRemedy):
    def __init__(self) -> None:
        super().__init__(RECOMMENDATION_REGISTRY[RecomID.CIS_4_1_1])
        self.has_input = True
        self.has_guide_detail = True
        self.remedy_guide_detail = REMEDY_FIX_EXAMPLE
        self.remedy_input_require = REMEDY_INPUT_REQUIRE

    def _validate_user_inputs(self) -> tuple[bool, str]:
        """
        Validate user inputs for HTTP->HTTPS redirect.
        
        Checks:
        - Redirect code is 301, 302, or 307
        - Redirect target starts with https:// or contains nginx variables
        
        Returns:
            (is_valid: bool, error_message: str)
        """
        if len(self.user_inputs) < 2:
            # Use defaults
            self.user_inputs = ["301", "https://$host$request_uri"]
            return (True, "")
        
        redirect_code = self.user_inputs[0].strip()
        redirect_target = self.user_inputs[1].strip()
        
        # Validate redirect code
        allowed_codes = ["301", "302", "307"]
        if redirect_code and redirect_code not in allowed_codes:
            return (False, f"Redirect code '{redirect_code}' invalid. Use one of: {', '.join(allowed_codes)}")
        
        # Default to 301 if not specified
        if not redirect_code:
            self.user_inputs[0] = "301"
            redirect_code = "301"
        
        # Validate redirect target
        if not redirect_target:
            return (False, "Redirect target cannot be empty")
        
        # Must be an HTTPS redirect target.
        if not redirect_target.startswith("https://"):
            return (False, f"Redirect target must start with 'https://'. Got: {redirect_target}")
        
        # Warn if using http:// instead of https://
        if redirect_target.startswith("http://"):
            return (False, f"Redirect target should use https://, not http://. Got: {redirect_target}")

        # Require preserving original request path/query to avoid collapsing traffic.
        if "$request_uri" not in redirect_target:
            return (False, "Redirect target must include '$request_uri' to preserve original request path/query")
        
        return (True, "")

    def _build_patches_411(self, all_ast_config=None):
        result = {}
        if not isinstance(self.child_ast_config, dict) or not self.child_ast_config:
            return result

        redirect_code = self.user_inputs[0].strip() if len(self.user_inputs) > 0 else "301"
        redirect_target = self.user_inputs[1].strip() if len(self.user_inputs) > 1 else "https://$host$request_uri"
        if not redirect_code:
            redirect_code = "301"
        if not redirect_target:
            redirect_target = "https://$host$request_uri"

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
                if remediation.get("action") not in {"add", "add_directive", "modify_directive", "replace"}:
                    continue
                if remediation.get("directive") != "return":
                    continue

                raw_path = ASTEditor._extract_context_path(remediation)
                rel_ctx = self._relative_context(raw_path)
                target = ASTEditor.get_child_ast_config(parsed_copy, rel_ctx)

                if isinstance(target, list) and rel_ctx == []:
                    target = None

                fallback_block_ctx = None
                if target is None:
                    server_blocks = self._find_block_contexts(parsed_copy, "server")
                    if server_blocks:
                        fallback_block_ctx = server_blocks[0]
                        target = ASTEditor.get_child_ast_config(parsed_copy, fallback_block_ctx)

                if self._is_ssl_reject_server_block(target):
                    continue

                return_args = [redirect_code, redirect_target]

                if isinstance(target, list):
                    block_ctx = rel_ctx if rel_ctx else fallback_block_ctx
                    if block_ctx is None:
                        continue
                    if not self._context_is_ssl_reject(parsed_copy, block_ctx):
                        patches.append({
                            "action": "upsert",
                            "exact_path": block_ctx,
                            "directive": "return",
                            "args": copy.deepcopy(return_args),
                            "priority": 0,
                        })
                elif isinstance(target, dict):
                    if target.get("directive") == "return":
                        if target.get("args") != ["444"]:
                            parent_ctx = rel_ctx[:-1] if rel_ctx else []
                            patches.append({
                                "action": "upsert",
                                "exact_path": parent_ctx if parent_ctx else rel_ctx,
                                "directive": "return",
                                "args": copy.deepcopy(return_args),
                                "priority": 0,
                            })
                    elif isinstance(target.get("block"), list):
                        if not self._is_ssl_reject_server_block(target.get("block")):
                            patches.append({
                                "action": "upsert",
                                "exact_path": rel_ctx + ["block"],
                                "directive": "return",
                                "args": copy.deepcopy(return_args),
                                "priority": 0,
                            })

            if patches:
                result[file_path] = patches

        # Proactive sweep: every HTTP server block across ALL config files
        # should have a redirect return directive.
        def _has_http_listen(server_block: list) -> bool:
            listens = [n for n in server_block if isinstance(n, dict) and n.get("directive") == "listen"]
            if not listens:
                return True
            for l in listens:
                args = l.get("args", [])
                if "ssl" not in args:
                    return True
            return False

        def _sweep_servers(nodes, prefix):
            sweep_patches = []
            if not isinstance(nodes, list):
                return sweep_patches
            for idx, node in enumerate(nodes):
                if not isinstance(node, dict):
                    continue
                if node.get("directive") == "server" and isinstance(node.get("block"), list):
                    server_ctx = prefix + [idx, "block"]
                    server_block = node.get("block", [])
                    if _has_http_listen(server_block) and not self._is_ssl_reject_server_block(server_block):
                        sweep_patches.append({
                            "action": "upsert",
                            "exact_path": server_ctx,
                            "directive": "return",
                            "args": [redirect_code, redirect_target],
                            "priority": 1,
                        })
                block = node.get("block")
                if isinstance(block, list):
                    sweep_patches.extend(_sweep_servers(block, prefix + [idx, "block"]))
            return sweep_patches

        # Sweep ALL config files from the full AST config (not just scan-violated ones)
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

            sweep_patches = _sweep_servers(parsed, [])
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
        return self._build_patches_411(all_ast_config=self._full_ast_config)

    def remediate(self) -> None:
        """
        Apply remediation for Rule 4.1.1: Add HTTP->HTTPS redirects.

        User inputs: [redirect_code, redirect_target]
        Example: ["301", "https://$host$request_uri"]
        
        This adds a 'return' directive to redirect HTTP to HTTPS.
        Note: Make sure the server block listens on port 80 (HTTP).
        """
        self.child_ast_modified = {}

        self.resolve_user_inputs()

        is_valid, error_msg = self._validate_user_inputs()
        if not is_valid:
            print(f"  Validation error: {error_msg}")
            return

        for file_path, patches in self._build_patches_411().items():
            parsed_copy = copy.deepcopy(self.child_ast_config[file_path]["parsed"])
            parsed_copy = ASTEditor.apply_reverse_path_patches(parsed_copy, patches)
            self.child_ast_modified[file_path] = {"parsed": parsed_copy}

    @staticmethod
    def _is_ssl_reject_server_block(block) -> bool:
        """
        Return True if the given block list belongs to a catch-all SSL-reject server.

        A catch-all SSL-reject server is identified by having:
          ssl_reject_handshake on;
        OR an existing:
          return 444;
        These blocks must NOT be overwritten with return 301.
        """
        if not isinstance(block, list):
            return False
        for item in block:
            if not isinstance(item, dict):
                continue
            directive = item.get("directive", "")
            if directive == "ssl_reject_handshake" and item.get("args") == ["on"]:
                return True
            if directive == "return" and item.get("args") == ["444"]:
                return True
        return False

    @staticmethod
    def _context_is_ssl_reject(parsed_copy: list, rel_ctx: list) -> bool:
        """
        Walk up the context path to find if the enclosing server block is an
        SSL-reject catch-all. Returns True if it is (remedy should skip).
        """
        if not isinstance(rel_ctx, list) or not rel_ctx:
            return False
        # Server blocks are typically at parsed_copy[N] or parsed_copy[N].block[M]
        # We try to find the server directive by walking up the context path.
        from core.remedyEng.ast_editor import ASTEditor
        for trim_len in range(1, len(rel_ctx) + 1):
            candidate_ctx = rel_ctx[:-trim_len]
            if not candidate_ctx:
                candidate = parsed_copy
            else:
                candidate = ASTEditor.get_child_ast_config(parsed_copy, candidate_ctx)
            if isinstance(candidate, dict) and candidate.get("directive") == "server":
                block = candidate.get("block", [])
                if Remediate411._is_ssl_reject_server_block(block):
                    return True
        return False

    def get_user_guidance(self) -> str:
        """Return step-by-step guidance for HTTP->HTTPS redirect."""
        return """Rule 4.1.1 Example (HTTP to HTTPS Redirect):

Forces unencrypted traffic to use encryption.

User inputs:
├─ Input 1: Redirect code
│          Options: 301 (permanent), 302 (temporary), 307 (preserve POST)
│          Default: 301 (recommended by CIS)
│
├─ Input 2: Redirect target
│          Example: https://$host$request_uri
│          Must use https:// or nginx variables
│
└─ Leave empty for smart defaults

Input example: 301, https://$host$request_uri

Nginx variables available:
├─ $host          - Request hostname (without port)
├─ $request_uri   - Original request path and query
├─ $server_name   - Configured server_name
├─ $scheme        - http or https
└─ $http_host     - Host header (may include port)

Result: return 301 https://$host$request_uri;
(added to server block listening on port 80)

HTTP to HTTPS flow:
1. Client: GET http://example.com/page
2. Nginx: return 301 https://example.com/page  
3. Client: (redirect) GET https://example.com/page
4. Nginx: HTTPS server handles request

Redirect codes explained:
├─ 301 (MOVED_PERMANENTLY)
│  └─ Permanent. Clients cache the redirect.
│     Browser remembers future requests should use HTTPS.
│     BEST FOR PRODUCTION - performant & SEO-friendly
│
├─ 302 (FOUND / MOVED_TEMPORARILY)
│  └─ Temporary. Clients don't cache.
│     Every request checks where to go.
│     Use for testing or temporary redirects
│
└─ 307 (TEMPORARY_REDIRECT)
   └─ Temporary, preserves HTTP method.
      Useful if POST data involved (rare for this case)

Important:
├─ This server block MUST listen on port 80 (HTTP)
├─ HTTPS server block on port 443 handles the real request
├─ Without HTTPS listening on 443, redirect destination fails
└─ Certificate must be valid for all server_names used

Verify:
├─ 1. curl -I http://your-server/
│     Should see: HTTP/1.1 301 Moved Permanently
│     Location: https://your-server/
│
├─ 2. curl -I https://your-server/
│     Should see: HTTP/1.1 200 OK
│     (HTTPS server responds)
│
└─ 3. nginx -t (syntax check before reload)
"""