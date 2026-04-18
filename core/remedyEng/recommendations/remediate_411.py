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
        
        # Must start with https:// or contain nginx variables (like $host, $scheme)
        if not ("https://" in redirect_target or "$" in redirect_target):
            return (False, f"Redirect target must start with 'https://' or use nginx variables (like $host). Got: {redirect_target}")
        
        # Warn if using http:// instead of https://
        if redirect_target.startswith("http://"):
            return (False, f"Redirect target should use https://, not http://. Got: {redirect_target}")
        
        return (True, "")

    def remediate(self) -> None:
        """
        Apply remediation for Rule 4.1.1: Add HTTP->HTTPS redirects.

        User inputs: [redirect_code, redirect_target]
        Example: ["301", "https://$host$request_uri"]
        
        This adds a 'return' directive to redirect HTTP to HTTPS.
        Note: Make sure the server block listens on port 80 (HTTP).
        """
        self.child_ast_modified = {}
        
        # Validate user inputs first
        is_valid, error_msg = self._validate_user_inputs()
        if not is_valid:
            print(f"  Validation error: {error_msg}")
            return
        
        if not isinstance(self.child_ast_config, dict) or not self.child_ast_config:
            return

        redirect_code = self.user_inputs[0].strip() if len(self.user_inputs) > 0 else "301"
        redirect_target = self.user_inputs[1].strip() if len(self.user_inputs) > 1 else "https://$host$request_uri"
        
        # Ensure defaults
        if not redirect_code:
            redirect_code = "301"
        if not redirect_target:
            redirect_target = "https://$host$request_uri"

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
                if remediation.get("action") not in {"add", "add_directive", "modify_directive", "replace"}:
                    continue
                if remediation.get("directive") != "return":
                    continue

                rel_ctx = self._relative_context(remediation.get("context", []))
                target = ASTEditor.get_child_ast_config(parsed_copy, rel_ctx)

                # Build return directive args
                return_args = [redirect_code, redirect_target]

                # Context can point to directive list or to existing directive
                if isinstance(target, list):
                    self._upsert_in_block(target, "return", return_args)
                elif isinstance(target, dict):
                    if target.get("directive") == "return":
                        target["args"] = copy.deepcopy(return_args)
                    elif isinstance(target.get("block"), list):
                        self._upsert_in_block(target["block"], "return", return_args)

            self.child_ast_modified[file_path] = {"parsed": parsed_copy}

    @staticmethod
    def _upsert_in_block(block_list, directive, args):
        """Update or insert directive within a block."""
        for item in block_list:
            if isinstance(item, dict) and item.get("directive") == directive:
                item["args"] = copy.deepcopy(args)
                return
        block_list.append({"directive": directive, "args": copy.deepcopy(args)})

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