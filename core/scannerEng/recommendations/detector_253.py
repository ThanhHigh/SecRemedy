from typing import Dict, List, Any, Optional
from core.scannerEng.base_recom import BaseRecom


class Detector253(BaseRecom):
    def __init__(self):
        super().__init__()
        self.id = "2.5.3"
        self.title = "Ensure hidden file serving is disabled (Manual)"
        self.description = "Hidden files and directories (starting with a dot, e.g., .git, .env) often contain sensitive metadata, version control history, or environment configurations. Serving these files should be globally disabled."
        self.audit_procedure = 'Search the loaded configuration for hidden file protection rules using `nginx -T 2>/dev/null | grep "location.*\\\\."` and look for a block like `location ~ /\\. { deny all; ... }`. Optionally, try to access a dummy hidden file and verify it returns a 403 Forbidden or 404 Not Found.'
        self.impact = "Blocking all dot-files will break Let's Encrypt / Certbot validation (.well-known/acme-challenge) unless explicitly allowed. Ensure the exception rule is placed before the deny rule or is more specific."
        self.remediation = "To restrict access to hidden files, add a configuration block denying access to hidden files inside each server block directly, or create a reusable snippet file containing the rules and include it in your server blocks."

    def evaluate(self, directive: Dict, filepath: str, logical_context: List[str], exact_path: List[Any]) -> Optional[Dict]:
        """
        Evaluate recommendation 2.5.3.
        Checks if 'server' blocks have a 'location' directive that denies access to hidden files (starts with dot).
        If missing, suggests adding a block to deny access.
        """
        if directive.get("directive") == "server":
            server_block = directive.get("block", [])
            has_hidden_deny = False

            for d in server_block:
                if d.get("directive") == "location":
                    args = d.get("args", [])
                    # Check if args contain something like '/\.' but is NOT just the default '/\.ht'
                    if any("/\\." in arg and "/\\.ht" not in arg for arg in args):
                        # also check if there's a deny all inside it
                        location_block = d.get("block", [])
                        # print for debugging
                        print()
                        if any(sub.get("directive") == "deny" and sub.get("args", []) == ["all"] for sub in location_block):
                            has_hidden_deny = True
                            break

            if not has_hidden_deny:
                return {
                    "file": filepath,
                    "remediations": [
                        {
                            "action": "add_block",
                            "context": exact_path + ["block"],
                            "directive": "location",
                            "args": ["~", "/\\."],
                            "block": [
                                {
                                    "directive": "deny",
                                    "args": ["all"]
                                },
                                {
                                    "directive": "access_log",
                                    "args": ["off"]
                                },
                                {
                                    "directive": "log_not_found",
                                    "args": ["off"]
                                }
                            ]
                        }
                    ]
                }

        return None
