from typing import Dict, List, Any, Optional
from core.scannerEng.base_recom import BaseRecom


class Detector251(BaseRecom):
    def __init__(self):
        super().__init__()
        self.id = "2.5.1"
        self.title = "Ensure server_tokens directive is set to `off`"
        self.description = "The server_tokens directive is responsible for displaying the NGINX version number and operating system version on error pages and in the Server HTTP response header field. This information should not be displayed."
        self.audit_procedure = "In the NGINX configuration file `nginx.conf`, verify the server_tokens directive is set to off. Check the response headers with `curl -I 127.0.0.1 | grep -i server`."
        self.impact = "None. Disabling server tokens does not affect functionality, as it merely removes the version string from error pages and headers."
        self.remediation = "Disable version disclosure globally by adding the directive `server_tokens off;` to the http block in `/etc/nginx/nginx.conf`."

    def evaluate(self, directive: Dict, filepath: str, logical_context: List[str], exact_path: List[Any]) -> Optional[Dict]:
        """
        Evaluate recommendation 2.5.1.
        Checks if 'server_tokens' restrictively disabled explicitly, or adds it to 'http' block if missing.
        """
        # 1. Inspect explicit server_tokens configuration
        if directive.get("directive") == "server_tokens":
            args = directive.get("args", [])
            if args and args[0] != "off":
                return {
                    "file": filepath,
                    "remediations": [
                        {
                            "action": "replace",
                            "context": exact_path,
                            "directive": "server_tokens",
                            "args": ["off"]
                        }
                    ]
                }

        # 2. Check if server_tokens is missing globally within the HTTP block
        # (Default is 'on', which violates the recommendation)
        if directive.get("directive") == "http":
            block = directive.get("block", [])
            has_server_tokens = any(
                d.get("directive") == "server_tokens" for d in block)

            if not has_server_tokens:
                return {
                    "file": filepath,
                    "remediations": [
                        {
                            "action": "add",
                            "context": exact_path + ["block"],
                            "directive": "server_tokens",
                            "args": ["off"]
                        }
                    ]
                }

        return None
