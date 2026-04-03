from typing import Dict, List, Any, Optional
from core.scannerEng.base_recom import BaseRecom


class Detector411(BaseRecom):
    def __init__(self):
        super().__init__()
        self.id = "4.1.1"
        self.title = "Ensure HTTP is redirected to HTTPS (Manual)"
        self.description = "Browsers and clients establish encrypted connections with servers by leveraging HTTPS. Unencrypted requests should be redirected so they are encrypted, meaning any listening HTTP port on your web server should redirect to a server profile that uses encryption."
        self.audit_procedure = "To verify your server listening configuration, check your web server or proxy configuration file. The configuration file should return a statement redirecting to HTTPS."
        self.impact = "Use of HTTPS does result in a performance reduction in traffic to your website, however, many businesses consider this to be a cost of doing business."
        self.remediation = "Edit your web server or proxy configuration file to redirect all unencrypted listening ports using a redirection through the return directive."

    def evaluate(self, directive: Dict, filepath: str, logical_context: List[str], exact_path: List[Any]) -> Optional[Dict]:
        """
        Evaluate recommendation 4.1.1.
        Checks if 'server' blocks listening on unencrypted ports (like 80)
        have a 'return' directive redirecting to HTTPS.
        """
        if directive.get("directive") == "server":
            block = directive.get("block", [])
            listens = [d for d in block if d.get("directive") == "listen"]
            is_http_server = False

            # Determine if this server block listens on an HTTP port
            if not listens:
                is_http_server = True  # Default NGINX listen port is 80 (HTTP)
            else:
                for l in listens:
                    args_str = " ".join(l.get("args", []))
                    # If listening on port other than 443 and without ssl parameter
                    if "ssl" not in args_str and "443" not in args_str:
                        is_http_server = True
                        break

            if is_http_server:
                # Check for return directive with https redirect
                returns = [d for d in block if d.get("directive") == "return"]
                has_https_redirect = False
                for r in returns:
                    args = r.get("args", [])
                    for arg in args:
                        if arg.startswith("https://"):
                            has_https_redirect = True
                            break

                if not has_https_redirect:
                    return {
                        "file": filepath,
                        "remediations": [
                            {
                                "action": "add",
                                "context": exact_path + ["block"],
                                "directive": "return",
                                "args": ["301", "https://$host$request_uri"]
                            }
                        ]
                    }

        return None
