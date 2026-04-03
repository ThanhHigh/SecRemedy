from typing import Dict, List, Any, Optional
from core.scannerEng.base_recom import BaseRecom


class Detector34(BaseRecom):
    def __init__(self):
        super().__init__()
        self.id = "3.4"
        self.title = "Ensure proxies pass source IP information (Manual)"
        self.description = "When NGINX acts as a reverse proxy or load balancer, it terminates the client connection and opens a new connection to the upstream application server. Standard HTTP headers like X-Forwarded-For and X-Real-IP must be explicitly configured to pass the original client's IP address."
        self.audit_procedure = "Check the active configuration for proxy header directives in proxied locations and verify that proxy_set_header X-Forwarded-For and proxy_set_header X-Real-IP are present."
        self.impact = "Enabling these headers allows the backend application to see the original client IP. However, if NGINX simply appends to an existing X-Forwarded-For header sent by a malicious client, the backend might be tricked into trusting a spoofed IP."
        self.remediation = "Configure NGINX to forward client IP information in your server or location blocks where proxy_pass is used."

    def evaluate(self, directive: Dict, filepath: str, logical_context: List[str], exact_path: List[Any]) -> Optional[Dict]:
        """
        Evaluate recommendation 3.4.
        Checks if a block containing 'proxy_pass' also contains 'proxy_set_header X-Forwarded-For' and 'proxy_set_header X-Real-IP'.
        If either is missing, suggests adding them.
        """
        # We only care about directives that have a block (e.g., location, server)
        if "block" in directive:
            block = directive.get("block", [])
            has_proxy_pass = False
            has_x_forwarded_for = False
            has_x_real_ip = False

            for d in block:
                # Check for proxy_pass
                if d.get("directive") == "proxy_pass":
                    has_proxy_pass = True

                # Check for proxy_set_header
                if d.get("directive") == "proxy_set_header":
                    args = d.get("args", [])
                    if len(args) >= 1:
                        header_name = args[0].lower()
                        if header_name == "x-forwarded-for":
                            has_x_forwarded_for = True
                        elif header_name == "x-real-ip":
                            has_x_real_ip = True

            # If proxy_pass is used but any of the mandatory headers are missing
            if has_proxy_pass and (not has_x_forwarded_for or not has_x_real_ip):
                remediations = []

                if not has_x_forwarded_for:
                    remediations.append({
                        "action": "add_directive",
                        "context": exact_path + ["block"],
                        "directive": "proxy_set_header",
                        "args": ["X-Forwarded-For", "$proxy_add_x_forwarded_for"]
                    })

                if not has_x_real_ip:
                    remediations.append({
                        "action": "add_directive",
                        "context": exact_path + ["block"],
                        "directive": "proxy_set_header",
                        "args": ["X-Real-IP", "$remote_addr"]
                    })

                return {
                    "file": filepath,
                    "remediations": remediations
                }

        return None
