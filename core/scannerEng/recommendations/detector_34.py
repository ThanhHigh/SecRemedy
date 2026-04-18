from typing import Dict, List, Any, Optional
import fnmatch
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

    def scan(self, parser_output: Dict[str, Any]) -> List[Dict[str, Any]]:
        uncompliances = []
        # TODO: Implement your logic here
        return self._group_by_file(uncompliances)
