from typing import Dict, List, Any, Optional
from core.scannerEng.base_recom import BaseRecom


class Detector242(BaseRecom):
    def __init__(self):
        super().__init__()
        self.id = "2.4.2"
        self.title = "Ensure requests for unknown host names are rejected"
        self.description = "NGINX should have a catch-all default server block that rejects requests for unknown hostnames, preventing Host Header attacks and unintended application exposure."
        self.audit_procedure = "Check for a default server block using `nginx -T 2>/dev/null | grep -Ei \"listen.*default_server|ssl_reject_handshake\"`. Verify it contains `return 444;` or a 4xx error code. For HTTPS/TLS, verify `ssl_reject_handshake on;` is used."
        self.impact = "Clients accessing the server directly via IP address or an unconfigured CNAME will be rejected. All valid domains must be explicitly defined in their own server blocks."
        self.remediation = "Configure a 'Catch-All' default server block as the first block in your configuration (or explicitly marked with default_server). After adding this block, ensure all your valid applications have their own server blocks with explicit server_name directives."

    def scan(self, parser_output: Dict[str, Any]) -> List[Dict[str, Any]]:
        uncompliances = []
        # TODO: Implement your logic here
        return self._group_by_file(uncompliances)
