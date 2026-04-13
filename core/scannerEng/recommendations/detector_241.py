from typing import Dict, List, Any, Optional
from core.scannerEng.base_recom import BaseRecom


class Detector241(BaseRecom):
    def __init__(self):
        super().__init__()
        self.id = "2.4.1"
        self.title = "Ensure NGINX only listens for network connections on authorized ports"
        self.description = "NGINX should be configured to listen only on authorized ports and protocols. While traditional HTTP/1.1 and HTTP/2 use TCP ports 80 and 443, modern HTTP/3 (QUIC) utilizes UDP port 443. Ensuring that NGINX binds only to approved interfaces and ports minimizes the attack surface."
        self.audit_procedure = "Run the command `nginx -T 2>/dev/null | grep -r \"listen\"` to inspect all listen directives in the loaded configuration. Review the output for unauthorized ports, ensuring no other ports (e.g., 8080, 8443) are open unless explicitly authorized."
        self.impact = "Disabling unused ports reduces the risk of unauthorized access. However, administrators must be aware that disabling UDP port 443 will break HTTP/3 connectivity, forcing clients to fall back to slower TCP-based HTTP/2 or HTTP/1.1."
        self.remediation = "Remove or comment out any listen directives that bind to unauthorized ports. For HTTP/3 (QUIC) support, ensure that you explicitly authorize and configure UDP port 443 in addition to TCP port 443."

        # Authorized ports
        self.authorized_ports = ["80", "443"]

    def evaluate(self, directive: Dict, filepath: str, logical_context: List[str], exact_path: List[Any]) -> Optional[Dict]:
        return None
