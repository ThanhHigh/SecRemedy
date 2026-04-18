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

    def scan(self, parser_output: Dict[str, Any]) -> List[Dict[str, Any]]:
        uncompliances = []
        # TODO: Implement your logic here
        return self._group_by_file(uncompliances)
