import fnmatch
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

    def scan(self, parser_output: Dict[str, Any]) -> List[Dict[str, Any]]:
        uncompliances = []
        # TODO: Implement your logic here
        return self._group_by_file(uncompliances)
