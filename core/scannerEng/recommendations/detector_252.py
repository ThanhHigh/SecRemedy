from typing import Dict, List, Any, Optional
from core.scannerEng.base_recom import BaseRecom


class Detector252(BaseRecom):
    def __init__(self):
        super().__init__()
        self.id = "2.5.2"
        self.title = "Ensure default error and index.html pages do not reference NGINX (Manual)"
        self.description = "Default error pages (e.g., 404, 500) and the default welcome page often contain NGINX branding or signatures. These pages should be removed or replaced with generic or custom-branded pages that do not disclose the underlying server technology."
        self.audit_procedure = "Check if error_page directives are active by running `nginx -T 2>/dev/null | grep -i \"error_page\"`. Trigger an error (e.g., request a non-existent page) and inspect the body to verify the output does not contain \"nginx\"."
        self.impact = "Creating and maintaining custom error pages requires additional administrative effort. Ensure that custom error pages are simple and do not themselves introduce vulnerabilities."
        self.remediation = "Instead of editing the default files, configure NGINX to use custom error pages. Create a directory and place generic HTML files there without NGINX branding, and add the error_page directive to your http or server blocks."

    def evaluate(self, directive: Dict, filepath: str, logical_context: List[str], exact_path: List[Any]) -> Optional[Dict]:
        """
        Evaluate recommendation 2.5.2.
        Checks if 'error_page' directive is present in the 'http' block.
        If missing, it suggests adding custom error_page configurations.
        """
        if directive.get("directive") == "http":
            block = directive.get("block", [])
            has_error_page = any(
                d.get("directive") == "error_page" for d in block)

            if not has_error_page:
                return {
                    "file": filepath,
                    "remediations": [
                        {
                            "action": "add",
                            "context": exact_path + ["block"],
                            "directive": "error_page",
                            "args": ["404", "/custom_404.html"]
                        },
                        {
                            "action": "add",
                            "context": exact_path + ["block"],
                            "directive": "error_page",
                            "args": ["500", "502", "503", "504", "/custom_50x.html"]
                        }
                    ]
                }

        return None
