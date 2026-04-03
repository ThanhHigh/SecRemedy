from typing import Dict, List, Any, Optional
from core.scannerEng.base_recom import BaseRecom


class Detector32(BaseRecom):
    def __init__(self):
        super().__init__()
        self.id = "3.2"
        self.title = "Ensure access logging is enabled (Manual)"
        self.description = "The access_log directive enables the logging of client requests. While enabled by default, NGINX allows granular control per server or location context."
        self.audit_procedure = "Inspect the fully loaded configuration for log settings and verify that access_log directives point to a valid local file path. Identify any instances of `access_log off;` and ensure it is not applied globally."
        self.impact = "Enabling detailed access logging increases disk space usage significantly. Without proper log rotation and monitoring, log files can rapidly consume available disk space, potentially causing the server to crash."
        self.remediation = "Enable access logging in the http block to set a secure global default, or configure it explicitly within specific server blocks."

    def evaluate(self, directive: Dict, filepath: str, logical_context: List[str], exact_path: List[Any]) -> Optional[Dict]:
        """
        Evaluate recommendation 3.2.
        Checks if 'access_log' has 'off' as argument.
        If so, suggests replacing it with a valid log path.
        """
        if directive.get("directive") == "access_log":
            args = directive.get("args", [])
            # NGINX allows 'access_log off;' to disable access logging
            if "off" in args:
                return {
                    "file": filepath,
                    "remediations": [
                        {
                            "action": "modify_directive",
                            "context": exact_path,
                            "directive": "access_log",
                            "args": ["/var/log/nginx/access.log", "combined"]
                        }
                    ]
                }

        return None
