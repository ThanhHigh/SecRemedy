from typing import Dict, List, Any, Optional
from core.scannerEng.base_recom import BaseRecom


class Detector31(BaseRecom):
    def __init__(self):
        super().__init__()
        self.id = "3.1"
        self.title = "Ensure detailed logging is enabled (Manual)"
        self.description = "System logging must be configured to meet organizational security and privacy policies. Detailed logs provide the necessary context for incident response and forensic analysis, with modern strategies favoring structured formats (JSON)."
        self.audit_procedure = "Inspect the log_format directives to confirm a detailed format is defined and includes critical fields. Check that the defined format is actually used by the access_log directive."
        self.impact = "Enabling detailed JSON logging increases the volume of log data. Ensure that log rotation policies and disk space monitoring are adjusted to handle the increased storage requirements."
        self.remediation = "Define a detailed log format in the http block of /etc/nginx/nginx.conf, preferably using JSON format for compatibility with modern SIEM tools, and apply it globally or per server."

    def evaluate(self, directive: Dict, filepath: str, logical_context: List[str], exact_path: List[Any]) -> Optional[Dict]:
        """
        Evaluate recommendation 3.1.
        Checks if the 'http' block has a 'log_format' directive defined.
        If missing, suggests adding a JSON log_format and an access_log directive using it.
        """
        if directive.get("directive") == "http":
            http_block = directive.get("block", [])
            has_log_format = False

            for d in http_block:
                if d.get("directive") == "log_format":
                    has_log_format = True
                    break

            if not has_log_format:
                return {
                    "file": filepath,
                    "remediations": [
                        {
                            "action": "add_directive",
                            "context": exact_path + ["block"],
                            "directive": "log_format",
                            "args": [
                                "main_json",
                                "escape=json",
                                "'{\"timestamp\":\"$time_iso8601\", "
                                "\"client_ip\":\"$remote_addr\", "
                                "\"status\":\"$status\", "
                                "\"request\":\"$request\", "
                                "\"bytes_sent\":\"$body_bytes_sent\", "
                                "\"user_agent\":\"$http_user_agent\"}'"
                            ]
                        },
                        {
                            "action": "add_directive",
                            "context": exact_path + ["block"],
                            "directive": "access_log",
                            "args": [
                                "/var/log/nginx/access.log",
                                "main_json"
                            ]
                        }
                    ]
                }

        return None
