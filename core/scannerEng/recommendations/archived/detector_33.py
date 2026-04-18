from typing import Dict, List, Any, Optional
from core.scannerEng.base_recom import BaseRecom


class Detector33(BaseRecom):
    def __init__(self):
        super().__init__()
        self.id = "3.3"
        self.title = "Ensure error logging is enabled and set to the info logging level (Manual)"
        self.description = "The error_log directive configures logging for server errors and operational messages. The log level determines the verbosity of these messages and should be set to capture sufficient detail (typically notice or info)."
        self.audit_procedure = "Check the fully loaded configuration for error log settings and verify that error_log is defined globally in the main context. Confirm it points to a valid local file and the level is set according to internal policy."
        self.impact = "Setting the log level to info can generate a significant volume of log data, increasing disk I/O and storage requirements. Ensure that log rotation is configured and storage usage is monitored."
        self.remediation = "Configure the error_log directive in the main context to capture operational events, setting the specific logging level to align with organizational policy (typically info or notice)."

    def scan(self, parser_output: Dict[str, Any]) -> List[Dict[str, Any]]:
        uncompliances = []
        return self._group_by_file(uncompliances)

    def evaluate(self, directive: Dict, filepath: str, logical_context: List[str], exact_path: List[Any]) -> Optional[Dict]:
        return None
