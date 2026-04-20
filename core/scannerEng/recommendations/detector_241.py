from typing import Dict, List, Any, Optional
from core.scannerEng.base_recom import BaseRecom


class Detector241(BaseRecom):
    def __init__(self):
        super().__init__()
        self.id = "2.4.1"
        self.title = ""
        self.description = ""
        self.audit_procedure = ""
        self.impact = ""
        self.remediation = ""

        # Danh sách các cổng được phép mở (Authorized ports) theo yêu cầu của hệ thống
        self.authorized_ports = ["80", "443", "8080", "3000"]

    def scan(self, parser_output: Dict[str, Any]) -> List[Dict[str, Any]]:
        uncompliances = []
        # TODO: Implement your logic here
        return self._group_by_file(uncompliances)
