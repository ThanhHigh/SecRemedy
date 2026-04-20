from typing import Dict, List, Any, Optional
from core.scannerEng.base_recom import BaseRecom


class Detector241(BaseRecom):
    def __init__(self):
        super().__init__()
        self.id = "2.4.1"
        self.title = "Đảm bảo NGINX chỉ lắng nghe các kết nối mạng trên các cổng được ủy quyền"
        self.description = "NGINX chỉ nên được cấu hình để lắng nghe trên các cổng và giao thức được phép. Việc giới hạn các cổng lắng nghe giúp giảm bề mặt tấn công."
        self.audit_procedure = "Kiểm tra tất cả các chỉ thị listen trong cấu hình. Đảm bảo không có cổng trái phép (ví dụ 8080, 8443) được mở nếu không có sự cho phép."
        self.impact = "Vô hiệu hóa các cổng không sử dụng giúp giảm rủi ro truy cập trái phép. Cần cẩn trọng khi vô hiệu hóa cổng UDP 443 vì sẽ làm hỏng kết nối HTTP/3 (QUIC)."
        self.remediation = "Xóa hoặc comment các chỉ thị listen gắn với cổng trái phép. Đảm bảo chỉ mở cổng TCP 80, TCP 443 và UDP 443 (nếu dùng HTTP/3)."

        # Danh sách các cổng được phép mở (Authorized ports) theo yêu cầu của hệ thống
        self.authorized_ports = ["80", "443", "8080", "8443", "9000"]

    def _extract_port(self, listen_arg: str) -> str:
        if "]" in listen_arg and ":" in listen_arg.split("]")[-1]:
            return listen_arg.split(":")[-1]
        elif "]" in listen_arg:
            return "80"
        elif ":" in listen_arg:
            return listen_arg.split(":")[-1]
        elif listen_arg.isdigit():
            return listen_arg
        return "80"

    def scan(self, parser_output: Dict[str, Any]) -> List[Dict[str, Any]]:
        uncompliances = []
        for file_info in parser_output.get("config", []):
            filepath = file_info.get("file", "")
            parsed = file_info.get("parsed", [])

            def traverse(directives, path):
                for i, d in enumerate(directives):
                    if d.get("directive") == "listen":
                        args = d.get("args", [])
                        if args:
                            port = self._extract_port(args[0])
                            if port not in self.authorized_ports:
                                uncompliances.append({
                                    "file": filepath,
                                    "remediations": [{
                                        "action": "delete",
                                        "exact_path": path + [i],
                                        "directive": d
                                    }]
                                })
                    if "block" in d:
                        traverse(d["block"], path + [i, "block"])

            traverse(parsed, [])

        return self._group_by_file(uncompliances)
