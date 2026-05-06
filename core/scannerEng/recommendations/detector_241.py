import re
from typing import Dict, List, Any, Optional
from core.scannerEng.base_recom import BaseRecom
from core.recom_registry import RecomID


class Detector241(BaseRecom):
    def __init__(self):
        super().__init__(RecomID.CIS_2_4_1)

    def scan(self, parser_output: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Hàm chính được gọi bởi Scanner Engine.
        Nhận vào toàn bộ AST của các file cấu hình và trả về danh sách các uncompliances.
        Kết quả được gộp theo file (mỗi file 1 entry) để khớp với JSON Contract.
        """
        uncompliances = []
        # Cổng hợp lệ (cho phép)
        authorized_ports = {80, 443, 8080, 8443, 9000}

        # Duyệt từng file AST
        for config_idx, config_file in enumerate(parser_output.get("config", [])):
            filepath = config_file.get("file", "")

            # Bỏ qua file ko phải .conf
            if not filepath.endswith(".conf"):
                continue

            parsed_ast = config_file.get("parsed", [])

            # Ghi nhận đường dẫn JSON exact_path để Auto-Remediation sửa đúng vị trí
            base_exact_path = ["config", config_idx, "parsed"]

            # Tìm kiếm đệ quy directive "listen"
            matches = self.traverse_directive(
                target_directive="listen",
                directives=parsed_ast,
                filepath=filepath,
                logical_context=[],
                exact_path=base_exact_path
            )

            # Xử lý từng directive "listen" tìm được
            for match in matches:
                directive = match["directive"]
                args = directive.get("args", [])
                if not args:
                    continue

                # Trích xuất port từ argument đầu tiên (vd: 80, 0.0.0.0:8080)
                listen_arg = args[0]
                port = self._extract_port(listen_arg)

                # Nếu port tìm được không có trong danh sách cho phép -> lỗi
                if port is not None and port not in authorized_ports:
                    uncompliances.append({
                        "file": filepath,
                        "remediations": [
                            {
                                "action": "delete",
                                "directive": "listen",
                                "logical_context": match["logical_context"],
                                # Bắt buộc có để Remediation biết xóa ở đâu
                                "exact_path": match["exact_path"]
                            }
                        ]
                    })

        # Gộp kết quả theo cấu trúc JSON Contract
        return self._group_by_file(uncompliances)

    def _extract_port(self, listen_arg: str) -> Optional[int]:
        """
        Trích xuất số port từ chuỗi tham số listen.
        """
        # Bỏ qua unix socket vì không dùng TCP port
        if listen_arg.startswith("unix:"):
            return None

        # Xử lý IPv6 (vd: [::]:8080)
        if listen_arg.startswith("["):
            close_idx = listen_arg.find("]")
            if close_idx != -1:
                rest = listen_arg[close_idx+1:]
                if rest.startswith(":"):
                    try:
                        return int(rest[1:])
                    except ValueError:
                        return None
                # Mặc định IPv6 không chỉ định port -> 80
                return 80

        # Xử lý IP:Port IPv4 (vd: 127.0.0.1:8443)
        if ":" in listen_arg:
            port_str = listen_arg.split(":")[-1]
            try:
                return int(port_str)
            except ValueError:
                return None

        # Xử lý chỉ có IP IPv4 (vd: 192.168.1.1) -> port 80
        if "." in listen_arg:
            return 80

        # Trường hợp phổ biến nhất: chỉ có số port (vd: '8080')
        try:
            return int(listen_arg)
        except ValueError:
            return None
