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
        authorized_ports = {80, 443, 8080, 8443, 9000}

        for config_idx, config_file in enumerate(parser_output.get("config", [])):
            filepath = config_file.get("file", "")

            # Chỉ xử lý các file có đuôi .conf
            if not filepath.endswith(".conf"):
                continue

            parsed_ast = config_file.get("parsed", [])

            # Khởi tạo Exact Path gốc cho file này.
            base_exact_path = ["config", config_idx, "parsed"]

            matches = self.traverse_directive(
                target_directive="listen",
                directives=parsed_ast,
                filepath=filepath,
                logical_context=[],
                exact_path=base_exact_path
            )

            for match in matches:
                directive = match["directive"]
                args = directive.get("args", [])
                if not args:
                    continue
                
                listen_arg = args[0]
                port = self._extract_port(listen_arg)
                
                if port is not None and port not in authorized_ports:
                    uncompliances.append({
                        "file": filepath,
                        "remediations": [
                            {
                                "action": "delete",
                                "directive": "listen",
                                "logical_context": match["logical_context"],
                                "exact_path": match["exact_path"]
                            }
                        ]
                    })

        return self._group_by_file(uncompliances)

    def _extract_port(self, listen_arg: str) -> Optional[int]:
        if listen_arg.startswith("unix:"):
            return None

        if listen_arg.startswith("["):
            close_idx = listen_arg.find("]")
            if close_idx != -1:
                rest = listen_arg[close_idx+1:]
                if rest.startswith(":"):
                    try:
                        return int(rest[1:])
                    except ValueError:
                        return None
                return 80

        if ":" in listen_arg:
            port_str = listen_arg.split(":")[-1]
            try:
                return int(port_str)
            except ValueError:
                return None

        if "." in listen_arg:
            return 80

        try:
            return int(listen_arg)
        except ValueError:
            return None
