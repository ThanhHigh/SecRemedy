import re
from typing import Dict, List, Any, Optional
from core.scannerEng.base_recom import BaseRecom
from core.recom_registry import RecomID


class Detector241(BaseRecom):
    def __init__(self):
        super().__init__(RecomID.CIS_2_4_1)

        # Danh sách các cổng được phép mở (Authorized ports) theo yêu cầu của hệ thống
        self.authorized_ports = ["80", "443", "8080", "8443", "9000"]

    def _extract_port(self, arg: str) -> Optional[str]:
        # Bỏ qua chỉ thị rỗng hoặc socket unix
        if not arg or arg.startswith("unix:"):
            return None
        
        # Bỏ qua nếu port là biến (ví dụ: $port) vì không thể kiểm tra tĩnh
        if "$" in arg:
            return arg

        # Tìm chuỗi số theo sau dấu hai chấm ở cuối cấu hình (vd: 127.0.0.1:80)
        match = re.search(r":(\d+)$", arg)
        if match:
            # IPv6 hoặc IPv4 có ghi rõ port
            if "]" in arg or arg.count(":") == 1:
                return match.group(1)
            # Trường hợp có nhiều dấu ":" nhưng không có ngoặc vuông (IPv6 hỏng hoặc dị dạng) thì mặc định port 80
            elif arg.count(":") > 1 and "[" not in arg:
                return "80"

        # Nếu chỉ có port (vd: "80")
        if arg.isdigit():
            return arg

        # Trường hợp chỉ là IP hoặc domain không có port (vd: "127.0.0.1") thì NGINX tự hiểu là 80
        return "80"

    def scan(self, parser_output: Dict[str, Any]) -> List[Dict[str, Any]]:
        uncompliances = []

        # Lặp qua từng file cấu hình do parser trả về
        for config_idx, config_file in enumerate(parser_output.get("config", [])):
            filepath = config_file.get("file", "")

            # Chỉ xử lý các file có đuôi .conf
            if not filepath.endswith(".conf"):
                continue

            parsed_ast = config_file.get("parsed", [])
            base_exact_path = ["config", config_idx, "parsed"]

            # Tìm tất cả server blocks
            server_blocks = self.traverse_directive(
                target_directive="server",
                directives=parsed_ast,
                filepath=filepath,
                logical_context=[],
                exact_path=base_exact_path
            )
            
            for s_block in server_blocks:
                s_dir = s_block["directive"]
                s_path = s_block["exact_path"]
                
                # Tìm tất cả listen directives trong server block này
                listen_dirs = self.traverse_directive(
                    target_directive="listen",
                    directives=s_dir.get("block", []),
                    filepath=filepath,
                    logical_context=s_block["logical_context"] + ["server"],
                    exact_path=s_path + ["block"]
                )
                
                for l_match in listen_dirs:
                    l_dir = l_match["directive"]
                    args = l_dir.get("args", [])
                    line = l_dir.get("line", 1)
                    
                    # Bắt lỗi listen không có đối số
                    if not args:
                        uncompliances.append({
                            "file": filepath,
                            "remediations": [{
                                "line": line,
                                "details": "Empty args for listen",
                                "exact_path": l_match["exact_path"]
                            }]
                        })
                        continue

                    # Trích xuất port từ đối số đầu tiên
                    port = self._extract_port(args[0])
                    
                    if port is None:
                        continue

                    is_valid = True
                    
                    # Kiểm tra dải cổng hợp lệ
                    if port.isdigit():
                        port_num = int(port)
                        if port_num == 0 or port_num > 65535:
                            is_valid = False
                    
                    # Kiểm tra xem port có nằm trong danh sách được phép không
                    if is_valid and port not in self.authorized_ports:
                        is_valid = False
                        
                    # Không cho phép dùng biến định cấu hình cổng vì rủi ro thay đổi run-time
                    if "$" in port:
                        is_valid = False

                    # Ghi nhận lỗi nếu có vi phạm
                    if not is_valid:
                        uncompliances.append({
                            "file": filepath,
                            "remediations": [{
                                "line": line,
                                "details": f"Unauthorized port found: {port}",
                                "exact_path": l_match["exact_path"]
                            }]
                        })

        # Gộp các lỗi theo từng file trước khi trả kết quả
        return self._group_by_file(uncompliances)
