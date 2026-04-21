from typing import Dict, List, Any, Optional
from core.scannerEng.base_recom import BaseRecom, RecomID


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
        authorized_ports = ["80", "443", "8080", "8443", "9000"]

        for config_idx, config_file in enumerate(parser_output.get("config", [])):
            filepath = config_file.get("file", "")
            parsed_ast = config_file.get("parsed", [])

            # Lấy tất cả directive 'listen' trong file này
            matches = self.traverse_directive(
                target_directive="listen",
                directives=parsed_ast,
                filepath=filepath,
                logical_context=[],
                exact_path=["config", config_idx, "parsed"]
            )

            for match in matches:
                listen_dir = match["directive"]
                args = listen_dir.get("args", [])
                
                port = self._extract_port(args)
                
                # Nếu không tìm thấy port (VD: unix socket) hoặc port nằm trong list cho phép -> Hợp lệ
                if port is None or port in authorized_ports:
                    continue
                
                # Nếu port không được ủy quyền -> Vi phạm
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

    def _extract_port(self, args: List[str]) -> Optional[str]:
        """
        Trích xuất port từ danh sách đối số của chỉ thị 'listen'.
        Ví dụ:
          ['80'] -> '80'
          ['127.0.0.1:8080'] -> '8080'
          ['[::]:443', 'ssl'] -> '443'
          ['unix:/var/run/nginx.sock'] -> None
          ['127.0.0.1'] -> '80' (mặc định)
        """
        if not args:
            return None
        
        first_arg = args[0]
        
        # Bỏ qua unix socket
        if first_arg.startswith("unix:"):
            return None
        
        # Xử lý IPv6: [::]:80 hoặc [::1]
        if "]" in first_arg:
            parts = first_arg.split("]")
            after_bracket = parts[1]
            if after_bracket.startswith(":"):
                return after_bracket[1:]
            return "80" # [::] mặc định port 80
            
        # Xử lý address:port hoặc port
        if ":" in first_arg:
            return first_arg.split(":")[-1]
            
        # Kiểm tra xem có phải là port thuần túy hay không
        if first_arg.isdigit():
            return first_arg
            
        # Nếu là address đơn thuần (không chứa :), Nginx mặc định dùng port 80
        return "80"
