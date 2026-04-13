from typing import Dict, List, Any, Optional
from core.scannerEng.base_recom import BaseRecom

class Detector241(BaseRecom):
    def __init__(self):
        super().__init__()
        self.id = "2.4.1"
        self.title = "Ensure NGINX only listens for network connections on authorized ports"
        self.description = "NGINX should be configured to listen only on authorized ports and protocols. While traditional HTTP/1.1 and HTTP/2 use TCP ports 80 and 443, modern HTTP/3 (QUIC) utilizes UDP port 443. Ensuring that NGINX binds only to approved interfaces and ports minimizes the attack surface."
        self.audit_procedure = "Run the command `nginx -T 2>/dev/null | grep -r \"listen\"` to inspect all listen directives in the loaded configuration. Review the output for unauthorized ports, ensuring no other ports (e.g., 8080, 8443) are open unless explicitly authorized."
        self.impact = "Disabling unused ports reduces the risk of unauthorized access. However, administrators must be aware that disabling UDP port 443 will break HTTP/3 connectivity, forcing clients to fall back to slower TCP-based HTTP/2 or HTTP/1.1."
        self.remediation = "Remove or comment out any listen directives that bind to unauthorized ports. For HTTP/3 (QUIC) support, ensure that you explicitly authorize and configure UDP port 443 in addition to TCP port 443."
        self.profile = "Level 1 - Webserver, Level 1 - Proxy, Level 1 - Loadbalancer."

        # Danh sách các cổng được phép mở (Authorized ports) theo yêu cầu của hệ thống
        self.authorized_ports = ["80", "443", "8080", "3000"]

    def _extract_port(self, listen_arg: str) -> Optional[str]:
        """
        Hàm helper để trích xuất số port từ tham số của chỉ thị `listen`.
        Xử lý các định dạng phức tạp của NGINX:
        - unix:/var/run/nginx.sock -> bỏ qua (trả về None)
        - [::]:80 hoặc [fe80::1]:443 (IPv6) -> lấy 80 hoặc 443
        - 127.0.0.1:8080 (IPv4) -> lấy 8080
        - 80 -> lấy 80
        - localhost -> bỏ qua (trả về None)
        """
        # Bỏ qua các socket unix hoặc tham số rỗng
        if not listen_arg or listen_arg.startswith("unix:"):
            return None
            
        # Xử lý định dạng IPv6 có chứa port, ví dụ: [::]:80
        if "]:" in listen_arg:
            port_str = listen_arg.split("]:")[-1]
            if port_str.isdigit():
                return port_str
                
        # Xử lý định dạng IPv4 có chứa port, ví dụ: 127.0.0.1:8080
        elif ":" in listen_arg:
            port_str = listen_arg.split(":")[-1]
            if port_str.isdigit():
                return port_str
                
        # Xử lý định dạng chỉ chứa số port, ví dụ: 80 hoặc 443
        elif listen_arg.isdigit():
            return listen_arg
            
        # Trả về None cho các trường hợp không parse được thành số (ví dụ: localhost)
        return None

    def evaluate(self, directive: Dict, filepath: str, logical_context: List[str], exact_path: List[Any]) -> Optional[Dict]:
        """
        Hàm đánh giá AST directive xem có vi phạm cấu hình mở port không được phép hay không.
        Sẽ trả về JSON Contract nếu phát hiện vi phạm để Thành viên 2 làm tính năng Auto-Remediation an toàn.
        """
        remediations = []
        
        # Hàm nội bộ để kiểm tra từng chỉ thị listen cụ thể
        def check_listen(d: Dict, path: List[Any], ctx: List[str]):
            args = d.get("args", [])
            if not args:
                return
                
            # Lấy số port từ tham số đầu tiên của chỉ thị listen
            port = self._extract_port(args[0])
            
            # Nếu parse được port và port này KHÔNG nằm trong danh sách được phép
            if port is not None and str(port) not in self.authorized_ports:
                # Ghi nhận vi phạm để Thành viên 2 có thể thực hiện Dry-Run và xóa/comment-out an toàn
                remediations.append({
                    "action": "delete", # Đề xuất hành động xóa (hoặc comment) dòng vi phạm
                    "directive": "listen",
                    "context": {
                        "exact_path": path, # Đường dẫn AST chính xác giúp difflib định vị dòng code
                        "logical_context": ctx # Ngữ cảnh logic (ví dụ: nằm trong block 'server')
                    }
                })

        # Trường hợp 1: Directive hiện tại chính là 'listen' (thường gặp khi file được include)
        if directive.get("directive") == "listen":
            check_listen(directive, exact_path, logical_context)
            
        # Trường hợp 2: Directive hiện tại là block 'server', ta cần duyệt qua các con của nó
        elif directive.get("directive") == "server":
            for i, child in enumerate(directive.get("block", [])):
                if child.get("directive") == "listen":
                    # Tính toán lại exact_path cho thẻ con để difflib không bị lệch dòng
                    child_path = exact_path + ["block", i]
                    # Cập nhật logical_context báo rằng nó nằm trong 'server'
                    child_ctx = logical_context + ["server"]
                    check_listen(child, child_path, child_ctx)

        # Nếu có bất kỳ vi phạm nào được tìm thấy, trả về cấu trúc JSON Contract
        if remediations:
            return {
                "file": filepath,
                "remediations": remediations
            }
            
        # Không có vi phạm (Compliant)
        return None
