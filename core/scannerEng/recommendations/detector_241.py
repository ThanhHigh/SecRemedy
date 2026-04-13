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

        # Danh sách các cổng được ủy quyền (Authorized ports)
        self.authorized_ports = ["80", "443", "8080", "3000"]

    def evaluate(self, directive: Dict, filepath: str, logical_context: List[str], exact_path: List[Any]) -> Optional[Dict]:
        
        # Hàm helper nội bộ: Kiểm tra xem một chỉ thị `listen` có vi phạm hay không
        def check_listen(listen_dir: Dict, path: List[Any]) -> Optional[Dict]:
            args = listen_dir.get("args", [])
            if not args:
                return None
            addr = args[0]
            port_str = None
            
            # Phân tách để lấy ra chuỗi cổng (port)
            # Hỗ trợ định dạng IPv6 (VD: [::]:80)
            if "]:" in addr:
                port_str = addr.split("]:")[-1]
            # Hỗ trợ định dạng IPv4 kèm IP (VD: 127.0.0.1:8080)
            elif ":" in addr and not addr.startswith("["):
                port_str = addr.split(":")[-1]
            # Trường hợp chỉ khai báo cổng (VD: 80, 443)
            else:
                port_str = addr

            # Nếu cổng đang sử dụng không nằm trong danh sách được phép
            if port_str not in self.authorized_ports:
                # Trả về đối tượng remediation (hành động khắc phục) là xóa dòng (delete)
                return {
                    "action": "delete",
                    "directive": "listen",
                    "context": path
                }
            return None

        # --- Xử lý tương thích cho Unit Test ---
        # Trong các bài test Compliant/NonCompliant, nguyên khối `http` được truyền vào
        if directive.get("directive") == "http" and logical_context == ["http"]:
            remediations = []

            # Hàm đệ quy duyệt qua các khối con (VD: server, location) để tìm chỉ thị `listen`
            def recurse(d, path):
                if d.get("directive") == "listen":
                    rem = check_listen(d, path)
                    if rem:
                        remediations.append(rem)
                elif "block" in d:
                    for i, child in enumerate(d["block"]):
                        recurse(child, path + ["block", i])

            recurse(directive, exact_path)

            # Nếu tìm thấy lỗi trong các khối con, trả về danh sách cách khắc phục gộp chung cho file
            if remediations:
                return {"file": filepath, "remediations": remediations}
            return None

        # --- Luồng quét bình thường (Normal scan flow) ---
        # Khi Scanner Engine duyệt cây AST và gọi hàm này trên từng node độc lập
        if directive.get("directive") == "listen":
            rem = check_listen(directive, exact_path)
            if rem:
                return {"file": filepath, "remediations": [rem]}

        return None

