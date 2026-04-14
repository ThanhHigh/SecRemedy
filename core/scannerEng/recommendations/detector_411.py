from typing import Dict, List, Any, Optional
from core.scannerEng.base_recom import BaseRecom


class Detector411(BaseRecom):
    def __init__(self):
        super().__init__()
        self.id = "4.1.1"
        self.title = "Ensure HTTP is redirected to HTTPS (Manual)"
        self.description = "Browsers and clients establish encrypted connections with servers by leveraging HTTPS. Unencrypted requests should be redirected so they are encrypted, meaning any listening HTTP port on your web server should redirect to a server profile that uses encryption."
        self.audit_procedure = "To verify your server listening configuration, check your web server or proxy configuration file. The configuration file should return a statement redirecting to HTTPS."
        self.impact = "Use of HTTPS does result in a performance reduction in traffic to your website, however, many businesses consider this to be a cost of doing business."
        self.remediation = "Edit your web server or proxy configuration file to redirect all unencrypted listening ports using a redirection through the return directive."
        self.level = "Level 1"

    def evaluate(self, directive: Dict, filepath: str, logical_context: List[str], exact_path: List[Any]) -> Optional[Dict]:
        # Chỉ kiểm tra trong ngữ cảnh của khối 'server'
        if directive.get("directive") != "server":
            return None
        
        block = directive.get("block", [])
        
        has_http_listen = False
        has_https_listen = False
        has_ssl_on = False
        has_valid_redirect = False
        has_listen = False
        
        # Duyệt qua các chỉ thị con bên trong khối 'server'
        for child in block:
            name = child.get("directive")
            args = child.get("args", [])
            
            if name == "listen":
                has_listen = True
                # Kiểm tra xem cổng đang lắng nghe có phải là HTTPS không
                # HTTPS thường được cấu hình bằng từ khóa 'ssl' hoặc trực tiếp với port '443'
                if "ssl" in args:
                    has_https_listen = True
                elif any("443" in a for a in args):
                    has_https_listen = True
                else:
                    # Nếu không có dấu hiệu của HTTPS, đây là cổng HTTP
                    has_http_listen = True
            
            elif name == "ssl" and args == ["on"]:
                # Nếu có chỉ thị 'ssl on;', toàn bộ khối server này dùng HTTPS
                has_ssl_on = True
                
            elif name == "return":
                # Kiểm tra chỉ thị return xem có chuyển hướng sang HTTPS hợp lệ không
                # Cú pháp hợp lệ ví dụ: return 301 https://$host$request_uri;
                if len(args) >= 2:
                    status = args[0]
                    url = args[1]
                    if status in ["301", "302", "307", "308"] and url.startswith("https://"):
                        has_valid_redirect = True
            
            elif name == "rewrite":
                # Nginx cũng có thể sử dụng rewrite để chuyển hướng sang HTTPS một cách an toàn
                if len(args) >= 2:
                    url = args[1]
                    if url.startswith("https://"):
                        has_valid_redirect = True

        if not has_listen:
            # Theo mặc định của Nginx, nếu không có chỉ thị 'listen',
            # server sẽ tự động lắng nghe trên cổng 80 (HTTP)
            has_http_listen = True

        if has_ssl_on:
            # Khẳng định lại đây là cấu hình HTTPS nếu tìm thấy 'ssl on;'
            has_https_listen = True
            
        # Nếu khối server lắng nghe trên cổng HTTP nhưng KHÔNG CÓ chỉ thị chuyển hướng hợp lệ (return/rewrite)
        # sang HTTPS, cấu hình này được xem là không tuân thủ (non-compliant) theo CIS Benchmark 4.1.1.
        #
        # Lưu ý: Ngay cả khi khối server cấu hình đồng thời cả HTTP và HTTPS (listen 80; listen 443 ssl;),
        # thì lưu lượng HTTP vẫn sẽ lọt qua và không bị tự động mã hoá, trừ khi có một cấu hình redirect 
        # cụ thể bắt lấy request từ HTTP. Vì thế, yêu cầu bắt buộc là nếu có HTTP thì phải có redirect.
        if has_http_listen and not has_valid_redirect:
            return {
                "file": filepath,
                "remediations": [
                    {
                        "action": "add",
                        "directive": "return",
                        "value": "301 https://$host$request_uri",
                        # Dữ liệu JSON Contract cho Thành viên 2 (Auto-remediation module)
                        # 'exact_path' giúp module remediation biết chính xác nhánh AST để chèn chỉ thị mới.
                        "context": {"exact_path": exact_path}
                    }
                ]
            }

        return None
