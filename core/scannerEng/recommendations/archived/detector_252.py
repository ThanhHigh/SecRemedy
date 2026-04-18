from typing import Dict, List, Any, Optional
from core.scannerEng.base_recom import BaseRecom


class Detector252(BaseRecom):
    def __init__(self):
        super().__init__()
        # Thông tin metadata theo chuẩn CIS Benchmark 2.5.2
        self.id = "2.5.2"
        self.title = "Ensure default error and index.html pages do not reference NGINX (Manual)"
        self.description = "Default error pages (e.g., 404, 500) and the default welcome page often contain NGINX branding or signatures. These pages should be removed or replaced with generic or custom-branded pages that do not disclose the underlying server technology."
        self.audit_procedure = "Check if error_page directives are active by running `nginx -T 2>/dev/null | grep -i \"error_page\"`. Trigger an error (e.g., request a non-existent page) and inspect the body to verify the output does not contain \"nginx\"."
        self.impact = "Creating and maintaining custom error pages requires additional administrative effort. Ensure that custom error pages are simple and do not themselves introduce vulnerabilities."
        self.remediation = "Instead of editing the default files, configure NGINX to use custom error pages. Create a directory and place generic HTML files there without NGINX branding, and add the error_page directive to your http or server blocks."
        self.level = "Level 1 - Webserver, Proxy, Loadbalancer"
        self.profile = "Level 1"

    def evaluate(self, directive: Dict, filepath: str, logical_context: List[str], exact_path: List[Any]) -> Optional[Dict]:
        """
        Kiểm tra trực tiếp một khối (http, server, location) để xem nó có trực tiếp định nghĩa
        các chỉ thị `error_page` an toàn cho các mã lỗi quan trọng (404, 500, 502, 503, 504) hay không.
        Hàm này trả về lỗi nếu khối đó không có error_page hoặc có error_page nhưng bị thiếu mã lỗi / trỏ sai địa chỉ chứa 'nginx'.
        """
        d_name = directive.get("directive")
        # Chỉ đánh giá trên các khối có khả năng chứa error_page
        if d_name not in ["http", "server", "location"]:
            return None

        # Thu thập thông tin từ tất cả các chỉ thị error_page nằm trực tiếp bên trong khối này
        block = directive.get("block", [])
        codes_covered = set()
        is_valid = True
        
        for d in block:
            if d.get("directive") == "error_page":
                args = d.get("args", [])
                # error_page cần ít nhất 1 mã lỗi và 1 URI (ví dụ: error_page 404 /404.html)
                if len(args) < 2:
                    is_valid = False
                    continue
                uri = args[-1]
                
                # Cảnh báo rò rỉ: nếu URI trỏ về trang có chứa chữ "nginx" (ví dụ trang mặc định của CentOS/Debian)
                if "nginx" in uri.lower():
                    is_valid = False
                    
                # Thu thập các mã lỗi (status codes) mà khai báo này đang xử lý
                for arg in args[:-1]:
                    if arg.isdigit():
                        codes_covered.add(int(arg))

        # Yêu cầu bắt buộc phải xử lý tất cả các mã lỗi này để ngăn rò rỉ NGINX version
        required_codes = {404, 500, 502, 503, 504}
        
        # Nếu block có khai báo hợp lệ và phủ đầy đủ các mã lỗi yêu cầu
        if is_valid and required_codes.issubset(codes_covered):
            return None

        # Trả về đối tượng JSON Contract mô tả cách Remediation (chèn/sửa)
        return {
            "file": filepath,
            "remediations": [{
                "action": "add", # Remediation: Bổ sung chỉ thị error_page an toàn
                "directive": "error_page",
                "value": "404 500 502 503 504 /custom_50x.html",
                "context": d_name
            }]
        }

    def scan(self, parser_output: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Hàm quét toàn cục trên cây AST.
        Xử lý tính kế thừa: nếu http đã có error_page an toàn, thì server con không cần định nghĩa lại
        trừ phi nó ghi đè một error_page không an toàn.
        """
        uncompliances = []
        http_exists = False
        
        # Bước 1: Kiểm tra xem cấu hình có khối `http` gốc nào không
        for config_file in parser_output.get("config", []):
            for d in config_file.get("parsed", []):
                if d.get("directive") == "http":
                    http_exists = True
                    break

        def get_explicit_coverage(block_directives):
            """Hàm helper: Trích xuất các mã lỗi đã được xử lý bằng error_page trực tiếp trong khối này"""
            codes = set()
            valid = True
            has_explicit = False
            for child in block_directives:
                if child.get("directive") == "error_page":
                    has_explicit = True
                    args = child.get("args", [])
                    if len(args) < 2:
                        valid = False
                        continue
                    uri = args[-1]
                    if "nginx" in uri.lower():
                        valid = False
                    for arg in args[:-1]:
                        if arg.isdigit():
                            codes.add(int(arg))
            return has_explicit, codes, valid

        def is_coverage_full(codes, valid):
            """Hàm helper: Đánh giá xem tập hợp các mã lỗi đã đủ các mã nguy hiểm tiềm tàng chưa"""
            return valid and {404, 500, 502, 503, 504}.issubset(codes)

        def traverse(directives, filepath, exact_path):
            """Duyệt đệ quy cây AST để kiểm tra tính kế thừa và ghi đè của error_page"""
            for idx, d in enumerate(directives):
                d_name = d.get("directive")
                ep = exact_path + [idx]
                
                # Bỏ qua các khối chuyên sâu về kết nối mạng/luồng, không liên quan đến cấu hình HTTP
                if d_name in ["stream", "events"]:
                    continue
                
                # Xử lý các khối chịu trách nhiệm phục vụ web
                if d_name in ["http", "server", "location"]:
                    block = d.get("block", [])
                    has_explicit, codes, valid = get_explicit_coverage(block)
                    
                    if has_explicit:
                        # TH1: Khối này CÓ định nghĩa error_page nhưng định nghĩa thiếu sót (ghi đè nguy hiểm)
                        if not is_coverage_full(codes, valid):
                            uncompliances.append({
                                "file": filepath,
                                "remediations": [{
                                    "action": "modify", # Bắt buộc sửa đổi trực tiếp vào dòng ghi đè bị sai
                                    "directive": "error_page",
                                    "value": "404 500 502 503 504 /custom_50x.html",
                                    "context": d_name
                                }]
                            })
                    else:
                        # TH2: Khối này KHÔNG định nghĩa error_page
                        # Đối với khối http (gốc), luôn báo lỗi nếu thiếu
                        if d_name == "http":
                            uncompliances.append({
                                "file": filepath,
                                "remediations": [{
                                    "action": "add",
                                    "directive": "error_page",
                                    "value": "404 500 502 503 504 /custom_50x.html",
                                    "context": d_name
                                }]
                            })
                        # Đối với khối server, nếu không có khối http nào trên toàn hệ thống để kế thừa, thì bản thân server phải gánh trách nhiệm
                        elif d_name == "server" and not http_exists:
                            uncompliances.append({
                                "file": filepath,
                                "remediations": [{
                                    "action": "add",
                                    "directive": "error_page",
                                    "value": "404 500 502 503 504 /custom_50x.html",
                                    "context": d_name
                                }]
                            })
                            
                    # Tiếp tục duyệt sâu vào các khối con (ví dụ từ http -> server, hoặc server -> location)
                    traverse(block, filepath, ep + ["block"])
                else:
                    # Nếu là các khối khác (ví dụ: if, limit_except), vẫn cần duyệt xuống nếu nó có chứa khối con
                    if "block" in d:
                        traverse(d.get("block", []), filepath, ep + ["block"])

        # Bắt đầu duyệt quét từ mức ngoài cùng của từng file cấu hình
        for config_idx, config_file in enumerate(parser_output.get("config", [])):
            filepath = config_file.get("file", "")
            traverse(config_file.get("parsed", []), filepath, ["config", config_idx, "parsed"])
            
        # Nén/nhóm các lỗi liên quan trên cùng 1 file thành 1 mảng JSON gọn gàng gửi cho bước Remediation
        return self._group_by_file(uncompliances)
