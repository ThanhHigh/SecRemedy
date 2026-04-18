from typing import Dict, List, Any, Optional
from core.scannerEng.base_recom import BaseRecom


class Detector251(BaseRecom):
    def __init__(self):
        super().__init__()
        # Thông tin metadata theo chuẩn CIS Benchmark 2.5.1
        self.id = "2.5.1"
        self.title = "Ensure server_tokens directive is set to `off`"
        self.description = "The server_tokens directive is responsible for displaying the NGINX version number and operating system version on error pages and in the Server HTTP response header field. This information should not be displayed."
        self.audit_procedure = "In the NGINX configuration file `nginx.conf`, verify the server_tokens directive is set to off. Check the response headers with `curl -I 127.0.0.1 | grep -i server`."
        self.impact = "None. Disabling server tokens does not affect functionality, as it merely removes the version string from error pages and headers."
        self.remediation = "Disable version disclosure globally by adding the directive `server_tokens off;` to the http block in `/etc/nginx/nginx.conf`."
        self.level = "Level 1"
        self.profile = "Level 1"

    def evaluate(self, directive: Dict, filepath: str, logical_context: List[str], exact_path: List[Any]) -> Optional[Dict]:
        """
        Hàm kiểm tra từng directive đơn lẻ hoặc một block để tìm kiếm các vi phạm liên quan đến server_tokens.
        Thích hợp cho việc kiểm tra cục bộ theo từng block được truyền vào từ base_recom.
        """
        d_name = directive.get("directive")
        
        # Hàm đệ quy nội bộ để tìm tất cả các chỉ thị 'server_tokens' nằm bên trong một block (ví dụ: http, server)
        def find_server_tokens(blk, path_prefix):
            found = []
            for i, d in enumerate(blk):
                if d.get("directive") == "server_tokens":
                    found.append((d, path_prefix + [i]))
                elif "block" in d:
                    # Nếu gặp block con (vd: location lồng nhau), tiếp tục tìm kiếm đệ quy
                    found.extend(find_server_tokens(d["block"], path_prefix + [i, "block"]))
            return found

        # Nếu đang xét các block http, server, hoặc location
        if d_name in ["http", "server", "location"]:
            # Tìm tất cả khai báo server_tokens bên trong block này
            tokens = find_server_tokens(directive.get("block", []), exact_path + ["block"])
            
            # Nếu không tìm thấy server_tokens nào, mặc định của NGINX là 'on', đây là một vi phạm do "thiếu sót" (missing directive)
            if not tokens:
                return {
                    "file": filepath,
                    "remediations": [{
                        "action": "add", # Cần thêm mới chỉ thị
                        "directive": "server_tokens",
                        "value": "off",
                        "context": directive # Cung cấp AST node hiện tại làm context để module Auto-Remediation biết chèn vào đâu
                    }]
                }
            else:
                # Nếu có tìm thấy, kiểm tra xem có khai báo nào vi phạm (khác 'off') không
                non_compliant = []
                for t, t_path in tokens:
                    args = t.get("args", [])
                    # Loại bỏ dấu nháy đơn/kép nếu có, ví dụ: "off" -> off
                    val = args[0].strip("\"'") if args else ""
                    if val.lower() != "off":
                        non_compliant.append((t, t_path))
                
                # Nếu tất cả các khai báo đều là 'off', thì block này tuân thủ
                if not non_compliant:
                    return None
                
                # Nếu có khai báo vi phạm, lấy khai báo đầu tiên để báo cáo
                t_bad, t_path = non_compliant[0]
                return {
                    "file": filepath,
                    "remediations": [{
                        "action": "modify", # Cần sửa giá trị của chỉ thị đã có
                        "directive": "server_tokens",
                        "value": "off",
                        "context": directive # Vẫn truyền node cha (hoặc node chứa lỗi) để có thể xác định file và vị trí sửa
                    }]
                }

        # Nếu directive hiện tại đang xét chính là 'server_tokens' (khi base_recom truyền thẳng vào)
        elif d_name == "server_tokens":
            args = directive.get("args", [])
            val = args[0].strip("\"'") if args else ""
            if val.lower() != "off":
                # Nếu giá trị không phải là 'off' (ví dụ 'on', 'build', chuỗi bất kỳ), báo lỗi cần 'modify'
                return {
                    "file": filepath,
                    "remediations": [{
                        "action": "modify",
                        "directive": "server_tokens",
                        "value": "off",
                        "context": directive
                    }]
                }
            # Nếu là 'off' thì hợp lệ
            return None
            
        return None

    def scan(self, parser_output: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Hàm kiểm tra tổng thể (Global scan) dựa trên kết quả phân tích AST của toàn bộ các tệp cấu hình NGINX.
        Xử lý trường hợp chỉ thị server_tokens không hề được khai báo ở bất kỳ đâu trong toàn bộ cấu hình,
        hoặc có những khai báo vi phạm ghi đè ở các file cấu hình con (ví dụ: conf.d/*.conf).
        """
        server_tokens_nodes = []
        http_block_info = None

        # Duyệt qua toàn bộ các file cấu hình được phân tích bởi crossplane
        for config_idx, config_file in enumerate(parser_output.get("config", [])):
            filepath = config_file.get("file", "")
            # Chỉ xét các tệp .conf để bỏ qua các file không liên quan (ví dụ: fastcgi_params, mime.types)
            if filepath and not filepath.endswith(".conf"):
                continue

            parsed_ast = config_file.get("parsed", [])
            base_exact_path = ["config", config_idx, "parsed"]

            # Hàm đệ quy duyệt qua AST của một tệp cấu hình
            def traverse(directives, current_exact_path):
                nonlocal http_block_info
                for idx, d in enumerate(directives):
                    ep = current_exact_path + [idx]
                    
                    # Ghi nhận vị trí của khối 'http' đầu tiên (thường nằm ở nginx.conf)
                    # Đây là vị trí lý tưởng nhất để chèn `server_tokens off;` nếu hệ thống hoàn toàn thiếu chỉ thị này
                    if d.get("directive") == "http":
                        if http_block_info is None:
                            http_block_info = (filepath, ep, d)
                    
                    # Thu thập tất cả các khai báo 'server_tokens' ở mọi vị trí trên toàn hệ thống
                    elif d.get("directive") == "server_tokens":
                        server_tokens_nodes.append((filepath, ep, d))
                    
                    # Đi sâu vào trong các khối (ví dụ: http -> server -> location)
                    if "block" in d:
                        traverse(d["block"], ep + ["block"])

            traverse(parsed_ast, base_exact_path)

        uncompliances = []

        # TÌNH HUỐNG 1: Không có bất kỳ khai báo 'server_tokens' nào trên toàn hệ thống (Missing directive globally)
        if not server_tokens_nodes:
            # Ưu tiên chèn vào khối 'http' nếu tìm thấy khối này
            if http_block_info:
                fp, ep, d = http_block_info
                uncompliances.append({
                    "file": fp,
                    "remediations": [{
                        "action": "add",
                        "directive": "server_tokens",
                        "value": "off",
                        "context": d # Payload gửi cho Thành viên 2 chứa node AST của khối 'http'
                    }]
                })
            else:
                # Fallback: Nếu không có cả khối 'http' (hiếm gặp trên NGINX, trừ trường hợp chỉ có stream),
                # Yêu cầu chèn thẳng vào file cấu hình đầu tiên phân tích được (hoặc file gốc).
                configs = parser_output.get("config", [])
                if configs:
                    fp = configs[0].get("file", "")
                    uncompliances.append({
                        "file": fp,
                        "remediations": [{
                            "action": "add",
                            "directive": "server_tokens",
                            "value": "off",
                            "context": None
                        }]
                    })
        
        # TÌNH HUỐNG 2: Đã có chỉ thị 'server_tokens' được cấu hình
        else:
            # Kiểm tra tất cả các khai báo đã thu thập
            for fp, ep, d in server_tokens_nodes:
                args = d.get("args", [])
                val = args[0].strip("\"'") if args else ""
                
                # Nếu phát hiện bất kỳ khai báo nào vi phạm (nghĩa là giá trị khác 'off')
                # (VD: cấu hình chung là off, nhưng một file api.conf lại đặt server_tokens on;)
                if val.lower() != "off":
                    uncompliances.append({
                        "file": fp,
                        "remediations": [{
                            "action": "modify", # Yêu cầu sửa cấu hình tại chính node này
                            "directive": "server_tokens",
                            "value": "off",
                            "context": d # Truyền chính node vi phạm để Auto-Remediation có thể replace chính xác
                        }]
                    })
                    
        # Gộp các lỗi theo từng file (Grouping) để xuất JSON Contract chuẩn cho Thành viên 2 (Auto-Remediation)
        return self._group_by_file(uncompliances)
