from typing import Dict, List, Any, Optional
import fnmatch
from core.scannerEng.base_recom import BaseRecom


class Detector34(BaseRecom):
    def __init__(self):
        super().__init__()
        self.id = "3.4"
        self.title = "Ensure proxies pass source IP information (Manual)"
        self.description = "When NGINX acts as a reverse proxy or load balancer, it terminates the client connection and opens a new connection to the upstream application server. Standard HTTP headers like X-Forwarded-For and X-Real-IP must be explicitly configured to pass the original client's IP address."
        self.audit_procedure = "Check the active configuration for proxy header directives in proxied locations and verify that proxy_set_header X-Forwarded-For and proxy_set_header X-Real-IP are present."
        self.impact = "Enabling these headers allows the backend application to see the original client IP. However, if NGINX simply appends to an existing X-Forwarded-For header sent by a malicious client, the backend might be tricked into trusting a spoofed IP."
        self.remediation = "Configure NGINX to forward client IP information in your server or location blocks where proxy_pass is used."
        self.level = "Level 1 - Proxy, Level 1 - Loadbalancer"

    def scan(self, parser_output: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Quét toàn bộ AST để tìm các cấu hình Nginx đóng vai trò proxy (có proxy_pass)
        nhưng không cấu hình truyền IP thật của client (X-Forwarded-For, X-Real-IP).
        """
        uncompliances = []
        # Tạo map lưu trữ nội dung AST của từng file cấu hình
        files_map = {f.get("file", ""): f.get("parsed", []) for f in parser_output.get("config", [])}
        
        # Trích xuất các cấu hình proxy_set_header ở block 'http' cấp cao nhất.
        # Điều này giúp xử lý các trường hợp mock AST không có liên kết include đầy đủ.
        global_http_headers = {}
        for filepath, parsed in files_map.items():
            for d in parsed:
                if d.get("directive") == "http":
                    for sub_d in d.get("block", []):
                        if sub_d.get("directive") == "proxy_set_header" and len(sub_d.get("args", [])) >= 2:
                            header_name = sub_d["args"][0].lower()
                            header_val = sub_d["args"][1]
                            global_http_headers[header_name] = header_val

        # Tìm các file gốc (root files) không bị include bởi bất kỳ file nào khác
        included_patterns = set()
        for filepath, parsed in files_map.items():
            self._find_includes(parsed, included_patterns)
            
        root_files = []
        for filepath in files_map.keys():
            is_included = False
            for pat in included_patterns:
                if fnmatch.fnmatch(filepath, pat):
                    is_included = True
                    break
            if not is_included:
                root_files.append(filepath)
                
        # Nếu không tìm thấy root_files (vd: file đơn lẻ), lấy file đầu tiên
        if not root_files and files_map:
            root_files = [list(files_map.keys())[0]]
            
        # Duyệt cây AST bắt đầu từ các file gốc
        for filepath in root_files:
            parsed = files_map[filepath]
            config_idx = next((i for i, f in enumerate(parser_output.get("config", [])) if f.get("file") == filepath), 0)
            
            # Nếu file này không có block 'http' ở root, giả định nó là file được include 
            # (ví dụ: conf.d/server.conf) và cần kế thừa global_http_headers.
            initial_headers = {}
            if not any(d.get("directive") == "http" for d in parsed):
                initial_headers = global_http_headers.copy()
                
            self._traverse(parsed, filepath, [], ["config", config_idx, "parsed"], initial_headers, files_map, parser_output, uncompliances)
            
        # Gom nhóm lỗi (uncompliances) theo file
        return self._group_by_file(uncompliances)
        
    def _find_includes(self, directives: List[Dict], included_patterns: set):
        """Hàm helper để tìm tất cả các pattern của chỉ thị 'include' trong AST."""
        for d in directives:
            if d.get("directive") == "include" and d.get("args"):
                included_patterns.add(d["args"][0])
            if "block" in d:
                self._find_includes(d["block"], included_patterns)

    def _traverse(self, directives: List[Dict], filepath: str, logical_context: List[str], exact_path: List[Any], current_headers: Dict[str, str], files_map: Dict[str, List[Dict]], parser_output: Dict[str, Any], uncompliances: List[Dict]):
        """
        Duyệt đệ quy cây AST. 
        Theo dõi trạng thái các header (current_headers) được kế thừa.
        Lưu ý: Trong Nginx, nếu một block có chỉ thị proxy_set_header, nó sẽ GHI ĐÈ 
        hoàn toàn danh sách proxy_set_header từ block cha chứ không gộp vào.
        """
        has_proxy_set_header = False
        block_headers = {}
        
        # Kiểm tra xem block hiện tại có định nghĩa proxy_set_header nào không
        for d in directives:
            if d.get("directive") == "proxy_set_header" and len(d.get("args", [])) >= 2:
                has_proxy_set_header = True
                header_name = d["args"][0].lower()
                header_val = d["args"][1]
                block_headers[header_name] = header_val
                
        # Nếu có khai báo, áp dụng luật ghi đè của Nginx.
        # Ngược lại, kế thừa danh sách headers từ context cha.
        if has_proxy_set_header:
            active_headers = block_headers
        else:
            active_headers = current_headers.copy()
            
        for idx, d in enumerate(directives):
            d_name = d.get("directive")
            d_args = d.get("args", [])
            current_exact_path = exact_path + [idx]
            
            # Xử lý chỉ thị include: duyệt file được gọi với context & headers hiện tại
            if d_name == "include" and d_args:
                pattern = d_args[0]
                for fpath, fparsed in files_map.items():
                    if fnmatch.fnmatch(fpath, pattern):
                        config_idx = next((i for i, f in enumerate(parser_output.get("config", [])) if f.get("file") == fpath), 0)
                        self._traverse(fparsed, fpath, logical_context + ["include"], ["config", config_idx, "parsed"], active_headers, files_map, parser_output, uncompliances)
                        
            # Xử lý chỉ thị proxy_pass: lúc này cần kiểm tra xem các header truyền IP đã an toàn chưa
            if d_name == "proxy_pass":
                xfwd = active_headers.get("x-forwarded-for", "")
                xreal = active_headers.get("x-real-ip", "")
                
                is_safe = True
                # Yêu cầu giá trị header phải sử dụng biến của Nginx (chứa dấu $)
                # Chặn các trường hợp hardcode tĩnh như '1.1.1.1'
                if "$" not in xfwd or "$" not in xreal:
                    is_safe = False
                    
                if not is_safe:
                    remediations = []
                    if "$" not in xfwd:
                        remediations.append({
                            "action": "add",
                            "directive": "proxy_set_header",
                            "value": "X-Forwarded-For $proxy_add_x_forwarded_for",
                            "context": logical_context
                        })
                    if "$" not in xreal:
                        remediations.append({
                            "action": "add",
                            "directive": "proxy_set_header",
                            "value": "X-Real-IP $remote_addr",
                            "context": logical_context
                        })
                    
                    uncompliances.append({
                        "file": filepath,
                        "exact_path": exact_path,
                        "remediations": remediations
                    })
                    
            # Đệ quy vào các block con
            if "block" in d:
                new_logical_context = logical_context + [d_name]
                new_exact_path = current_exact_path + ["block"]
                self._traverse(d["block"], filepath, new_logical_context, new_exact_path, active_headers, files_map, parser_output, uncompliances)

    def evaluate(self, directive: Dict, filepath: str, logical_context: List[str], exact_path: List[Any]) -> Optional[Dict]:
        """
        Hàm evaluate phục vụ cho việc kiểm thử và quét một block độc lập.
        Tạo dữ liệu mock và gọi hàm duyệt _traverse như một AST thực.
        """
        if "block" not in directive:
            return None
            
        uncompliances = []
        parser_output_mock = {"config": [{"file": filepath, "parsed": [directive]}]}
        files_map_mock = {filepath: [directive]}
        
        self._traverse([directive], filepath, logical_context[:-1], exact_path[:-1], {}, files_map_mock, parser_output_mock, uncompliances)
        
        if uncompliances:
            first = uncompliances[0]
            return {
                "file": filepath,
                "remediations": first["remediations"]
            }
        return None
