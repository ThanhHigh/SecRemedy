import fnmatch
from typing import Dict, List, Any, Optional
from core.scannerEng.base_recom import BaseRecom


class Detector253(BaseRecom):
    def __init__(self):
        super().__init__()
        # Thông tin metadata theo chuẩn CIS Benchmark 2.5.3
        self.id = "2.5.3"
        self.title = "Ensure hidden file serving is disabled (Manual)"
        self.description = "Hidden files and directories (starting with a dot, e.g., .git, .env) often contain sensitive metadata, version control history, or environment configurations. Serving these files should be globally disabled."
        self.audit_procedure = 'Search the loaded configuration for hidden file protection rules using `nginx -T 2>/dev/null | grep "location.*\\\\."` and look for a block like `location ~ /\\. { deny all; ... }`. Optionally, try to access a dummy hidden file and verify it returns a 403 Forbidden or 404 Not Found.'
        self.impact = "Blocking all dot-files will break Let's Encrypt / Certbot validation (.well-known/acme-challenge) unless explicitly allowed. Ensure the exception rule is placed before the deny rule or is more specific."
        self.remediation = "To restrict access to hidden files, add a configuration block denying access to hidden files inside each server block directly, or create a reusable snippet file containing the rules and include it in your server blocks."
        self.level = "Level 1"

    def evaluate(self, directive: Dict, filepath: str, logical_context: List[str], exact_path: List[Any]) -> Optional[Dict]:
        """
        Kiểm tra trực tiếp một khối (chỉ áp dụng cho khối server) xem nó có chặn truy cập vào các file ẩn hay không.
        Trả về None nếu cấu hình an toàn, ngược lại trả về đối tượng JSON chỉ định cách khắc phục (Remediation).
        """
        d_name = directive.get("directive")
        # Chỉ đánh giá trên khối server
        if d_name != "server":
            return None
            
        is_protected = False
        seen_hidden_regex = False
        wrong_order = False
        
        def is_safe_location(c_args, c_block):
            """Hàm helper: Đánh giá xem khối location hiện tại có chỉ thị chặn an toàn file ẩn không."""
            modifier = c_args[0] if len(c_args) > 1 else ""
            pattern = c_args[1] if len(c_args) > 1 else c_args[0]
            is_regex = modifier in ["~", "~*"]
            
            # Kiểm tra nếu location này có bắt regex bắt đầu với dấu chấm (file ẩn)
            if is_regex and pattern in [r"/\.", r"\.", r"/\.(?!well-known).*"]:
                for b in c_block:
                    # Trả về True nếu sử dụng lệnh cấm truy cập
                    if b.get("directive") == "deny" and b.get("args") == ["all"]:
                        return True
                    # Trả về True nếu sử dụng lệnh trả về mã lỗi 403 hoặc 404
                    if b.get("directive") == "return" and b.get("args") and b["args"][0] in ["403", "404"]:
                        return True
            return False

        # Duyệt qua các thành phần con của khối server
        for child in directive.get("block", []):
            c_name = child.get("directive")
            c_args = child.get("args", [])
            c_block = child.get("block", [])
            
            # Nếu include một file cấu hình bảo mật thông dụng
            if c_name == "include" and c_args:
                inc_path = c_args[0].lower()
                if any(x in inc_path for x in ["hidden", "security", "global_deny", "block_dot_files", "dotfiles"]):
                    is_protected = True
                    
            if c_name == "location" and len(c_args) >= 1:
                modifier = c_args[0] if len(c_args) > 1 else ""
                pattern = c_args[1] if len(c_args) > 1 else c_args[0]
                is_regex = modifier in ["~", "~*"]
                
                # Kiểm tra lỗi đặt sai thứ tự: Rule cho Let's Encrypt (.well-known)
                # cần phải đứng trước rule chặn file ẩn khi sử dụng regex trong NGINX
                if "well-known" in pattern:
                    if is_regex and seen_hidden_regex:
                        wrong_order = True
                        
                # Đánh dấu đã thấy chỉ thị bảo mật
                if is_safe_location(c_args, c_block):
                    is_protected = True
                    seen_hidden_regex = True
                    
        # Khối server an toàn khi có rule bảo vệ và rule ngoại lệ đặt đúng thứ tự
        if is_protected and not wrong_order:
            return None
            
        # Trả về JSON Contract hướng dẫn bộ phận Remediation cách tự động thêm đoạn mã bảo mật
        return {
            "file": filepath,
            "remediations": [{
                "action": "add_block", # Hành động: Thêm khối cấu hình mới
                "directive": "location",
                "value": "location ~ /\\. {\n    deny all;\n}",
                "context": "server"
            }]
        }

    def scan(self, parser_output: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Quét toàn bộ cây cấu hình (AST) NGINX để phát hiện lỗi bảo mật và gộp nhóm lỗi theo file.
        Sử dụng kỹ thuật duyệt 2 bước (Pre-pass) để xử lý tính liên kết toàn cục của NGINX include.
        """
        uncompliances = []
        safe_files = set()
        
        def is_safe_location(c_args, c_block):
            """Hàm helper: Xác minh khối location có logic chặn file ẩn."""
            modifier = c_args[0] if len(c_args) > 1 else ""
            pattern = c_args[1] if len(c_args) > 1 else c_args[0]
            is_regex = modifier in ["~", "~*"]
            if is_regex and pattern in [r"/\.", r"\.", r"/\.(?!well-known).*"]:
                for b in c_block:
                    if b.get("directive") == "deny" and b.get("args") == ["all"]:
                        return True
                    if b.get("directive") == "return" and b.get("args") and b["args"][0] in ["403", "404"]:
                        return True
            return False

        # Bước 1 (Pre-pass): Quét qua một lượt để thu thập danh sách tên file cấu hình có chứa rule bảo mật
        def find_safe_locations(directives, filepath):
            for d in directives:
                if d.get("directive") == "location":
                    if is_safe_location(d.get("args", []), d.get("block", [])):
                        safe_files.add(filepath.split("/")[-1])
                if "block" in d:
                    find_safe_locations(d.get("block", []), filepath)

        for config_file in parser_output.get("config", []):
            find_safe_locations(config_file.get("parsed", []), config_file.get("file", ""))

        def check_server_with_globals(server_d):
            """Hàm helper: Đánh giá khối server có an toàn hay không (xét cả trường hợp file include bảo mật bên ngoài)."""
            # Kiểm tra nội bộ server bằng phương thức evaluate
            eval_result = self.evaluate(server_d, "", [], [])
            if eval_result is None:
                return True
                
            # Nếu nội bộ không an toàn, kiểm tra xem server này có sử dụng include trỏ đến
            # bất kỳ file an toàn nào (đã được lấy từ Pre-pass) hay không
            for child in server_d.get("block", []):
                if child.get("directive") == "include" and child.get("args"):
                    inc_path = child["args"][0]
                    inc_basename = inc_path.split("/")[-1]
                    for sf in safe_files:
                        if sf == inc_basename or inc_path.endswith(sf):
                            return True
            return False

        # Bước 2: Duyệt toàn bộ cây AST để kiểm tra tính tuân thủ của từng khối server
        def traverse(directives, filepath, exact_path):
            for idx, d in enumerate(directives):
                if d.get("directive") == "server":
                    # Nếu server được đánh giá là thiếu rule bảo mật file ẩn
                    if not check_server_with_globals(d):
                        uncompliances.append({
                            "file": filepath,
                            "remediations": [{
                                "action": "add_block",
                                "directive": "location",
                                "value": "location ~ /\\. {\n    deny all;\n}",
                                "context": "server"
                            }]
                        })
                # Nếu là các khối chứa con (http, server, location, if,...), thì đệ quy duyệt xuống
                elif "block" in d:
                    traverse(d.get("block", []), filepath, exact_path + [idx, "block"])
                    
        # Kích hoạt quá trình duyệt cấu trúc cây của các file NGINX
        for config_idx, config_file in enumerate(parser_output.get("config", [])):
            traverse(config_file.get("parsed", []), config_file.get("file", ""), ["config", config_idx, "parsed"])
            
        # Nén và phân nhóm các lỗi của cùng 1 file, sau đó trả về mảng kết quả để xử lý Remediation
        return self._group_by_file(uncompliances)
