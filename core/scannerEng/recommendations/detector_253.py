import fnmatch
from typing import Dict, List, Any, Optional
from core.scannerEng.base_recom import BaseRecom


class Detector253(BaseRecom):
    def __init__(self):
        super().__init__()
        self.id = "2.5.3"
        self.title = "Ensure hidden file serving is disabled (Manual)"
        self.description = "Hidden files and directories (starting with a dot, e.g., .git, .env) often contain sensitive metadata, version control history, or environment configurations. Serving these files should be globally disabled."
        self.audit_procedure = 'Search the loaded configuration for hidden file protection rules using `nginx -T 2>/dev/null | grep "location.*\\\\."` and look for a block like `location ~ /\\. { deny all; ... }`. Optionally, try to access a dummy hidden file and verify it returns a 403 Forbidden or 404 Not Found.'
        self.impact = "Blocking all dot-files will break Let's Encrypt / Certbot validation (.well-known/acme-challenge) unless explicitly allowed. Ensure the exception rule is placed before the deny rule or is more specific."
        self.remediation = "To restrict access to hidden files, add a configuration block denying access to hidden files inside each server block directly, or create a reusable snippet file containing the rules and include it in your server blocks."
        self.level = "Level 1"

    def _is_general_hidden_file_path(self, path: str) -> bool:
        path = path.strip()
        if path == r"/\.":
            return True
        if path.startswith(r"/\.(?!well-known"):
            return True
        return False

    def _has_secure_action(self, directives: List[Dict]) -> bool:
        for d in directives:
            if d.get("directive") == "deny" and "all" in d.get("args", []):
                return True
            if d.get("directive") == "return":
                args = d.get("args", [])
                if args and args[0] in ["404", "403", "444"]:
                    return True
        return False

    def _has_protected_location(self, directives: List[Dict]) -> bool:
        for d in directives:
            if d.get("directive") == "location":
                args = d.get("args", [])
                if any(self._is_general_hidden_file_path(arg) for arg in args):
                    if self._has_secure_action(d.get("block", [])):
                        return True
        return False

    def _is_server_protected(self, server_directive: Dict, protected_files: set) -> bool:
        if self._has_protected_location(server_directive.get("block", [])):
            return True
        
        for d in server_directive.get("block", []):
            if d.get("directive") == "include":
                for arg in d.get("args", []):
                    pattern = arg if arg.startswith("/") else "*/" + arg
                    for pfile in protected_files:
                        if fnmatch.fnmatch(pfile, pattern):
                            return True
        return False

    def _is_ignored_server(self, directives: List[Dict]) -> bool:
        if not directives:
            return True
        has_root_or_location = False
        has_return_or_rewrite = False
        for d in directives:
            if d.get("directive") in ["root", "location", "proxy_pass", "fastcgi_pass"]:
                has_root_or_location = True
            if d.get("directive") in ["return", "rewrite"]:
                has_return_or_rewrite = True
        
        if has_return_or_rewrite and not has_root_or_location:
            return True
            
        return False

    def evaluate(self, directive: Dict, filepath: str, logical_context: List[str], exact_path: List[Any]) -> Optional[Dict]:
        """
        Hàm evaluate được sử dụng để kiểm tra một block độc lập (Dùng chủ yếu cho Unit Test).
        Nó sẽ nhận vào một block (như `server` hoặc `http`) và kiểm tra xem có chặn file ẩn hay chưa.
        """
        if directive.get("directive") not in ["http", "server"]:
            return None

        servers_to_check = []
        if directive.get("directive") == "http":
            for d in directive.get("block", []):
                if d.get("directive") == "server":
                    servers_to_check.append(d)
        elif directive.get("directive") == "server":
            servers_to_check.append(directive)

        remediations = []
        for srv in servers_to_check:
            # Truyền một set rỗng (set()) vì evaluate() chạy cục bộ, không có ngữ cảnh của các file snippet bên ngoài
            if not self._is_server_protected(srv, set()):
                remediations.append({
                    "action": "add",
                    "directive": "location",
                    "context": "server",
                    "block": [
                        {"directive": "deny", "args": ["all"]},
                        {"directive": "access_log", "args": ["off"]},
                        {"directive": "log_not_found", "args": ["off"]}
                    ]
                })

        if remediations:
            return {"file": filepath, "remediations": remediations}
        return None

    def scan(self, parser_output: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Hàm scan là entrypoint chính trong hệ thống thực tế. Nó sử dụng thuật toán 2-pass.
        - Bước 1 (Pass 1): Tìm tất cả các file cấu hình có chứa sẵn snippet chặn file ẩn an toàn.
        - Bước 2 (Pass 2): Quét lại mọi block server, nếu server thiếu cấu hình cục bộ và không include 
                           các file snippet an toàn đã tìm thấy, báo cáo cần Remediation.
        """
        configs = parser_output.get("config", [])
        
        # Bước 1: Quét tìm các file cấu hình chứa cấu trúc chặn (ví dụ các file snippet dùng chung)
        protected_files = set()
        for config in configs:
            if self._has_protected_location(config.get("parsed", [])):
                protected_files.add(config.get("file", ""))
        
        findings = []
        file_remediations = {}
        
        def add_rem(fp, rem):
            if fp not in file_remediations:
                file_remediations[fp] = []
            file_remediations[fp].append(rem)
            
        # Bước 2: Duyệt từng file, quét sâu vào từng block server để đối chiếu
        for config_idx, config in enumerate(configs):
            filepath = config.get("file", "")
            parsed = config.get("parsed", [])
            
            def traverse(directives, current_path):
                for i, d in enumerate(directives):
                    if d.get("directive") == "server":
                        server_block = d.get("block", [])
                        
                        # Bỏ qua các server chỉ dùng để redirect (VD: chuyển hướng http sang https)
                        if self._is_ignored_server(server_block):
                            continue
                            
                        # Nếu block server này không được bảo vệ cục bộ VÀ không include snippet bảo vệ nào
                        if not self._is_server_protected(d, protected_files):
                            # Tạo contract JSON chỉ định Auto-Remediation chèn khối location chặn file ẩn
                            add_rem(filepath, {
                                "action": "add",
                                "directive": "location",
                                "context": "server",
                                "block": [
                                    {"directive": "deny", "args": ["all"]},
                                    {"directive": "access_log", "args": ["off"]},
                                    {"directive": "log_not_found", "args": ["off"]}
                                ]
                            })
                            
                    elif "block" in d:
                        traverse(d.get("block", []), current_path + [i, "block"])
                        
            traverse(parsed, ["config", config_idx, "parsed"])
            
        # Gom nhóm lỗi (Grouping) theo file cho JSON Contract
        for fp, rems in file_remediations.items():
            findings.append({
                "file": fp,
                "remediations": rems
            })
            
        return findings
