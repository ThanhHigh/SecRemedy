from typing import Dict, List, Any, Optional
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
        self.level = "Level 1"

    def _is_valid_header_value(self, value: str) -> bool:
        if not value:
            return False
        # Loại bỏ ngoặc kép nếu có
        value = value.strip('"\'')
        if not value:
            return False
        # Phải là một biến (chứa ký tự $) để lấy IP động của client
        return '$' in value

    def evaluate(self, directive: Dict, filepath: str, logical_context: List[str], exact_path: List[Any]) -> Optional[Dict]:
        remediations = []

        def traverse(d: Dict, state: Dict[str, str]):
            current_state = dict(state)
            if "block" in d:
                # 1. Thu thập proxy_set_header ở level hiện tại
                for child in d["block"]:
                    if child.get("directive") == "proxy_set_header":
                        args = child.get("args", [])
                        if len(args) >= 2:
                            current_state[args[0].lower()] = args[1]
                
                # 2. Xử lý proxy_pass và đệ quy vào các block con
                for child in d["block"]:
                    child_dir = child.get("directive")
                    if child_dir == "proxy_pass":
                        valid_xff = self._is_valid_header_value(current_state.get("x-forwarded-for", ""))
                        valid_xrealip = self._is_valid_header_value(current_state.get("x-real-ip", ""))
                        if not valid_xrealip:
                            remediations.append({
                                "action": "add",
                                "directive": "proxy_set_header",
                                "args": ["X-Real-IP", "$remote_addr"],
                                "context": "location"
                            })
                        if not valid_xff:
                            remediations.append({
                                "action": "add",
                                "directive": "proxy_set_header",
                                "args": ["X-Forwarded-For", "$proxy_add_x_forwarded_for"],
                                "context": "location"
                            })
                    elif "block" in child:
                        traverse(child, current_state)

        traverse(directive, {})
        
        if remediations:
            return {"file": filepath, "remediations": remediations}
        return None

    def scan(self, parser_output: Dict[str, Any]) -> List[Dict[str, Any]]:
        global_configs = {}
        for config in parser_output.get("config", []):
            global_configs[config.get("file", "")] = config.get("parsed", [])

        # Tìm tất cả các file được include để tránh quét lặp (double-scan)
        included_files = set()
        def find_includes(dirs: List[Dict]):
            for d in dirs:
                if d.get("directive") == "include":
                    args = d.get("args", [])
                    if args:
                        inc_pattern = args[0].replace("*.conf", "").replace("*", "")
                        for fpath in global_configs.keys():
                            if inc_pattern in fpath:
                                included_files.add(fpath)
                if "block" in d:
                    find_includes(d["block"])
                    
        for parsed in global_configs.values():
            find_includes(parsed)

        findings_by_file = {}

        def traverse_scan(directives: List[Dict], filepath: str, state: Dict[str, str]):
            current_state = dict(state)
            
            def collect_headers(dirs: List[Dict]):
                for d in dirs:
                    d_name = d.get("directive")
                    if d_name == "proxy_set_header":
                        args = d.get("args", [])
                        if len(args) >= 2:
                            current_state[args[0].lower()] = args[1]
                    elif d_name == "include":
                        args = d.get("args", [])
                        if args:
                            inc_pattern = args[0].replace("*.conf", "").replace("*", "")
                            for fpath, parsed in global_configs.items():
                                if inc_pattern in fpath:
                                    collect_headers(parsed)
                                    
            collect_headers(directives)

            for d in directives:
                d_name = d.get("directive")
                if d_name == "proxy_pass":
                    valid_xff = self._is_valid_header_value(current_state.get("x-forwarded-for", ""))
                    valid_xrealip = self._is_valid_header_value(current_state.get("x-real-ip", ""))
                    if not valid_xrealip:
                        if filepath not in findings_by_file:
                            findings_by_file[filepath] = []
                        findings_by_file[filepath].append({
                            "action": "add",
                            "directive": "proxy_set_header",
                            "args": ["X-Real-IP", "$remote_addr"],
                            "context": "location"
                        })
                    if not valid_xff:
                        if filepath not in findings_by_file:
                            findings_by_file[filepath] = []
                        findings_by_file[filepath].append({
                            "action": "add",
                            "directive": "proxy_set_header",
                            "args": ["X-Forwarded-For", "$proxy_add_x_forwarded_for"],
                            "context": "location"
                        })
                elif d_name == "include":
                    args = d.get("args", [])
                    if args:
                        inc_pattern = args[0].replace("*.conf", "").replace("*", "")
                        for inc_fpath, parsed in global_configs.items():
                            if inc_pattern in inc_fpath:
                                traverse_scan(parsed, inc_fpath, current_state)
                elif "block" in d:
                    traverse_scan(d["block"], filepath, current_state)

        for config in parser_output.get("config", []):
            filepath = config.get("file", "")
            # Chỉ bắt đầu scan từ các file gốc (không phải file include)
            # Hoặc nếu config chỉ có 1 file thì vẫn quét
            if filepath not in included_files or len(global_configs) == 1:
                traverse_scan(config.get("parsed", []), filepath, {})

        findings = []
        for filepath, remediations in findings_by_file.items():
            findings.append({
                "file": filepath,
                "remediations": remediations
            })
        return findings
