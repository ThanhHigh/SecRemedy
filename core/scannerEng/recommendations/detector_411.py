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

    def _is_server_compliant(self, server_directive: Dict) -> bool:
        block = server_directive.get("block", [])
        
        # Kiểm tra xem khối server này có lắng nghe trên cổng HTTP public (80) hay không.
        # Lưu ý (Architecture / MVP): Các cổng khác (như 8080, 3000, 9000...) thường là 
        # các cổng nội bộ (internal ports) dùng để Nginx giao tiếp với backend app 
        # (Reverse Proxy) và chúng chỉ chạy HTTP thuần. 
        # Do đó, thuật toán sẽ bỏ qua và coi chúng là hợp lệ để tránh làm gãy (break)
        # các luồng kết nối nội bộ khi ép buộc chuyển sang HTTPS.
        listens_on_80 = False
        for d in block:
            if d.get("directive") == "listen":
                args = d.get("args", [])
                for a in args:
                    if a == "80" or a.endswith(":80"):
                        listens_on_80 = True
                        break
        
        if not listens_on_80:
            return True
            
        # Nếu đã lắng nghe trên cổng 80, BẮT BUỘC phải có lệnh chuyển hướng (redirect) sang HTTPS
        return self._has_https_redirect(block)

    def _has_https_redirect(self, block: List[Dict]) -> bool:
        for d in block:
            if d.get("directive") == "return":
                args = d.get("args", [])
                if any(a.startswith("https://") for a in args):
                    return True
            elif d.get("directive") == "rewrite":
                args = d.get("args", [])
                if any(a.startswith("https://") for a in args):
                    return True
            elif d.get("directive") == "if":
                if self._has_https_redirect(d.get("block", [])):
                    return True
        return False

    def evaluate(self, directive: Dict, filepath: str, logical_context: List[str], exact_path: List[Any]) -> Optional[Dict]:
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
            if not self._is_server_compliant(srv):
                remediations.append({
                    "action": "add",
                    "directive": "return",
                    "context": "server"
                })

        if remediations:
            return {"file": filepath, "remediations": remediations}
        return None

    def scan(self, parser_output: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings = []
        for config_idx, config in enumerate(parser_output.get("config", [])):
            filepath = config.get("file", "")
            parsed = config.get("parsed", [])
            
            remediations = []
            def traverse(directives, in_stream=False):
                for d in directives:
                    if d.get("directive") == "server":
                        if not in_stream and not self._is_server_compliant(d):
                            remediations.append({
                                "action": "add",
                                "directive": "return",
                                "context": "server"
                            })
                    elif "block" in d:
                        traverse(d.get("block", []), in_stream=in_stream or d.get("directive") == "stream")
            
            traverse(parsed)
            if remediations:
                findings.append({
                    "file": filepath,
                    "remediations": remediations
                })
        return findings
