from typing import Dict, List, Any, Optional
from core.scannerEng.base_recom import BaseRecom


class Detector242(BaseRecom):
    def __init__(self):
        super().__init__()
        self.id = "2.4.2"
        self.title = "Ensure requests for unknown host names are rejected"
        self.level = "Level 1"
        self.description = "NGINX should have a catch-all default server block that rejects requests for unknown hostnames, preventing Host Header attacks and unintended application exposure."
        self.audit_procedure = "Check for a default server block using `nginx -T 2>/dev/null | grep -Ei \"listen.*default_server|ssl_reject_handshake\"`. Verify it contains `return 444;` or a 4xx error code. For HTTPS/TLS, verify `ssl_reject_handshake on;` is used."
        self.impact = "Clients accessing the server directly via IP address or an unconfigured CNAME will be rejected. All valid domains must be explicitly defined in their own server blocks."
        self.remediation = "Configure a catch-all default server block as the first block in your http configuration (or explicitly marked with default_server). It should return 444 for HTTP and use ssl_reject_handshake on for HTTPS."

    def _is_http_catchall(self, server_block: Dict) -> bool:
        """
        Kiểm tra xem khối server có phải là khối catch-all cho HTTP hay không.
        Khối này phải lắng nghe với tham số 'default_server' và từ chối các yêu cầu (ví dụ: return 444).
        """
        has_default_listen = False
        has_reject = False

        for d in server_block.get("block", []):
            if d.get("directive") == "listen":
                args = d.get("args", [])
                if "ssl" not in args and "quic" not in args:
                    if "default_server" in args:
                        has_default_listen = True
            elif d.get("directive") == "return":
                args = d.get("args", [])
                if args and args[0] in ("444", "400", "401", "403", "404"):
                    has_reject = True

        return has_default_listen and has_reject

    def _is_https_catchall(self, server_block: Dict) -> bool:
        """
        Kiểm tra xem khối server có phải là khối catch-all cho HTTPS hay không.
        Khối này phải lắng nghe bằng TLS (ssl/quic) với 'default_server' và từ chối bắt tay SSL ('ssl_reject_handshake on').
        """
        has_default_listen = False
        has_reject = False

        for d in server_block.get("block", []):
            if d.get("directive") == "listen":
                args = d.get("args", [])
                if "ssl" in args or "quic" in args:
                    if "default_server" in args:
                        has_default_listen = True
            elif d.get("directive") == "ssl_reject_handshake":
                args = d.get("args", [])
                if args and args[0] == "on":
                    has_reject = True

        return has_default_listen and has_reject

    def evaluate(self, directive: Dict, filepath: str, logical_context: List[str], exact_path: List[Any]) -> Optional[Dict]:
        """
        Đánh giá một chỉ thị cấu hình.
        Để tương thích với các bài kiểm thử unit (unit tests), nếu chỉ thị là 'http', hàm sẽ kiểm tra nội dung bên trong.
        """
        if directive.get("directive") != "http":
            return None

        # Trạng thái theo dõi xem cấu hình có chứa khối catch-all hay không
        global_http_catchall = False
        global_https_catchall = False
        
        # Theo dõi xem cấu hình có phục vụ HTTP hay HTTPS không
        has_http_listen = False
        has_https_listen = False

        for d in directive.get("block", []):
            if d.get("directive") == "server":
                # Kiểm tra các khối server để phát hiện khối catch-all hợp lệ
                if self._is_http_catchall(d):
                    global_http_catchall = True
                if self._is_https_catchall(d):
                    global_https_catchall = True

                has_any_listen = False
                for sub in d.get("block", []):
                    if sub.get("directive") == "listen":
                        has_any_listen = True
                        args = sub.get("args", [])
                        if "ssl" in args or "quic" in args:
                            has_https_listen = True
                        else:
                            has_http_listen = True
                
                # NGINX mặc định lắng nghe ở cổng 80 (HTTP) nếu không có chỉ thị listen
                if not has_any_listen:
                    has_http_listen = True

        remediations = []
        
        # Nếu có phục vụ HTTP nhưng thiếu khối catch-all, tạo đối tượng khắc phục (thêm khối return 444)
        if has_http_listen and not global_http_catchall:
            remediations.append({
                "action": "add",
                "directive": "server",
                "context": exact_path + ["block"],
                "block": [
                    {"directive": "listen", "args": ["80", "default_server"]},
                    {"directive": "return", "args": ["444"]}
                ]
            })

        # Nếu có phục vụ HTTPS nhưng thiếu khối catch-all, tạo đối tượng khắc phục (thêm khối ssl_reject_handshake)
        if has_https_listen and not global_https_catchall:
            remediations.append({
                "action": "add",
                "directive": "server",
                "context": exact_path + ["block"],
                "block": [
                    {"directive": "listen", "args": ["443", "ssl", "default_server"]},
                    {"directive": "ssl_reject_handshake", "args": ["on"]}
                ]
            })

        if remediations:
            return {
                "file": filepath,
                "remediations": remediations
            }

        return None

    def scan(self, parser_output: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Duyệt toàn cục (Global scan) qua tất cả các tệp cấu hình để phát hiện sự thiếu sót của các khối server catch-all.
        Giải pháp này cho phép phát hiện nếu khối catch-all được định nghĩa trong một tệp riêng biệt (ví dụ thông qua include).
        """
        global_http_catchall = False
        global_https_catchall = False

        has_http_listen = False
        has_https_listen = False

        # Lưu trữ vị trí (context) của khối http để thêm khối catch-all vào nếu cần
        http_block_context = None

        def traverse(directives, exact_path, filepath):
            nonlocal global_http_catchall, global_https_catchall
            nonlocal has_http_listen, has_https_listen, http_block_context

            for idx, d in enumerate(directives):
                curr_path = exact_path + [idx]

                if d.get("directive") == "http":
                    if http_block_context is None:
                        http_block_context = {
                            "filepath": filepath,
                            "exact_path": curr_path
                        }

                if d.get("directive") == "server":
                    # Ghi nhận nếu tìm thấy khối catch-all bất kỳ đâu trong cấu hình
                    if self._is_http_catchall(d):
                        global_http_catchall = True
                    if self._is_https_catchall(d):
                        global_https_catchall = True

                    has_any_listen = False
                    for sub in d.get("block", []):
                        if sub.get("directive") == "listen":
                            has_any_listen = True
                            args = sub.get("args", [])
                            if "ssl" in args or "quic" in args:
                                has_https_listen = True
                            else:
                                has_http_listen = True
                    
                    if not has_any_listen:
                        has_http_listen = True

                if "block" in d:
                    traverse(d["block"], curr_path + ["block"], filepath)

        # Lặp qua tất cả các file cấu hình được phân tích (parsed AST)
        for config_idx, config_file in enumerate(parser_output.get("config", [])):
            filepath = config_file.get("file", "")
            if not filepath.endswith(".conf"):
                continue
            parsed_ast = config_file.get("parsed", [])
            traverse(parsed_ast, ["config", config_idx, "parsed"], filepath)

        # Nếu không tìm thấy khối http, không thực hiện gì thêm
        if not http_block_context:
            return []

        remediations = []
        
        if has_http_listen and not global_http_catchall:
            remediations.append({
                "action": "add",
                "directive": "server",
                "context": http_block_context["exact_path"] + ["block"],
                "block": [
                    {"directive": "listen", "args": ["80", "default_server"]},
                    {"directive": "return", "args": ["444"]}
                ]
            })

        if has_https_listen and not global_https_catchall:
            remediations.append({
                "action": "add",
                "directive": "server",
                "context": http_block_context["exact_path"] + ["block"],
                "block": [
                    {"directive": "listen", "args": ["443", "ssl", "default_server"]},
                    {"directive": "ssl_reject_handshake", "args": ["on"]}
                ]
            })

        if not remediations:
            return []

        return [{
            "file": http_block_context["filepath"],
            "remediations": remediations
        }]
