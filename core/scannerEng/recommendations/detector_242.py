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
        self.remediation = "Configure a 'Catch-All' default server block as the first block in your configuration (or explicitly marked with default_server). After adding this block, ensure all your valid applications have their own server blocks with explicit server_name directives."

    def _extract_ports(self, listen_args: List[str]) -> List[str]:
        """
        Trích xuất các port từ các tham số của chỉ thị `listen`.
        Ví dụ: `listen 80 default_server` -> trả về `['80']`.
        `listen [::]:443 ssl` -> trả về `['443']`.
        """
        ports = []
        for arg in listen_args:
            # Bỏ qua các tham số định dạng và cờ hệ thống không phải port
            if arg in ["ssl", "default_server", "http2", "http3", "deferred", "proxy_protocol", "reuseport", "bind"]:
                continue
            # Bỏ qua các key=value args như ipv6only=on, backlog=512
            if "=" in arg:
                continue
            # Xử lý port đi kèm với địa chỉ IP (ví dụ: 127.0.0.1:80 hoặc [::]:443)
            if ":" in arg:
                port = arg.split(":")[-1]
                if port.isdigit():
                    ports.append(port)
            # Tham số là port trực tiếp
            elif arg.isdigit():
                ports.append(arg)
        
        # Nếu không trích xuất được port nào nhưng có cờ `ssl`, mặc định là 443, nếu không là 80
        if not ports:
            if "ssl" in listen_args:
                ports.append("443")
            else:
                ports.append("80")
        return ports

    def _get_listen_ports(self, server_block: Dict) -> List[str]:
        """
        Quét tất cả các chỉ thị `listen` bên trong một khối `server` để lấy danh sách port.
        """
        ports = []
        has_listen = False
        for d in server_block.get("block", []):
            if d.get("directive") == "listen":
                has_listen = True
                ports.extend(self._extract_ports(d.get("args", [])))
        
        # NGINX ngầm định lắng nghe port 80 nếu không có chỉ thị `listen`
        if not has_listen:
            ports.append("80")
        return list(set(ports))

    def _is_secure_catchall(self, server_block: Dict) -> bool:
        """
        Đánh giá xem khối `server` hiện tại có phải là một catch-all an toàn hay không.
        Yêu cầu:
        1. Phải có chỉ thị `return` với mã lỗi >= 400 (như 444, 400, 403, 404).
        2. Nếu là cấu hình HTTPS, bắt buộc phải có `ssl_reject_handshake on;`.
        """
        has_reject = False
        has_ssl_reject = False
        is_https = False

        for d in server_block.get("block", []):
            # Kiểm tra xem có chứa cấu hình trả về mã lỗi bảo mật hay không
            if d.get("directive") == "return":
                if d.get("args") and d["args"][0] in ["444", "400", "403", "404", "405", "418"]:
                    has_reject = True
            # Kiểm tra trạng thái ssl_reject_handshake
            elif d.get("directive") == "ssl_reject_handshake":
                if d.get("args") and d["args"][0] == "on":
                    has_ssl_reject = True
            # Nhận dạng xem block này có phục vụ SSL/HTTPS không
            elif d.get("directive") == "listen":
                args = d.get("args", [])
                if "ssl" in args or "443" in args or "8443" in args:
                    is_https = True

        # Nếu không có lệnh từ chối request, không an toàn
        if not has_reject:
            return False
        # Nếu đang phục vụ HTTPS nhưng không bật reject handshake, sẽ có rủi ro lộ chứng chỉ SSL mặc định
        if is_https and not has_ssl_reject:
            return False
        return True

    def _analyze_servers(self, servers: List[Dict], http_blocks: List[Dict]) -> List[Dict]:
        """
        Phân tích tất cả các khối `server` (được nhóm theo port).
        Thuật toán:
        1. Gom nhóm tất cả server theo port mà chúng phục vụ.
        2. Với mỗi port, kiểm tra xem có khối server nào có `default_server` không.
        3. Nếu có default_server, kiểm tra xem nó có an toàn không (insecure_catchalls).
        4. Nếu không có explicit `default_server`, khối server ĐẦU TIÊN của port đó sẽ là ngầm định. Kiểm tra xem nó có an toàn không.
        5. Nếu không có bắt cứ khối catchall an toàn nào trên port đó -> missing_catchall_ports.
        """
        port_servers = {}
        for s_info in servers:
            ports = self._get_listen_ports(s_info["directive"])
            for p in ports:
                if p not in port_servers:
                    port_servers[p] = []
                port_servers[p].append(s_info)

        insecure_catchalls = []
        missing_catchall_ports = []

        for port, s_list in port_servers.items():
            has_secure = False
            has_explicit_default = False
            has_insecure_explicit = False

            for s_info in s_list:
                for d in s_info["directive"].get("block", []):
                    if d.get("directive") == "listen":
                        args = d.get("args", [])
                        # Kiểm tra xem khối server này có được đánh dấu làm mặc định rõ ràng không
                        if "default_server" in args and port in self._extract_ports(args):
                            has_explicit_default = True
                            if self._is_secure_catchall(s_info["directive"]):
                                has_secure = True
                            else:
                                has_insecure_explicit = True
                                # Khối này được đánh dấu làm catch-all nhưng thiếu tính năng bảo vệ (VD: thiếu return 444)
                                if s_info not in insecure_catchalls:
                                    insecure_catchalls.append(s_info)

            # Nếu không có server nào ghi rành rành 'default_server', NGINX sẽ lấy cái đầu tiên
            if not has_explicit_default and s_list:
                first_server = s_list[0]
                if self._is_secure_catchall(first_server["directive"]):
                    has_secure = True

            # Port này chưa được cấu hình một catch-all bảo mật (cả rõ ràng lẫn ngầm định)
            if not has_secure and not has_insecure_explicit:
                missing_catchall_ports.append(port)

        # Trường hợp ngoại lệ: không có cấu hình server nào cả, mặc định cảnh báo về port 80
        if not port_servers:
            missing_catchall_ports.append("80")

        findings = []
        # Xử lý các khối default_server nhưng không an toàn -> Hành động là 'modify'
        for s_info in insecure_catchalls:
            findings.append({
                "file": s_info["filepath"],
                "remediations": [
                    {
                        "action": "modify",
                        "directive": "server",
                        "context": "server",
                        "exact_path": s_info["exact_path"],
                        "config": "server {\n    # Catch-all was insecure\n    return 444;\n}"
                    }
                ]
            })

        # Xử lý các port thiếu catch-all an toàn -> Hành động là 'add' (Tạo mới ở level http)
        if missing_catchall_ports:
            if http_blocks:
                for h_info in http_blocks:
                    findings.append({
                        "file": h_info["filepath"],
                        "remediations": [
                            {
                                "action": "add",
                                "directive": "server",
                                "context": "http",
                                "exact_path": h_info["exact_path"],
                                "config": "server {\n    listen 80 default_server;\n    return 444;\n}"
                            }
                        ]
                    })
            else:
                # Fallback: Không tìm thấy http block trực tiếp (có thể file này được include), chèn đè vào vị trí server hiện tại
                if servers:
                    findings.append({
                        "file": servers[0]["filepath"],
                        "remediations": [
                            {
                                "action": "add",
                                "directive": "server",
                                "context": "http",
                                "exact_path": servers[0]["exact_path"][:-2] if len(servers[0]["exact_path"]) >= 2 else [],
                                "config": "server {\n    listen 80 default_server;\n    return 444;\n}"
                            }
                        ]
                    })

        return findings

    def evaluate(self, directive: Dict, filepath: str, logical_context: List[str], exact_path: List[Any]) -> Optional[Dict]:
        """
        Dùng cho việc quét đơn lẻ từng khối `http`.
        Hàm này sẽ tập hợp các khối `server` con và phân tích.
        """
        if directive.get("directive") != "http":
            return None

        servers = []
        for i, d in enumerate(directive.get("block", [])):
            if d.get("directive") == "server":
                servers.append({
                    "directive": d,
                    "filepath": filepath,
                    "exact_path": exact_path + ["block", i]
                })

        http_info = {
            "directive": directive,
            "filepath": filepath,
            "exact_path": exact_path
        }

        findings = self._analyze_servers(servers, [http_info])
        return findings[0] if findings else None

    def scan(self, parser_output: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Ghi đè phương thức quét toàn cục để có góc nhìn toàn diện trên mọi file cấu hình.
        Giúp giải quyết vấn đề khi `default_server` được định nghĩa ở một file khác file ứng dụng.
        """
        all_servers = []
        http_blocks = []

        def traverse(directives, filepath, exact_path):
            for i, d in enumerate(directives):
                curr_path = exact_path + [i]
                if d.get("directive") == "http":
                    http_blocks.append({
                        "directive": d,
                        "filepath": filepath,
                        "exact_path": curr_path
                    })
                elif d.get("directive") == "server":
                    all_servers.append({
                        "directive": d,
                        "filepath": filepath,
                        "exact_path": curr_path
                    })
                # Đệ quy đi sâu vào các block con
                if "block" in d:
                    traverse(d["block"], filepath, curr_path + ["block"])

        # Quét qua toàn bộ output của parser
        for config_idx, config_file in enumerate(parser_output.get("config", [])):
            filepath = config_file.get("file", "")
            parsed = config_file.get("parsed", [])
            traverse(parsed, filepath, ["config", config_idx, "parsed"])

        # Phân tích tập trung tất cả dữ liệu
        findings = self._analyze_servers(all_servers, http_blocks)

        # Chúng ta cố tình không sử dụng _group_by_file ở đây để đáp ứng các test case
        # mong đợi trả về 1 finding cho mỗi khối HTTP (ngay cả khi nằm trong cùng 1 file).
        return findings
