from typing import Dict, List, Any, Optional
from core.scannerEng.base_recom import BaseRecom


class Detector242(BaseRecom):
    def __init__(self):
        super().__init__()
        self.id = "2.4.2"
        self.title = "Ensure requests for unknown host names are rejected"
        self.description = (
            "NGINX should have a catch-all default server block that rejects "
            "requests for unknown hostnames, preventing Host Header attacks "
            "and unintended application exposure."
        )
        self.audit_procedure = (
            "Check for a default server block using "
            "`nginx -T 2>/dev/null | grep -Ei \"listen.*default_server|ssl_reject_handshake\"`. "
            "Verify it contains `return 444;` or a 4xx error code. "
            "For HTTPS/TLS, verify `ssl_reject_handshake on;` is used."
        )
        self.impact = (
            "Clients accessing the server directly via IP address or an "
            "unconfigured CNAME will be rejected. All valid domains must be "
            "explicitly defined in their own server blocks."
        )
        self.remediation = (
            "Configure a catch-all default server block as the first block in "
            "your http configuration (or explicitly marked with default_server). "
            "It should return 444 for HTTP and use ssl_reject_handshake on for HTTPS."
        )

    # ------------------------------------------------------------------
    # Helper: kiểm tra một server block có phải catch-all hợp lệ không
    # ------------------------------------------------------------------
    def _is_valid_catchall(self, server_block: List[Dict]) -> Dict[str, bool]:
        """
        Phân tích một server block (danh sách directives bên trong)
        và trả về dict mô tả trạng thái tuân thủ:
          - has_default_server:      Có listen ... default_server không?
          - has_wildcard_name:       Có server_name _ không?
          - has_reject_return:       Có return 444 hoặc 4xx không?
          - has_ssl_reject:          Có ssl_reject_handshake on không?
        """
        result = {
            "has_default_server": False,
            "has_wildcard_name": False,
            "has_reject_return": False,
            "has_ssl_reject": False,
        }

        for d in server_block:
            directive = d.get("directive", "")
            args = d.get("args", [])

            # 1. Kiểm tra listen ... default_server
            if directive == "listen" and "default_server" in args:
                result["has_default_server"] = True

            # 2. Kiểm tra server_name _
            if directive == "server_name" and "_" in args:
                result["has_wildcard_name"] = True

            # 3. Kiểm tra return 444 hoặc 4xx
            if directive == "return" and args:
                try:
                    status_code = int(args[0])
                    if 400 <= status_code <= 499 or status_code == 444:
                        result["has_reject_return"] = True
                except (ValueError, IndexError):
                    pass

            # 4. Kiểm tra ssl_reject_handshake on
            if directive == "ssl_reject_handshake" and args and args[0] == "on":
                result["has_ssl_reject"] = True

        return result

    # ------------------------------------------------------------------
    # Override evaluate() — Ghi đè phương thức đánh giá từ BaseRecom
    # ------------------------------------------------------------------
    def evaluate(
        self,
        directive: Dict,
        filepath: str,
        logical_context: List[str],
        exact_path: List[Any],
    ) -> Optional[Dict]:
        """
        Đánh giá luật 2.4.2 tại cấp http block.

        Chiến lược:
        - Khi gặp directive "http", duyệt tất cả server block con.
        - Tìm server block nào có listen ... default_server.
        - Nếu KHÔNG tìm thấy => uncompliance (cần thêm block mới).
        - Nếu tìm thấy nhưng thiếu return 444/4xx hoặc ssl_reject_handshake
          => uncompliance (cần sửa block hiện tại).
        """
        # Chỉ xử lý khi gặp block 'http'
        if directive.get("directive") != "http":
            return None

        http_block = directive.get("block", [])

        # Thu thập tất cả server block có default_server
        default_servers = []
        for idx, d in enumerate(http_block):
            if d.get("directive") == "server" and "block" in d:
                server_block = d["block"]
                # Kiểm tra xem server này có listen ... default_server
                has_ds = any(
                    sub.get("directive") == "listen"
                    and "default_server" in sub.get("args", [])
                    for sub in server_block
                )
                if has_ds:
                    default_servers.append((idx, server_block))

        # ============================================================
        # CASE 1: Không có server block nào có default_server
        #         => Cần thêm một catch-all block mới vào http block
        # ============================================================
        if not default_servers:
            return {
                "file": filepath,
                "remediations": [
                    {
                        "action": "add_block",
                        "context": exact_path + ["block"],
                        "position": 0,
                        "directive": "server",
                        "block": [
                            {
                                "directive": "listen",
                                "args": ["80", "default_server"],
                            },
                            {
                                "directive": "listen",
                                "args": ["443", "ssl", "default_server"],
                            },
                            {
                                "directive": "server_name",
                                "args": ["_"],
                            },
                            {
                                "directive": "ssl_reject_handshake",
                                "args": ["on"],
                            },
                            {
                                "directive": "return",
                                "args": ["444"],
                            },
                        ],
                        "note": (
                            "Add a catch-all default_server block to the http context. "
                            "You must also provide valid ssl_certificate and "
                            "ssl_certificate_key paths for the TLS listener."
                        ),
                    }
                ],
            }

        # ============================================================
        # CASE 2: Có default_server, kiểm tra cấu hình bên trong
        # ============================================================
        remediations = []

        for ds_idx, server_block in default_servers:
            check = self._is_valid_catchall(server_block)

            # Đường dẫn chính xác đến server block này trong AST
            server_exact_path = exact_path + ["block", ds_idx, "block"]

            # 2a. Thiếu server_name _
            if not check["has_wildcard_name"]:
                remediations.append({
                    "action": "add",
                    "context": server_exact_path,
                    "directive": "server_name",
                    "args": ["_"],
                })

            # 2b. Thiếu return 444 / 4xx (block không từ chối request)
            if not check["has_reject_return"]:
                remediations.append({
                    "action": "add",
                    "context": server_exact_path,
                    "directive": "return",
                    "args": ["444"],
                })

            # 2c. Thiếu ssl_reject_handshake on (cho HTTPS listener)
            if not check["has_ssl_reject"]:
                # Chỉ thêm nếu có SSL listener (listen 443 ssl default_server)
                has_ssl_listener = any(
                    sub.get("directive") == "listen"
                    and "ssl" in sub.get("args", [])
                    for sub in server_block
                )
                if has_ssl_listener:
                    remediations.append({
                        "action": "add",
                        "context": server_exact_path,
                        "directive": "ssl_reject_handshake",
                        "args": ["on"],
                    })

        if remediations:
            return {
                "file": filepath,
                "remediations": remediations,
            }

        # Tất cả đều tuân thủ
        return None
