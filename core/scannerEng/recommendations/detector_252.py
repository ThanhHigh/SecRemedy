from typing import Dict, List, Any, Optional
from core.scannerEng.base_recom import BaseRecom


class Detector252(BaseRecom):
    def __init__(self):
        super().__init__()
        self.id = "2.5.2"
        self.title = "Ensure default error and index.html pages do not reference NGINX (Manual)"
        self.description = "Default error pages (e.g., 404, 500) and the default welcome page often contain NGINX branding or signatures. These pages should be removed or replaced with generic or custom-branded pages that do not disclose the underlying server technology."
        self.audit_procedure = "Check if error_page directives are active by running `nginx -T 2>/dev/null | grep -i \"error_page\"`. Trigger an error (e.g., request a non-existent page) and inspect the body to verify the output does not contain \"nginx\"."
        self.impact = "Creating and maintaining custom error pages requires additional administrative effort. Ensure that custom error pages are simple and do not themselves introduce vulnerabilities."
        self.remediation = "Instead of editing the default files, configure NGINX to use custom error pages. Create a directory and place generic HTML files there without NGINX branding, and add the error_page directive to your http or server blocks."
        self.level = "Level 1 - Webserver, Proxy, Loadbalancer"

    def _parse_error_page(self, args: List[str]):
        """
        Phân tích tham số của chỉ thị error_page để tìm ra các mã lỗi (4xx, 5xx) đã được cấu hình.
        Ví dụ: error_page 500 502 503 504 /50x.html;
        """
        if len(args) < 2:
            return set(), set()

        # Phần tử cuối cùng thường là URI hoặc =response (ví dụ =200)
        url = args[-1]
        if url == "=":
            return set(), set()

        c4 = set()
        c5 = set()

        # Duyệt qua các mã lỗi, bỏ qua phần tử cuối cùng (URI đích)
        for arg in args[:-1]:
            if arg.startswith('4') and len(arg) == 3 and arg.isdigit():
                c4.add(arg)
            elif arg.startswith('5') and len(arg) == 3 and arg.isdigit():
                c5.add(arg)
            elif arg == "50x":  # Cú pháp tóm tắt thường dùng trong nginx
                c5.update({"500", "502", "503", "504"})
        return c4, c5

    def _check_block_coverage(self, directives: List[Dict]):
        """
        Đệ quy kiểm tra các chỉ thị trong một khối (ví dụ: khối server) để gom 
        tất cả các mã lỗi (4xx, 5xx) đã được định nghĩa thông qua error_page.
        Có hỗ trợ tìm kiếm sâu vào các khối location con.
        """
        c4 = set()
        c5 = set()
        for d in directives:
            if d.get("directive") == "error_page":
                l4, l5 = self._parse_error_page(d.get("args", []))
                c4.update(l4)
                c5.update(l5)
            # Nếu gặp khối con (như location) nhưng không phải khối server (vì server độc lập với nhau)
            if "block" in d and d.get("directive") != "server":
                # recurse into locations (Đệ quy tìm trong các location)
                r4, r5 = self._check_block_coverage(d.get("block", []))
                c4.update(r4)
                c5.update(r5)
        return c4, c5

    def _is_ignored_server(self, directives: List[Dict]):
        """
        Kiểm tra xem khối server này có nên bị bỏ qua không.
        Các server trống, hoặc chỉ dùng để redirect (sử dụng lệnh 'return') 
        thì thường không cần quan tâm đến lỗi error_page, vì yêu cầu đã bị đẩy đi nơi khác.
        """
        if not directives:
            return True
        for d in directives:
            if d.get("directive") == "return":
                return True
        return False

    def _evaluate_server(self, server_directive: Dict, http_4xx: set, http_5xx: set, context_path: Any) -> List[Dict]:
        """
        Kiểm tra một khối server và trả về các remediations nếu thiếu cấu hình error_page.
        """
        if self._is_ignored_server(server_directive.get("block", [])):
            return []

        srv_4xx, srv_5xx = self._check_block_coverage(server_directive.get("block", []))
        
        combined_4xx = http_4xx.union(srv_4xx)
        combined_5xx = http_5xx.union(srv_5xx)

        has_4xx = len(combined_4xx) > 0
        has_5xx = {"500", "502", "503", "504"}.issubset(combined_5xx)

        remediations = []
        if not has_4xx:
            remediations.append({
                "action": "add",
                "directive": "error_page",
                "args": ["404", "/404.html"],
                "context": context_path
            })
        if not has_5xx:
            remediations.append({
                "action": "add",
                "directive": "error_page",
                "args": ["500", "502", "503", "504", "/50x.html"],
                "context": context_path
            })
        return remediations

    def evaluate(self, directive: Dict, filepath: str, logical_context: List[str], exact_path: List[Any]) -> Optional[Dict]:
        """
        Hàm `evaluate` được sử dụng để kiểm tra ĐỘC LẬP một block cấu hình (thường là `http` hoặc `server`).
        - Trong môi trường CHẠY THỰC TẾ: Hàm này KHÔNG được gọi (vì `scan()` đã bị override để xử lý toàn cục).
        - Trong UNIT TESTS: Hàm này cực kỳ quan trọng! Nó được gọi trực tiếp bởi 44 test cases (Phần 2 & 3
          trong test_detector_252.py) để kiểm tra logic của một block cấu hình bị cô lập mà không cần phải 
          giả lập (mock) toàn bộ cây AST với nhiều file.
        """
        if directive.get("directive") not in ["http", "server"]:
            return None

        http_4xx = set()
        http_5xx = set()
        servers_to_check = []

        if directive.get("directive") == "http":
            for d in directive.get("block", []):
                if d.get("directive") == "error_page":
                    h4, h5 = self._parse_error_page(d.get("args", []))
                    http_4xx.update(h4)
                    http_5xx.update(h5)
                elif d.get("directive") == "server":
                    servers_to_check.append(d)
        elif directive.get("directive") == "server":
            servers_to_check.append(directive)

        remediations = []
        context_val = "server" if directive.get("directive") == "server" else "http"
        for srv in servers_to_check:
            remediations.extend(self._evaluate_server(srv, http_4xx, http_5xx, context_val))

        if remediations:
            return {"file": filepath, "remediations": remediations}
        return None

    def scan(self, parser_output: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Hàm `scan` là entrypoint chính trong môi trường CHẠY THỰC TẾ.
        Khác với các rule thông thường chỉ cần kiểm tra từng node độc lập, rule 2.5.2 yêu cầu
        phải biết được các `error_page` định nghĩa ở cấp `http` (global) nằm rải rác ở nhiều file
        để kế thừa xuống các khối `server`.
        
        Vì vậy, hàm này thực hiện một thuật toán 2-bước (2-pass):
        - Bước 1: Quét toàn bộ các file để gom tất cả `error_page` ở cấp độ `http`.
        - Bước 2: Quét lại toàn bộ các file để vào sâu bên trong từng `server` block và
                  đối chiếu với dữ liệu global đã thu thập ở Bước 1 thông qua `_evaluate_server()`.
                  
        Trong Unit test, hàm này được test ở Phần 4 (15 test cases) để đảm bảo tích hợp toàn diện.
        """
        findings = []
        configs = parser_output.get("config", [])

        # 1. Thu thập phạm vi cấu hình error_page ở cấp HTTP (global)
        http_4xx = set()
        http_5xx = set()

        for config_file in configs:
            for d in config_file.get("parsed", []):
                if d.get("directive") == "http":
                    for sub_d in d.get("block", []):
                        if sub_d.get("directive") == "error_page":
                            h4, h5 = self._parse_error_page(sub_d.get("args", []))
                            http_4xx.update(h4)
                            http_5xx.update(h5)
                elif d.get("directive") == "error_page":
                    h4, h5 = self._parse_error_page(d.get("args", []))
                    http_4xx.update(h4)
                    http_5xx.update(h5)

        # 2. Duyệt qua tất cả các server blocks ở mọi nơi và đánh giá
        file_remediations = {}

        def add_rem(fp, rems):
            if fp not in file_remediations:
                file_remediations[fp] = []
            file_remediations[fp].extend(rems)

        for config_idx, config_file in enumerate(configs):
            filepath = config_file.get("file", "")
            parsed = config_file.get("parsed", [])

            def traverse_for_servers(directives, current_path):
                for i, d in enumerate(directives):
                    if d.get("directive") == "server":
                        server_block_path = current_path + [i, "block"]
                        rems = self._evaluate_server(d, http_4xx, http_5xx, server_block_path)
                        if rems:
                            add_rem(filepath, rems)
                    if "block" in d:
                        traverse_for_servers(d["block"], current_path + [i, "block"])

            traverse_for_servers(parsed, ["config", config_idx, "parsed"])

        for fp, rems in file_remediations.items():
            findings.append({
                "file": fp,
                "remediations": rems
            })

        return findings
