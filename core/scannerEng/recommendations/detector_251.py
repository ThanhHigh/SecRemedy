from typing import Dict, List, Any, Optional
from core.scannerEng.base_recom import BaseRecom

class Detector251(BaseRecom):
    def __init__(self):
        super().__init__()
        self.id = "2.5.1"
        self.title = "Ensure server_tokens directive is set to `off`"
        self.description = "The server_tokens directive is responsible for displaying the NGINX version number and operating system version on error pages and in the Server HTTP response header field. This information should not be displayed."
        self.audit_procedure = "In the NGINX configuration file `nginx.conf`, verify the server_tokens directive is set to off. Check the response headers with `curl -I 127.0.0.1 | grep -i server`."
        self.impact = "None. Disabling server tokens does not affect functionality, as it merely removes the version string from error pages and headers."
        self.remediation = "Disable version disclosure globally by adding the directive `server_tokens off;` to the http block in `/etc/nginx/nginx.conf`."
        self.level = "Level 1"
        self.profile = "Level 1"

    def scan(self, parser_output: Dict[str, Any]) -> List[Dict[str, Any]]:
        # Thay vì chỉ dùng evaluate() trên từng node, ta ghi đè scan() để có thể
        # quản lý trạng thái kế thừa (inheritance state) của server_tokens từ block cha xuống block con.
        # NGINX mặc định server_tokens là "on" nếu không được khai báo.
        findings = []
        configs = parser_output.get("config", [])
        
        # Nếu cấu hình trống hoàn toàn, mặc định NGINX bật server_tokens, đây là vi phạm.
        # Ta yêu cầu thêm (add) server_tokens off vào file cấu hình chính.
        if not configs:
            return [{"file": "/etc/nginx/nginx.conf", "remediations": [{"action": "add", "directive": "server_tokens", "context": []}]}]

        # Biến cờ theo dõi xem có bất kỳ cấu hình "server_tokens off;" nào hợp lệ trong toàn bộ hệ thống không
        has_any_secure_token = False
        
        # Lưu lại đường dẫn đến khối http (nếu có) để thêm directive vào đó nếu thiếu hoàn toàn
        http_block_path = None
        http_block_filepath = None
        file_remediations = {}

        def add_rem(filepath, rem):
            # Hàm helper để gom nhóm các hành động khắc phục (remediations) theo từng file
            if filepath not in file_remediations:
                file_remediations[filepath] = []
            file_remediations[filepath].append(rem)

        def traverse(directives, filepath, exact_path, current_state="on"):
            # Hàm duyệt cây AST đệ quy, nhận thêm current_state để biết block cha đang bật hay tắt server_tokens
            nonlocal has_any_secure_token, http_block_path, http_block_filepath
            
            local_token_dir = None
            local_token_path = None
            local_token_val = None
            
            # Bước 1: Tìm xem trong block hiện tại có khai báo server_tokens không
            for i, d in enumerate(directives):
                if d.get("directive") == "server_tokens":
                    local_token_dir = d
                    local_token_path = exact_path + [i]
                    args = d.get("args", [])
                    local_token_val = args[0] if args else ""
            
            # Bước 2: Xác định trạng thái của block hiện tại
            block_state = current_state
            if local_token_dir is not None:
                # Nếu block hiện tại có khai báo, trạng thái của block này sẽ bị ghi đè bởi khai báo đó
                block_state = local_token_val
                
                # Nếu giá trị không phải là "off" (VD: "on", "build", hoặc rỗng), đây là cấu hình sai.
                # Báo lỗi và yêu cầu thay thế (replace) giá trị này thành "off"
                if local_token_val != "off":
                    add_rem(filepath, {
                        "action": "replace",
                        "directive": "server_tokens",
                        "context": local_token_path
                    })
                else:
                    # Ghi nhận đã có ít nhất một cấu hình an toàn trong hệ thống
                    has_any_secure_token = True
            
            # Bước 3: Tiếp tục duyệt sâu vào các block con (http, server, location)
            for i, d in enumerate(directives):
                if d.get("directive") == "http":
                    # Lưu lại vị trí của block http để ưu tiên chèn cấu hình vào đây nếu cần "add"
                    http_block_path = exact_path + [i]
                    http_block_filepath = filepath
                
                if "block" in d:
                    # Truyền trạng thái hiện tại (block_state) xuống cho các block con kế thừa
                    traverse(d["block"], filepath, exact_path + [i, "block"], block_state)

        # Khởi chạy duyệt từ cấp cao nhất của từng file với trạng thái mặc định của NGINX là "on"
        for config_idx, config_file in enumerate(configs):
            filepath = config_file.get("file", "")
            parsed = config_file.get("parsed", [])
            traverse(parsed, filepath, ["config", config_idx, "parsed"], current_state="on")
            
        # Nếu toàn bộ hệ thống không có bất kỳ cấu hình nào sai (file_remediations rỗng)
        # NHƯNG đồng thời cũng KHÔNG có cấu hình "server_tokens off" nào (tức là thiếu cấu hình)
        # thì NGINX sẽ dùng mặc định là "on" (vi phạm).
        if not file_remediations and not has_any_secure_token:
            if http_block_path is not None:
                # Nếu có block http, ưu tiên thêm (add) vào bên trong block http
                add_rem(http_block_filepath, {
                    "action": "add",
                    "directive": "server_tokens",
                    "context": http_block_path + ["block"]
                })
            else:
                # Nếu không có block http, thêm (add) vào file config đầu tiên (thường là nginx.conf gốc)
                target_file = configs[0].get("file", "/etc/nginx/nginx.conf") if configs else "/etc/nginx/nginx.conf"
                add_rem(target_file, {
                    "action": "add",
                    "directive": "server_tokens",
                    "context": ["config", 0, "parsed"]
                })

        # Đóng gói kết quả đầu ra theo chuẩn JSON Contract mong đợi
        for fp, rems in file_remediations.items():
            findings.append({
                "file": fp,
                "remediations": rems
            })
            
        return findings

    def evaluate(self, directive: Dict, filepath: str, logical_context: List[str], exact_path: List[Any]) -> Optional[Dict]:
        # Do ta đã ghi đè toàn bộ quy trình quét ở hàm scan() để xử lý kế thừa block,
        # hàm evaluate() gốc của BaseRecom không cần thiết thực hiện logic gì nữa.
        return None
