from typing import Dict, List, Any, Optional
from core.scannerEng.base_recom import BaseRecom
from core.recom_registry import RecomID


class Detector242(BaseRecom):
    def __init__(self):
        super().__init__(RecomID.CIS_2_4_2)

    def scan(self, parser_output: Dict[str, Any]) -> List[Dict[str, Any]]:
        default_servers = []

        # Lặp qua từng file cấu hình được phân tích
        for config_idx, config_file in enumerate(parser_output.get("config", [])):
            filepath = config_file.get("file", "")
            parsed_ast = config_file.get("parsed", [])
            if not parsed_ast:
                continue
            base_exact_path = ["config", config_idx, "parsed"]

            # Tìm tất cả các khối server trong file hiện tại
            server_blocks = self.traverse_directive(
                target_directive="server",
                directives=parsed_ast,
                filepath=filepath,
                logical_context=[],
                exact_path=base_exact_path
            )
            
            for s_block in server_blocks:
                s_dir = s_block["directive"]
                
                # Tìm các chỉ thị listen bên trong khối server để kiểm tra default_server
                listen_dirs = self.traverse_directive(
                    target_directive="listen",
                    directives=s_dir.get("block", []),
                    filepath=filepath,
                    logical_context=s_block["logical_context"] + ["server"],
                    exact_path=s_block["exact_path"] + ["block"]
                )
                
                is_default = False
                for l_match in listen_dirs:
                    # Nếu có tham số default_server, đánh dấu khối server này là catch-all
                    if "default_server" in l_match["directive"].get("args", []):
                        is_default = True
                        break
                        
                if is_default:
                    default_servers.append(s_block)

        uncompliances = []

        # Nếu không tìm thấy bất kỳ server dự phòng nào, đánh dấu vi phạm
        if not default_servers:
            first_file = parser_output.get("config", [{}])[0].get("file", "") if parser_output.get("config") else ""
            uncompliances.append({
                "file": first_file,
                "remediations": [{
                    "details": "Không tìm thấy cấu hình default_server dự phòng."
                }]
            })
            return self._group_by_file(uncompliances)

        # Kiểm tra tính an toàn của các default_server tìm được
        for s_block in default_servers:
            filepath = s_block["filepath"]
            s_dir = s_block["directive"]
            
            has_reject = False
            
            # Kiểm tra xem có bật chế độ từ chối bắt tay SSL không
            ssl_rejects = self.traverse_directive(
                target_directive="ssl_reject_handshake",
                directives=s_dir.get("block", []),
                filepath=filepath,
                logical_context=s_block["logical_context"] + ["server"],
                exact_path=s_block["exact_path"] + ["block"]
            )
            for sr in ssl_rejects:
                # Đảm bảo lệnh ssl_reject_handshake nằm ở cấp server chứ không phải location
                if sr["directive"].get("args", []) == ["on"] and "location" not in sr["logical_context"]:
                    has_reject = True
                    break
                    
            # Kiểm tra xem có cấu hình trả về mã lỗi không
            return_dirs = self.traverse_directive(
                target_directive="return",
                directives=s_dir.get("block", []),
                filepath=filepath,
                logical_context=s_block["logical_context"] + ["server"],
                exact_path=s_block["exact_path"] + ["block"]
            )
            for ret in return_dirs:
                args = ret["directive"].get("args", [])
                # Đảm bảo lệnh return nằm ở cấp server, không nằm trong location
                if args and "location" not in ret["logical_context"]:
                    code = args[0]
                    # Chấp nhận mã 444 (đóng kết nối) hoặc các mã lỗi 4xx
                    if code == "444" or (code.isdigit() and 400 <= int(code) < 500):
                        has_reject = True
                        break
                        
            # Nếu khối default_server không có cấu hình từ chối hợp lệ, đánh dấu vi phạm
            if not has_reject:
                uncompliances.append({
                    "file": filepath,
                    "remediations": [{
                        "details": "Khối default_server không có cấu hình từ chối an toàn (chưa cấu hình return 4xx/444 hoặc ssl_reject_handshake).",
                        "exact_path": s_block["exact_path"]
                    }]
                })

        # Gộp các lỗi theo file trước khi trả về
        return self._group_by_file(uncompliances)
