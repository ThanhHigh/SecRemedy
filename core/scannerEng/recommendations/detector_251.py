from typing import Dict, List, Any
from core.scannerEng.base_recom import BaseRecom, RecomID


class Detector251(BaseRecom):
    def __init__(self):
        super().__init__(RecomID.CIS_2_5_1)

    def scan(self, parser_output: Dict[str, Any]) -> List[Dict[str, Any]]:
        uncompliances = []

        all_server_tokens = []
        first_http_block = None
        first_file_parsed_path = None

        # Dùng enumerate để lấy được index của config_file (VD: 0, 1, 2...)
        for config_idx, config_file in enumerate(parser_output.get("config", [])):
            filepath = config_file.get("file", "")

            # Chỉ xử lý các file có đuôi .conf
            if not filepath.endswith(".conf"):
                continue

            parsed_ast = config_file.get("parsed", [])

            # Khởi tạo Exact Path gốc cho file này.
            base_exact_path = ["config", config_idx, "parsed"]

            if first_file_parsed_path is None:
                first_file_parsed_path = {
                    "filepath": filepath,
                    "exact_path": base_exact_path,
                    "logical_context": []
                }

            # Tìm tất cả chỉ thị server_tokens
            tokens = self.traverse_directive(
                target_directive="server_tokens",
                directives=parsed_ast,
                filepath=filepath,
                logical_context=[],
                exact_path=base_exact_path
            )
            all_server_tokens.extend(tokens)

            # Tìm khối http
            https = self.traverse_directive(
                target_directive="http",
                directives=parsed_ast,
                filepath=filepath,
                logical_context=[],
                exact_path=base_exact_path
            )
            if https and first_http_block is None:
                first_http_block = https[0]

        has_valid_global_or_http = False

        for st in all_server_tokens:
            dir_node = st["directive"]
            args = dir_node.get("args", [])
            val = " ".join(args).strip(" '\"").lower()

            is_global_or_http = len(st["logical_context"]) == 0 or st["logical_context"] == ["http"]

            if val == "off":
                if is_global_or_http:
                    has_valid_global_or_http = True
            else:
                # Nếu không phải off -> replace thành off
                uncompliances.append({
                    "file": st["filepath"],
                    "remediations": [{
                        "action": "replace",
                        "directive": "server_tokens",
                        "args": ["off"],
                        "logical_context": st["logical_context"],
                        "exact_path": st["exact_path"]
                    }]
                })
                # Mặc dù sai nhưng sau khi replace nó sẽ thành off ở cấp global/http
                if is_global_or_http:
                    has_valid_global_or_http = True

        # Nếu không có server_tokens ở cấp độ global hoặc http, ta phải add thêm
        if not has_valid_global_or_http:
            if first_http_block:
                exact_path = first_http_block["exact_path"] + ["block"]
                logical_context = ["http"]
                filepath = first_http_block["filepath"]
            elif first_file_parsed_path:
                exact_path = first_file_parsed_path["exact_path"]
                logical_context = []
                filepath = first_file_parsed_path["filepath"]
            else:
                return self._group_by_file(uncompliances)

            uncompliances.append({
                "file": filepath,
                "remediations": [{
                    "action": "add",
                    "directive": "server_tokens",
                    "args": ["off"],
                    "logical_context": logical_context,
                    "exact_path": exact_path
                }]
            })

        # Gộp các uncompliance trùng file thành 1 entry duy nhất
        return self._group_by_file(uncompliances)