from typing import Dict, List, Any, Optional
from core.scannerEng.base_recom import BaseRecom, RecomID


class Detector32(BaseRecom):
    def __init__(self):
        super().__init__(RecomID.CIS_3_2)

    def _scan_block(self, directives: List[Dict[str, Any]], filepath: str, logical_context: List[str], exact_path: List[Any], is_exception_context: bool) -> List[Dict[str, Any]]:
        uncompliances = []
        for idx, directive in enumerate(directives):
            current_exact_path = exact_path + [idx]
            dir_name = directive.get("directive", "")
            args = directive.get("args", [])
            
            current_is_exception = is_exception_context
            if dir_name == "location":
                args_str = "".join(args).lower()
                if "favicon.ico" in args_str or "robots.txt" in args_str or "\\.(css|js|jpg|jpeg|png)$" in "".join(args):
                    current_is_exception = True

            if dir_name == "access_log":
                if not current_is_exception:
                    if len(args) > 0:
                        first_arg = args[0].strip('"\'').lower()
                        if first_arg == "off" or first_arg == "/dev/null":
                            uncompliances.append({
                                "file": filepath,
                                "remediations": [
                                    {
                                        "action": "delete",
                                        "directive": "access_log",
                                        "logical_context": logical_context,
                                        "exact_path": current_exact_path
                                    }
                                ]
                            })

            if "block" in directive:
                new_logical_context = logical_context + [dir_name]
                new_exact_path = current_exact_path + ["block"]
                uncompliances.extend(self._scan_block(
                    directive["block"], filepath, new_logical_context, new_exact_path, current_is_exception
                ))
                
        return uncompliances

    def scan(self, parser_output: Dict[str, Any]) -> List[Dict[str, Any]]:
        uncompliances = []

        # Dùng enumerate để lấy được index của config_file (VD: 0, 1, 2...)
        for config_idx, config_file in enumerate(parser_output.get("config", [])):
            filepath = config_file.get("file", "")

            # Chỉ xử lý các file có đuôi .conf
            if not filepath.endswith(".conf"):
                continue

            parsed_ast = config_file.get("parsed", [])

            # Khởi tạo Exact Path gốc cho file này.
            # VD: ["config", 0, "parsed"]
            base_exact_path = ["config", config_idx, "parsed"]

            uncompliances.extend(self._scan_block(
                parsed_ast, filepath, [], base_exact_path, False
            ))

        # Gộp các uncompliance trùng file thành 1 entry duy nhất,
        # gom tất cả remediations lại. Khớp với JSON Contract (scan_result.json).
        return self._group_by_file(uncompliances)
