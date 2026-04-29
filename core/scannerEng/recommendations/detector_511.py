from typing import Dict, List, Any, Optional
from core.scannerEng.base_recom import BaseRecom, RecomID


class Detector511(BaseRecom):
    def __init__(self, strict_private: bool = False):
        super().__init__(RecomID.CIS_5_1_1)
        self.strict_private = strict_private

    def _check_block(self, directives_list: List[Dict[str, Any]], logical_context: List[str], exact_path_to_list: List[Any], filepath: str) -> List[Dict[str, Any]]:
        uncompliances = []
        remediations = []
        
        allow_indices = []
        deny_all_indices = []
        
        for idx, directive in enumerate(directives_list):
            d_name = directive.get("directive")
            d_args = directive.get("args", [])
            
            if d_name == "allow":
                if not d_args:
                    remediations.append({
                        "action": "delete",
                        "directive": "allow",
                        "logical_context": list(logical_context),
                        "exact_path": exact_path_to_list + [idx]
                    })
                elif "all" in d_args:
                    remediations.append({
                        "action": "delete",
                        "directive": "allow",
                        "logical_context": list(logical_context),
                        "exact_path": exact_path_to_list + [idx]
                    })
                else:
                    allow_indices.append(idx)
                    
            elif d_name == "deny":
                if "all" in d_args:
                    deny_all_indices.append(idx)
                    
            if "block" in directive:
                new_logical = list(logical_context) + [d_name]
                new_exact = exact_path_to_list + [idx, "block"]
                
                if self.strict_private and d_name == "server":
                    has_acl = any(d.get("directive") in ("allow", "deny") for d in directive["block"])
                    if not has_acl:
                        uncompliances.append({
                            "file": filepath,
                            "remediations": [{
                                "action": "add",
                                "directive": "deny",
                                "args": ["all"],
                                "logical_context": new_logical,
                                "exact_path": new_exact
                            }]
                        })
                        
                uncompliances.extend(self._check_block(directive["block"], new_logical, new_exact, filepath))
                
        if allow_indices:
            has_valid_deny_all = False
            for d_idx in deny_all_indices:
                if d_idx > max(allow_indices):
                    has_valid_deny_all = True
                    break
            
            if not has_valid_deny_all:
                for d_idx in deny_all_indices:
                    remediations.append({
                        "action": "delete",
                        "directive": "deny",
                        "logical_context": list(logical_context),
                        "exact_path": exact_path_to_list + [d_idx]
                    })
                remediations.append({
                    "action": "add",
                    "directive": "deny",
                    "args": ["all"],
                    "logical_context": list(logical_context),
                    "exact_path": list(exact_path_to_list)
                })
                
        if remediations:
            uncompliances.append({
                "file": filepath,
                "remediations": remediations
            })
            
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

            # Logic chính của detector 5.1.1
            file_uncompliances = self._check_block(parsed_ast, [], base_exact_path, filepath)
            uncompliances.extend(file_uncompliances)

        # Gộp các uncompliance trùng file thành 1 entry duy nhất,
        # gom tất cả remediations lại. Khớp với JSON Contract (scan_result.json).
        return self._group_by_file(uncompliances)
