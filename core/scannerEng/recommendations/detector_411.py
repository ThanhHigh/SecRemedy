from typing import Dict, List, Any, Optional
from core.scannerEng.base_recom import BaseRecom, RecomID


class Detector411(BaseRecom):
    def __init__(self):
        super().__init__(RecomID.CIS_4_1_1)

    def scan(self, parser_output: Dict[str, Any]) -> List[Dict[str, Any]]:
        uncompliances = []

        for config_idx, config_file in enumerate(parser_output.get("config", [])):
            filepath = config_file.get("file", "")
            if not filepath.endswith(".conf"):
                continue

            parsed_ast = config_file.get("parsed", [])
            base_exact_path = ["config", config_idx, "parsed"]

            self._check_node(parsed_ast, base_exact_path, [], uncompliances, filepath)

        return self._group_by_file(uncompliances)

    def _check_node(self, node: List[Dict[str, Any]], exact_path: List[Any], logical_context: List[str], uncompliances: List[Any], filepath: str):
        for i, directive in enumerate(node):
            dir_name = directive.get("directive")
            current_path = exact_path + [i]
            
            if dir_name == "server":
                self._check_server(directive, current_path, logical_context + ["server"], uncompliances, filepath)
            
            if "block" in directive:
                self._check_node(directive["block"], current_path + ["block"], logical_context + [dir_name], uncompliances, filepath)

    def _check_server(self, server_node: Dict[str, Any], exact_path: List[Any], logical_context: List[str], uncompliances: List[Any], filepath: str):
        block = server_node.get("block", [])
        
        listens = [d for d in block if d.get("directive") == "listen"]
        
        has_http = False
        if not listens:
            has_http = True
        else:
            for l in listens:
                args = l.get("args", [])
                if "ssl" not in args:
                    has_http = True
                    break
                    
        if not has_http:
            return
            
        returns = [ (i, d) for i, d in enumerate(block) if d.get("directive") == "return" ]
        
        valid_return_in_if = False
        for d in block:
            if d.get("directive") == "if" and "block" in d:
                for child in d["block"]:
                    if child.get("directive") == "return":
                        if self._is_valid_return(child):
                            valid_return_in_if = True
                            break
                            
        if valid_return_in_if:
            return
            
        has_valid_return = False
        invalid_return_idx = -1
        
        for i, ret in returns:
            if self._is_valid_return(ret):
                has_valid_return = True
                break
            else:
                if invalid_return_idx == -1:
                    invalid_return_idx = i
                
        if has_valid_return:
            return
            
        if invalid_return_idx != -1:
            uncompliances.append({
                "file": filepath,
                "remediations": [{
                    "action": "replace",
                    "directive": "return",
                    "args": ["301", "https://$host$request_uri"],
                    "logical_context": logical_context,
                    "exact_path": exact_path + ["block", invalid_return_idx]
                }]
            })
        else:
            uncompliances.append({
                "file": filepath,
                "remediations": [{
                    "action": "add",
                    "directive": "return",
                    "args": ["301", "https://$host$request_uri"],
                    "logical_context": logical_context,
                    "exact_path": exact_path + ["block"]
                }]
            })

    def _is_valid_return(self, ret_node: Dict[str, Any]) -> bool:
        args = ret_node.get("args", [])
        if len(args) >= 2:
            code = args[0]
            url = args[1]
            if code in ["301", "302", "308"]:
                url_clean = url.strip('"').strip("'")
                if url_clean.startswith("https://") or url_clean.startswith("$"):
                    # allow custom variables like https://$custom_host
                    return True
        return False
