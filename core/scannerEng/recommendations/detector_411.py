from typing import Dict, List, Any, Optional
from core.scannerEng.base_recom import BaseRecom, RecomID


class Detector411(BaseRecom):
    def __init__(self):
        super().__init__(RecomID.CIS_4_1_1)

    def _should_skip_block(self, node: Dict[str, Any]) -> bool:
        if not isinstance(node, dict):
            return False

        dir_name = node.get("directive")
        # Bỏ qua upstream blocks: CIS 4.1.1 chỉ áp dụng cho Virtual Host (Client -> Nginx)
        if dir_name == "upstream":
            return True

        if dir_name != "server":
            return False

        block = node.get("block", [])
        has_return_4xx = False
        has_catch_all_server_name = False
        has_default_server = False

        for child in block:
            if not isinstance(child, dict):
                continue
            dir_name = child.get("directive")
            args = child.get("args", [])

            if dir_name == "return" and len(args) == 1 and args[0] in ["444", "403"]:
                has_return_4xx = True
            elif dir_name == "server_name" and len(args) == 1 and args[0] == "_":
                has_catch_all_server_name = True
            elif dir_name == "listen" and len(args) == 2 and args[1] == "default_server":
                has_default_server = True

        return has_return_4xx or has_catch_all_server_name or has_default_server

    def scan(self, parser_output: Dict[str, Any]) -> List[Dict[str, Any]]:
        uncompliances = []

        for config_idx, config_file in enumerate(parser_output.get("config", [])):
            filepath = config_file.get("file", "")
            if not filepath.endswith(".conf"):
                continue

            parsed_ast = config_file.get("parsed", [])
            base_exact_path = ["config", config_idx, "parsed"]

            self._check_node(parsed_ast, base_exact_path,
                             [], uncompliances, filepath)

        return self._group_by_file(uncompliances)

    def _check_node(self, node: List[Dict[str, Any]], exact_path: List[Any], logical_context: List[str], uncompliances: List[Any], filepath: str):
        for i, directive in enumerate(node):
            if self._should_skip_block(directive):
                continue

            dir_name = directive.get("directive")
            current_path = exact_path + [i]

            if dir_name == "server":
                self._check_server(
                    directive, current_path, logical_context + ["server"], uncompliances, filepath)

            if "block" in directive:
                self._check_node(directive["block"], current_path + ["block"],
                                 logical_context + [dir_name], uncompliances, filepath)

    def _check_server(self, server_node: Dict[str, Any], exact_path: List[Any], logical_context: List[str], uncompliances: List[Any], filepath: str):
        block = server_node.get("block", [])

        listens = [(i, d) for i, d in enumerate(block) if d.get("directive") == "listen"]

        http_listens = []
        https_listens = []
        
        for i, l in listens:
            args = l.get("args", [])
            if "ssl" not in args:
                http_listens.append((i, l))
            else:
                https_listens.append((i, l))

        has_http = False
        if not listens:
            has_http = True
        else:
            has_http = len(http_listens) > 0

        if not has_http:
            return

        returns = [(i, d) for i, d in enumerate(block)
                   if d.get("directive") == "return"]

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

        # Check return directives inside location blocks
        valid_return_in_location = False
        for d in block:
            if d.get("directive") == "location" and "block" in d:
                for child in d["block"]:
                    if child.get("directive") == "return":
                        if self._is_valid_return(child):
                            valid_return_in_location = True
                            break
            if valid_return_in_location:
                break

        if valid_return_in_location:
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

        is_mixed = len(http_listens) > 0 and len(https_listens) > 0

        if is_mixed:
            https_block = []
            http_listen_indices = {i for i, d in http_listens}
            for i, d in enumerate(block):
                if i not in http_listen_indices:
                    https_block.append(d)

            http_block = []
            for _, d in http_listens:
                http_block.append(d)
            server_names = [d for d in block if d.get("directive") == "server_name"]
            for d in server_names:
                http_block.append(d)
            http_block.append({
                "directive": "return",
                "args": ["301", "https://$host$request_uri"]
            })

            uncompliances.append({
                "file": filepath,
                "remediations": [
                    {
                        "action": "delete",
                        "directive": "server",
                        "exact_path": exact_path,
                        "logical_context": logical_context
                    },
                    {
                        "action": "add",
                        "directive": "server",
                        "args": [],
                        "block": https_block,
                        "exact_path": exact_path[:-1],
                        "logical_context": logical_context[:-1]
                    },
                    {
                        "action": "add",
                        "directive": "server",
                        "args": [],
                        "block": http_block,
                        "exact_path": exact_path[:-1],
                        "logical_context": logical_context[:-1]
                    }
                ]
            })
            return

        if invalid_return_idx != -1:
            uncompliances.append({
                "file": filepath,
                "remediations": [{
                    "action": "replace",
                    "directive": "return",
                    "line": block[invalid_return_idx].get("line"),
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
                    "line": server_node.get("line"),
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
