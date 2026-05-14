from typing import Dict, List, Any, Optional
from core.scannerEng.base_recom import BaseRecom, RecomID

class Detector254(BaseRecom):
    def __init__(self):
        super().__init__(RecomID.CIS_2_5_4)

    def _should_skip_block(self, node: Dict[str, Any]) -> bool:
        if not isinstance(node, dict):
            return False
        if node.get("directive") != "server":
            return False

        block = node.get("block", [])
        has_https_redirect = False
        has_return_444 = False

        for child in block:
            if not isinstance(child, dict):
                continue
            dir_name = child.get("directive")
            args = child.get("args", [])

            if dir_name == "return":
                if len(args) >= 2 and args[0] in ("301", "302", "307", "308") and args[1].startswith("https://"):
                    has_https_redirect = True
                elif len(args) == 1 and args[0].startswith("https://"):
                    has_https_redirect = True
                elif len(args) == 1 and args[0] == "444":
                    has_return_444 = True

        return has_https_redirect or has_return_444

    def scan(self, parser_output: Dict[str, Any]) -> List[Dict[str, Any]]:
        uncompliances = []

        for config_idx, config_file in enumerate(parser_output.get("config", [])):
            filepath = config_file.get("file", "")

            if not filepath.endswith(".conf"):
                continue

            parsed_ast = config_file.get("parsed", [])
            base_exact_path = ["config", config_idx, "parsed"]

            self._traverse(
                parsed_ast,
                filepath,
                base_exact_path,
                [],
                set(),
                set(),
                set(),
                uncompliances
            )

        return self._group_by_file(uncompliances)

    def _traverse(
        self, 
        ast_list: List[Any], 
        filepath: str, 
        exact_path: List[Any], 
        logical_context: List[str], 
        proxy_hidden: set, 
        fastcgi_hidden: set, 
        uwsgi_hidden: set,
        uncompliances: List[Dict[str, Any]]
    ):
        current_proxy_hidden = set(proxy_hidden)
        current_fastcgi_hidden = set(fastcgi_hidden)
        current_uwsgi_hidden = set(uwsgi_hidden)
        
        has_proxy_hide = False
        has_fastcgi_hide = False
        has_uwsgi_hide = False
        for node in ast_list:
            if isinstance(node, dict):
                d_name = node.get("directive")
                if d_name == "proxy_hide_header":
                    has_proxy_hide = True
                elif d_name == "fastcgi_hide_header":
                    has_fastcgi_hide = True
                elif d_name == "uwsgi_hide_header":
                    has_uwsgi_hide = True

        if has_proxy_hide:
            current_proxy_hidden = set()
            for node in ast_list:
                if isinstance(node, dict) and node.get("directive") == "proxy_hide_header":
                    args = node.get("args", [])
                    if args and not args[0].startswith("$"):
                        current_proxy_hidden.add(args[0].lower())

        if has_fastcgi_hide:
            current_fastcgi_hidden = set()
            for node in ast_list:
                if isinstance(node, dict) and node.get("directive") == "fastcgi_hide_header":
                    args = node.get("args", [])
                    if args and not args[0].startswith("$"):
                        current_fastcgi_hidden.add(args[0].lower())

        if has_uwsgi_hide:
            current_uwsgi_hidden = set()
            for node in ast_list:
                if isinstance(node, dict) and node.get("directive") == "uwsgi_hide_header":
                    args = node.get("args", [])
                    if args and not args[0].startswith("$"):
                        current_uwsgi_hidden.add(args[0].lower())

        for idx, node in enumerate(ast_list):
            if not isinstance(node, dict):
                continue
            
            if self._should_skip_block(node):
                continue

            dir_name = node.get("directive")
            
            if dir_name == "proxy_pass":
                if "x-powered-by" not in current_proxy_hidden:
                    uncompliances.append({
                        "file": filepath,
                        "remediations": [{
                            "action": "add",
                            "directive": "proxy_hide_header",
                            "args": ["X-Powered-By"],
                            "logical_context": logical_context.copy(),
                            "exact_path": exact_path.copy()
                        }]
                    })
                if "server" not in current_proxy_hidden:
                    uncompliances.append({
                        "file": filepath,
                        "remediations": [{
                            "action": "add",
                            "directive": "proxy_hide_header",
                            "args": ["Server"],
                            "logical_context": logical_context.copy(),
                            "exact_path": exact_path.copy()
                        }]
                    })
            elif dir_name == "fastcgi_pass":
                if "x-powered-by" not in current_fastcgi_hidden:
                    uncompliances.append({
                        "file": filepath,
                        "remediations": [{
                            "action": "add",
                            "directive": "fastcgi_hide_header",
                            "args": ["X-Powered-By"],
                            "logical_context": logical_context.copy(),
                            "exact_path": exact_path.copy()
                        }]
                    })
            elif dir_name == "uwsgi_pass":
                if "x-powered-by" not in current_uwsgi_hidden:
                    uncompliances.append({
                        "file": filepath,
                        "remediations": [{
                            "action": "add",
                            "directive": "uwsgi_hide_header",
                            "args": ["X-Powered-By"],
                            "logical_context": logical_context.copy(),
                            "exact_path": exact_path.copy()
                        }]
                    })
                if "server" not in current_uwsgi_hidden:
                    uncompliances.append({
                        "file": filepath,
                        "remediations": [{
                            "action": "add",
                            "directive": "uwsgi_hide_header",
                            "args": ["Server"],
                            "logical_context": logical_context.copy(),
                            "exact_path": exact_path.copy()
                        }]
                    })
            
            if "block" in node:
                self._traverse(
                    node["block"],
                    filepath,
                    exact_path + [idx, "block"],
                    logical_context + [dir_name],
                    current_proxy_hidden,
                    current_fastcgi_hidden,
                    current_uwsgi_hidden,
                    uncompliances
                )
