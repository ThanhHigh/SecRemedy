import re
from typing import Dict, List, Any, Optional
from core.scannerEng.base_recom import BaseRecom, RecomID


class Detector532(BaseRecom):
    def __init__(self):
        super().__init__(RecomID.CIS_5_3_2)

    def _check_csp(self, directive: dict) -> bool:
        args = directive.get("args", [])
        if not args or len(args) < 2:
            return False
        if args[-1].lower() != "always":
            return False
        value = args[1].lower()
        if "default-src" not in value or "frame-ancestors" not in value:
            return False
        if "unsafe-inline" in value or "unsafe-eval" in value:
            return False
        return True

    def _resolve_includes(self, d: dict, config_list: List[Dict]) -> List[int]:
        inc_files = []
        if "includes" in d:
            inc_files = d["includes"]
        else:
            inc_arg = d.get("args", [""])[0] if d.get("args") else ""
            if inc_arg:
                search_str = inc_arg.split("/")[-1]
                if search_str == "*.conf":
                    search_str = ".conf"
                for inc_idx, cf in enumerate(config_list):
                    if cf.get("file", "").endswith(search_str):
                        inc_files.append(inc_idx)
        return inc_files

    def _get_direct_add_headers(self, dirs: List[Dict], cur_exact_path: List[Any], cur_file_idx: int, config_list: List[Dict]) -> List[Dict]:
        headers = []
        for i, d in enumerate(dirs):
            path = cur_exact_path + [i]
            if d.get("directive") == "add_header":
                headers.append({
                    "stmt": d,
                    "exact_path": path,
                    "file_idx": cur_file_idx
                })
            elif d.get("directive") == "include":
                for inc_idx in self._resolve_includes(d, config_list):
                    if inc_idx < len(config_list):
                        inc_parsed = config_list[inc_idx].get("parsed", [])
                        inc_path = ["config", inc_idx, "parsed"]
                        headers.extend(self._get_direct_add_headers(inc_parsed, inc_path, inc_idx, config_list))
        return headers

    def _is_leaf(self, dirs: List[Dict], config_list: List[Dict]) -> bool:
        for d in dirs:
            if d.get("directive") in ("server", "location"):
                return False
            if d.get("directive") == "include":
                for inc_idx in self._resolve_includes(d, config_list):
                    if inc_idx < len(config_list):
                        inc_parsed = config_list[inc_idx].get("parsed", [])
                        if not self._is_leaf(inc_parsed, config_list):
                            return False
        return True

    def _traverse(self, directives: List[Dict], logical_context: List[str], base_exact_path: List[Any], file_idx: int, inherited_csp: Optional[Dict], config_list: List[Dict], adds: Dict, replaces: Dict, visited_files: set):
        visited_files.add(file_idx)
        
        headers = self._get_direct_add_headers(directives, base_exact_path, file_idx, config_list)
        has_add_header = len(headers) > 0
        local_csp = None
        
        for h in headers:
            args = h["stmt"].get("args", [])
            if args and args[0].lower() in ("content-security-policy", "content-security-policy-report-only"):
                is_valid = self._check_csp(h["stmt"])
                local_csp = {
                    "stmt": h["stmt"],
                    "exact_path": h["exact_path"],
                    "file_idx": h["file_idx"],
                    "is_valid": is_valid,
                    "owner_context": logical_context.copy()
                }
        
        effective_csp = local_csp if has_add_header else inherited_csp
        current_block_name = logical_context[-1] if logical_context else ""
        block_is_leaf = self._is_leaf(directives, config_list)
        
        if current_block_name in ("server", "location"):
            needs_add = False
            invalid_csp = None
            
            if has_add_header:
                if local_csp is None:
                    needs_add = True
                elif not local_csp["is_valid"]:
                    invalid_csp = local_csp
            else:
                if effective_csp is None:
                    if block_is_leaf:
                        needs_add = True
                else:
                    if not effective_csp["is_valid"]:
                        invalid_csp = effective_csp
            
            if needs_add:
                ep_tuple = tuple(base_exact_path)
                adds[ep_tuple] = {
                    "file_idx": file_idx,
                    "logical_context": logical_context.copy(),
                    "exact_path": base_exact_path.copy()
                }
                effective_csp = {
                    "stmt": {}, "exact_path": [], "file_idx": 0, "is_valid": True, "owner_context": []
                }
            
            if invalid_csp:
                ep_tuple = tuple(invalid_csp["exact_path"])
                replaces[ep_tuple] = {
                    "file_idx": invalid_csp["file_idx"],
                    "logical_context": invalid_csp["owner_context"],
                    "exact_path": invalid_csp["exact_path"],
                    "stmt": invalid_csp["stmt"]
                }
        
        for i, d in enumerate(directives):
            path = base_exact_path + [i]
            dir_name = d.get("directive", "")
            
            if "block" in d:
                next_context = logical_context.copy()
                if dir_name in ("http", "server", "location"):
                    next_context.append(dir_name)
                self._traverse(d["block"], next_context, path + ["block"], file_idx, effective_csp, config_list, adds, replaces, visited_files)
            
            elif dir_name == "include":
                for inc_idx in self._resolve_includes(d, config_list):
                    if inc_idx < len(config_list):
                        inc_parsed = config_list[inc_idx].get("parsed", [])
                        inc_path = ["config", inc_idx, "parsed"]
                        self._traverse(inc_parsed, logical_context, inc_path, inc_idx, effective_csp, config_list, adds, replaces, visited_files)

    def scan(self, parser_output: Dict[str, Any]) -> List[Dict[str, Any]]:
        uncompliances = []
        config_list = parser_output.get("config", [])
        
        adds = {}
        replaces = {}
        visited_files = set()

        if config_list:
            entrypoint_idx = 0
            for i, cf in enumerate(config_list):
                if cf.get("file", "").endswith("nginx.conf"):
                    entrypoint_idx = i
                    break
            
            self._traverse(config_list[entrypoint_idx].get("parsed", []), [], ["config", entrypoint_idx, "parsed"], entrypoint_idx, None, config_list, adds, replaces, visited_files)
            
            global_http_csp = None
            for i, stmt in enumerate(config_list[entrypoint_idx].get("parsed", [])):
                if stmt.get("directive") == "http":
                    headers = self._get_direct_add_headers(stmt.get("block", []), ["config", entrypoint_idx, "parsed", i, "block"], entrypoint_idx, config_list)
                    for h in headers:
                        args = h["stmt"].get("args", [])
                        if args and args[0].lower() in ("content-security-policy", "content-security-policy-report-only"):
                            global_http_csp = {
                                "stmt": h["stmt"], "exact_path": h["exact_path"], "file_idx": h["file_idx"], 
                                "is_valid": self._check_csp(h["stmt"]), "owner_context": ["http"]
                            }
            
            for idx, config_file in enumerate(config_list):
                if idx not in visited_files:
                    filepath = config_file.get("file", "")
                    if not filepath.endswith(".conf"):
                        continue
                    self._traverse(config_file.get("parsed", []), ["http"], ["config", idx, "parsed"], idx, global_http_csp, config_list, adds, replaces, visited_files)

        for add_item in adds.values():
            file_path = config_list[add_item["file_idx"]]["file"]
            uncompliances.append({
                "file": file_path,
                "remediations": [{
                    "action": "add",
                    "directive": "add_header",
                    "args": ["Content-Security-Policy", '"default-src \'self\'; frame-ancestors \'self\'; form-action \'self\';"', "always"],
                    "logical_context": add_item["logical_context"],
                    "exact_path": add_item["exact_path"]
                }]
            })

        for rep_item in replaces.values():
            file_path = config_list[rep_item["file_idx"]]["file"]
            orig_name = rep_item["stmt"].get("args", ["Content-Security-Policy"])[0]
            uncompliances.append({
                "file": file_path,
                "remediations": [{
                    "action": "replace",
                    "directive": "add_header",
                    "args": [orig_name, '"default-src \'self\'; frame-ancestors \'self\'; form-action \'self\';"', "always"],
                    "logical_context": rep_item["logical_context"],
                    "exact_path": rep_item["exact_path"]
                }]
            })

        return self._group_by_file(uncompliances)
