from typing import Dict, List, Any, Optional
from core.scannerEng.base_recom import BaseRecom, RecomID
import fnmatch
import os


class Detector34(BaseRecom):
    def __init__(self):
        super().__init__(RecomID.CIS_3_4)

    def scan(self, parser_output: Dict[str, Any]) -> List[Dict[str, Any]]:
        self.config_list = parser_output.get("config", [])
        uncompliances = []

        root_indices = self._get_root_indices()

        for idx in root_indices:
            config_file = self.config_list[idx]
            filepath = config_file.get("file", "")
            if not filepath.endswith(".conf"):
                continue

            parsed_ast = config_file.get("parsed", [])
            exact_path = ["config", idx, "parsed"]
            self._traverse(parsed_ast, filepath, exact_path,
                           [], {}, {}, {}, {}, uncompliances)

        return self._group_by_file(uncompliances)

    def _get_root_indices(self) -> List[int]:
        included = set()
        for idx, config_file in enumerate(self.config_list):
            self._find_includes(config_file.get("parsed", []), included, idx)

        roots = [i for i in range(len(self.config_list)) if i not in included]
        if not roots and self.config_list:
            roots = [0]
        return roots

    def _find_includes(self, ast_list: List[Any], included: set, current_idx: int):
        for node in ast_list:
            if isinstance(node, dict):
                if node.get("directive") == "include":
                    includes = node.get("includes")
                    if includes:
                        included.update(includes)
                    else:
                        args = node.get("args", [])
                        if args:
                            included.update(
                                self._resolve_include(args[0], current_idx))
                if "block" in node:
                    self._find_includes(node["block"], included, current_idx)

    def _resolve_include(self, pattern: str, current_idx: int) -> List[int]:
        matched = []
        for idx, config_file in enumerate(self.config_list):
            if idx == current_idx:
                continue
            filepath = config_file.get("file", "")
            if filepath == pattern or \
               fnmatch.fnmatch(filepath, pattern) or \
               fnmatch.fnmatch(filepath, "*/" + pattern) or \
               fnmatch.fnmatch(os.path.basename(filepath), os.path.basename(pattern)):
                matched.append(idx)
        return matched

    def _traverse(self, ast_list: List[Any], filepath: str, exact_path: List[Any],
                  logical_context: List[str], proxy_headers: Dict[str, bool],
                  fastcgi_params: Dict[str, bool], grpc_headers: Dict[str, bool],
                  uwsgi_params: Dict[str, bool],
                  uncompliances: List[Dict[str, Any]]):

        has_proxy_override = any(isinstance(n, dict) and n.get("directive") == "proxy_set_header" and (
            not n.get("args") or n.get("args")[0].lower() not in ("x-forwarded-for", "x-real-ip")) for n in ast_list)
        has_fastcgi_override = any(isinstance(n, dict) and n.get("directive") == "fastcgi_param" and (
            not n.get("args") or n.get("args")[0].lower() not in ("x-forwarded-for", "x-real-ip")) for n in ast_list)
        has_grpc_override = any(isinstance(n, dict) and n.get("directive") == "grpc_set_header" and (
            not n.get("args") or n.get("args")[0].lower() not in ("x-forwarded-for", "x-real-ip")) for n in ast_list)
        has_uwsgi_override = any(isinstance(n, dict) and n.get("directive") == "uwsgi_param" and (
            not n.get("args") or n.get("args")[0].lower() not in ("x-forwarded-for", "x-real-ip")) for n in ast_list)

        curr_proxy = proxy_headers.copy() if not has_proxy_override else {}
        curr_fastcgi = fastcgi_params.copy() if not has_fastcgi_override else {}
        curr_grpc = grpc_headers.copy() if not has_grpc_override else {}
        curr_uwsgi = uwsgi_params.copy() if not has_uwsgi_override else {}

        for idx, node in enumerate(ast_list):
            if not isinstance(node, dict):
                continue

            directive = node.get("directive")
            args = node.get("args", [])

            if directive == "proxy_set_header" and len(args) >= 1:
                curr_proxy[args[0].lower()] = True
                if len(args) >= 2 and args[1] in ('""', "''", ""):
                    curr_proxy[args[0].lower()] = False
            elif directive == "fastcgi_param" and len(args) >= 1:
                curr_fastcgi[args[0].lower()] = True
                if len(args) >= 2 and args[1] in ('""', "''", ""):
                    curr_fastcgi[args[0].lower()] = False
            elif directive == "grpc_set_header" and len(args) >= 1:
                curr_grpc[args[0].lower()] = True
                if len(args) >= 2 and args[1] in ('""', "''", ""):
                    curr_grpc[args[0].lower()] = False
            elif directive == "uwsgi_param" and len(args) >= 1:
                curr_uwsgi[args[0].lower()] = True
                if len(args) >= 2 and args[1] in ('""', "''", ""):
                    curr_uwsgi[args[0].lower()] = False

        for idx, node in enumerate(ast_list):
            if not isinstance(node, dict):
                continue

            directive = node.get("directive")

            if directive == "proxy_pass":
                self._check_headers(filepath, exact_path, logical_context, curr_proxy,
                                    "proxy_set_header", uncompliances)
            elif directive == "fastcgi_pass":
                self._check_headers(filepath, exact_path, logical_context, curr_fastcgi,
                                    "fastcgi_param", uncompliances)
            elif directive == "grpc_pass":
                self._check_headers(filepath, exact_path, logical_context, curr_grpc,
                                    "grpc_set_header", uncompliances)
            elif directive == "uwsgi_pass":
                self._check_headers(filepath, exact_path, logical_context, curr_uwsgi,
                                    "uwsgi_param", uncompliances)
            elif directive == "include":
                includes = node.get("includes")
                args = node.get("args", [])
                if not includes and args:
                    current_idx = -1
                    for i, c in enumerate(self.config_list):
                        if c.get("file") == filepath:
                            current_idx = i
                            break
                    includes = self._resolve_include(args[0], current_idx)
                if includes:
                    for inc_idx in includes:
                        inc_file = self.config_list[inc_idx]
                        inc_ast = inc_file.get("parsed", [])
                        inc_filepath = inc_file.get("file", "")
                        inc_exact_path = ["config", inc_idx, "parsed"]
                        self._traverse(inc_ast, inc_filepath, inc_exact_path, logical_context,
                                       curr_proxy, curr_fastcgi, curr_grpc, curr_uwsgi, uncompliances)
            elif "block" in node:
                if self._should_skip_block(node):
                    continue
                new_logical = logical_context + [directive]
                new_exact = exact_path + [idx, "block"]
                self._traverse(node["block"], filepath, new_exact, new_logical,
                               curr_proxy, curr_fastcgi, curr_grpc, curr_uwsgi, uncompliances)

    def _should_skip_block(self, node: Dict[str, Any]) -> bool:
        if node.get("directive") != "server":
            return False

        block = node.get("block", [])
        has_return_444 = False
        has_return_403 = False
        has_https_redirect = False
        has_catch_all_server_name = False

        for child in block:
            if not isinstance(child, dict):
                continue
            dir_name = child.get("directive")
            args = child.get("args", [])

            if dir_name == "server_name" and args[0] == "_":
                has_catch_all_server_name = True

            if dir_name == "return":
                if len(args) >= 2 and args[0] in ("301", "302", "307", "308") and args[1].startswith("https://"):
                    has_https_redirect = True
                elif len(args) == 1 and args[0].startswith("https://"):
                    has_https_redirect = True
                elif len(args) == 1 and args[0] == "444":
                    has_return_444 = True
                elif len(args) == 1 and args[0] == "403":
                    has_return_403 = True

        return has_return_444 or has_https_redirect or (has_return_403 and has_catch_all_server_name)

    def _check_headers(self, filepath: str, exact_path: List[Any], logical_context: List[str],
                       current_headers: Dict[str, bool], directive_name: str,
                       uncompliances: List[Dict[str, Any]]):
        remediations = []
        if not current_headers.get("x-forwarded-for"):
            remediations.append({
                "action": "add",
                "directive": directive_name,
                "args": ["X-Forwarded-For", "$proxy_add_x_forwarded_for"],
                "logical_context": logical_context.copy(),
                "exact_path": exact_path.copy()
            })
        if not current_headers.get("x-real-ip"):
            remediations.append({
                "action": "add",
                "directive": directive_name,
                "args": ["X-Real-IP", "$remote_addr"],
                "logical_context": logical_context.copy(),
                "exact_path": exact_path.copy()
            })

        if remediations:
            uncompliances.append({
                "file": filepath,
                "remediations": remediations
            })
