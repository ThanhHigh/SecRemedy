from typing import Dict, List, Any, Optional
from core.scannerEng.base_recom import BaseRecom, RecomID


class Detector252(BaseRecom):
    def __init__(self):
        super().__init__(RecomID.CIS_2_5_2)

    def _get_error_codes(self, block_directives: List[Dict[str, Any]]):
        codes = set()
        has_error_page = False
        for d in block_directives:
            if d.get("directive") == "error_page":
                args = d.get("args", [])
                if len(args) >= 2:
                    has_uri = False
                    for arg in args:
                        clean_arg = str(arg).strip("\"'")
                        if not clean_arg.isdigit() and not (clean_arg.startswith("=") and clean_arg[1:].isdigit()):
                            has_uri = True
                            break
                    if has_uri:
                        has_error_page = True
                        for arg in args:
                            clean_arg = str(arg).strip("\"'")
                            if clean_arg.isdigit():
                                codes.add(clean_arg)
        return has_error_page, codes

    def _check_missing(self, codes: set):
        missing_404 = "404" not in codes
        missing_50x = not all(c in codes for c in ["500", "502", "503", "504"])
        return missing_404, missing_50x

    def _add_rems(self, uncompliances: List[Dict[str, Any]], filepath: str, exact_path: List[Any], ctx: List[str], missing_404: bool, missing_50x: bool):
        rems = []
        if missing_404:
            rems.append({
                "action": "add",
                "directive": "error_page",
                "args": ["404", "/custom_404.html"],
                "logical_context": ctx,
                "exact_path": exact_path
            })
        if missing_50x:
            rems.append({
                "action": "add",
                "directive": "error_page",
                "args": ["500", "502", "503", "504", "/custom_50x.html"],
                "logical_context": ctx,
                "exact_path": exact_path
            })
        if rems:
            uncompliances.append({
                "file": filepath,
                "remediations": rems
            })

    def scan(self, parser_output: Dict[str, Any]) -> List[Dict[str, Any]]:
        uncompliances = []

        http_blocks = []
        server_blocks = []

        for config_idx, config_file in enumerate(parser_output.get("config", [])):
            filepath = config_file.get("file", "")
            if not filepath.endswith(".conf"):
                continue
            
            parsed_ast = config_file.get("parsed", [])
            base_exact_path = ["config", config_idx, "parsed"]

            https = self.traverse_directive(
                target_directive="http",
                directives=parsed_ast,
                filepath=filepath,
                logical_context=[],
                exact_path=base_exact_path
            )
            http_blocks.extend(https)
            
            servers = self.traverse_directive(
                target_directive="server",
                directives=parsed_ast,
                filepath=filepath,
                logical_context=[],
                exact_path=base_exact_path
            )
            server_blocks.extend(servers)

        if not http_blocks and not server_blocks:
            for config_idx, config_file in enumerate(parser_output.get("config", [])):
                filepath = config_file.get("file", "")
                if filepath.endswith(".conf"):
                    rems = []
                    rems.append({
                        "action": "add",
                        "directive": "error_page",
                        "args": ["404", "/custom_404.html"],
                        "logical_context": [],
                        "exact_path": ["config", config_idx, "parsed"]
                    })
                    rems.append({
                        "action": "add",
                        "directive": "error_page",
                        "args": ["500", "502", "503", "504", "/custom_50x.html"],
                        "logical_context": [],
                        "exact_path": ["config", config_idx, "parsed"]
                    })
                    uncompliances.append({
                        "file": filepath,
                        "remediations": rems
                    })
                    break
            return self._group_by_file(uncompliances)

        global_http_codes = set()
        for http_match in http_blocks:
            d = http_match["directive"]
            has_ep, codes = self._get_error_codes(d.get("block", []))
            if has_ep:
                global_http_codes.update(codes)

        if not server_blocks:
            for http_match in http_blocks:
                filepath = http_match["filepath"]
                d = http_match["directive"]
                epath = http_match["exact_path"]
                ctx = http_match["logical_context"] + ["http"]
                
                _, codes = self._get_error_codes(d.get("block", []))
                m_404, m_50x = self._check_missing(codes)
                if m_404 or m_50x:
                    self._add_rems(uncompliances, filepath, epath + ["block"], ctx, m_404, m_50x)
        else:
            required_codes = {"404", "500", "502", "503", "504"}
            for server_match in server_blocks:
                filepath = server_match["filepath"]
                d = server_match["directive"]
                epath = server_match["exact_path"]
                ctx = server_match["logical_context"] + ["server"]
                
                has_ep, codes = self._get_error_codes(d.get("block", []))
                
                if has_ep:
                    has_custom_code = any(c not in required_codes for c in codes)
                    if has_custom_code:
                        effective_codes = codes
                    else:
                        effective_codes = codes.union(global_http_codes)
                else:
                    effective_codes = global_http_codes
                
                m_404, m_50x = self._check_missing(effective_codes)
                if m_404 or m_50x:
                    self._add_rems(uncompliances, filepath, epath + ["block"], ctx, m_404, m_50x)

        return self._group_by_file(uncompliances)
