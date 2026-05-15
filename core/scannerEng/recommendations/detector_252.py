from typing import Dict, List, Any, Optional
from core.scannerEng.base_recom import BaseRecom, RecomID


class Detector252(BaseRecom):
    def __init__(self, scan_server: bool = True):
        super().__init__(RecomID.CIS_2_5_2)
        self.scan_server = scan_server

    def _should_skip_block(self, node: Dict[str, Any]) -> bool:
        if not isinstance(node, dict):
            return False
        if node.get("directive") != "server":
            return False

        block = node.get("block", [])
        has_return_444 = False

        for child in block:
            if not isinstance(child, dict):
                continue
            dir_name = child.get("directive")
            args = child.get("args", [])

            if dir_name == "return":
                if len(args) == 1 and args[0] == "444":
                    has_return_444 = True

        return has_return_444

    def traverse_directive(self, target_directive: str, directives: List[Dict], filepath: str, logical_context: List[str], exact_path: List[Any], state: Any = None) -> List[Dict[str, Any]]:
        matches = []
        for idx, directive in enumerate(directives):
            if directive.get("directive") == "upstream":
                continue

            if self._should_skip_block(directive):
                continue

            current_exact_path = exact_path + [idx]

            if directive.get("directive") == target_directive:
                matches.append({
                    "directive": directive,
                    "line": directive.get("line"),
                    "filepath": filepath,
                    "logical_context": logical_context,
                    "exact_path": current_exact_path,
                    "state": state
                })

            if "block" in directive:
                new_logical_context = logical_context + \
                    [directive["directive"]]
                new_exact_path = current_exact_path + ["block"]

                matches.extend(self.traverse_directive(
                    target_directive=target_directive,
                    directives=directive["block"],
                    filepath=filepath,
                    logical_context=new_logical_context,
                    exact_path=new_exact_path,
                    state=state
                ))
        return matches

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

    def _add_rems(self, uncompliances: List[Dict[str, Any]], filepath: str, exact_path: List[Any], ctx: List[str], missing_404: bool, missing_50x: bool, line: Optional[int] = None):
        rems = []
        if missing_404:
            rems.append({
                "action": "add",
                "directive": "error_page",
                "args": ["404", "/custom_404.html"],
                "line": line,
                "logical_context": ctx,
                "exact_path": exact_path
            })
        if missing_50x:
            rems.append({
                "action": "add",
                "directive": "error_page",
                "args": ["500", "502", "503", "504", "/custom_50x.html"],
                "line": line,
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
            if not filepath.endswith(".conf") and not filepath.endswith("nginx.conf"):
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

        # Global codes for inheritance check
        global_http_codes = set()
        for h in http_blocks:
            _, codes = self._get_error_codes(h["directive"].get("block", []))
            global_http_codes.update(codes)

        # 1. Scan HTTP blocks
        for h in http_blocks:
            has_ep, codes = self._get_error_codes(h["directive"].get("block", []))
            m404, m50x = self._check_missing(codes)
            if m404 or m50x:
                self._add_rems(uncompliances, h["filepath"], h["exact_path"] + ["block"],
                               h["logical_context"] + ["http"], m404, m50x, h["directive"].get("line"))

        # 2. Scan Server blocks
        for s in server_blocks:
            has_ep, codes = self._get_error_codes(s["directive"].get("block", []))
            
            if has_ep:
                # Local error_page overrides http level
                m404, m50x = self._check_missing(codes)
                if m404 or m50x:
                    self._add_rems(uncompliances, s["filepath"], s["exact_path"] + ["block"],
                                   s["logical_context"] + ["server"], m404, m50x, s["directive"].get("line"))
            else:
                # Inherits from http
                if self.scan_server:
                    # Strict mode: must have its own
                    self._add_rems(uncompliances, s["filepath"], s["exact_path"] + ["block"],
                                   s["logical_context"] + ["server"], True, True, s["directive"].get("line"))
                else:
                    # Inherited compliance
                    m404, m50x = self._check_missing(global_http_codes)
                    if m404 or m50x:
                        self._add_rems(uncompliances, s["filepath"], s["exact_path"] + ["block"],
                                       s["logical_context"] + ["server"], m404, m50x, s["directive"].get("line"))

        # 3. Fallback if no blocks found at all
        if not http_blocks and not server_blocks:
            for config_idx, config_file in enumerate(parser_output.get("config", [])):
                filepath = config_file.get("file", "")
                if filepath.endswith(".conf") or filepath.endswith("nginx.conf"):
                    self._add_rems(uncompliances, filepath, ["config", config_idx, "parsed"], [], True, True)
                    break

        return self._group_by_file(uncompliances)
