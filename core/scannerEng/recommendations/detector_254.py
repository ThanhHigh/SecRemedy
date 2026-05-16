from typing import Dict, List, Any, Optional
from core.scannerEng.base_recom import BaseRecom, RecomID
import fnmatch
import os


class Detector254(BaseRecom):
    def __init__(self):
        super().__init__(RecomID.CIS_2_5_4)

    # ------------------------------------------------------------------
    # pass directive -> hide_header directive name
    # ------------------------------------------------------------------
    _PASS_TO_HIDE = {
        "proxy_pass":   "proxy_hide_header",
        "fastcgi_pass": "fastcgi_hide_header",
        "uwsgi_pass":   "uwsgi_hide_header",
    }

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

    # ------------------------------------------------------------------
    # Include resolution helpers (mirrors detector_34 pattern)
    # ------------------------------------------------------------------
    def _resolve_include(self, pattern: str, current_idx: int) -> List[int]:
        matched = []
        for idx, config_file in enumerate(self.config_list):
            if idx == current_idx:
                continue
            filepath = config_file.get("file", "")
            if (filepath == pattern or
                    fnmatch.fnmatch(filepath, pattern) or
                    fnmatch.fnmatch(filepath, "*/" + pattern) or
                    fnmatch.fnmatch(os.path.basename(filepath), os.path.basename(pattern))):
                matched.append(idx)
        return matched

    def _find_sibling_include_target(
        self, ast_list: List[Any], filepath: str
    ) -> Dict[str, Optional[tuple]]:
        """When a pass directive and an include co-exist in the same block,
        return the resolved include file as the remediation target.

        Returns: {hide_directive_name: (inc_filepath, inc_exact_path) | None}
        """
        pass_types: set = set()
        include_nodes: List[Dict] = []
        for node in ast_list:
            if not isinstance(node, dict):
                continue
            d = node.get("directive", "")
            if d in self._PASS_TO_HIDE:
                pass_types.add(d)
            elif d == "include":
                include_nodes.append(node)

        result: Dict[str, Optional[tuple]] = {}
        if not pass_types or not include_nodes:
            return result

        current_idx = next(
            (i for i, c in enumerate(self.config_list) if c.get("file") == filepath),
            -1
        )

        for pass_dir in pass_types:
            hide_name = self._PASS_TO_HIDE[pass_dir]
            for inc_node in include_nodes:
                includes = inc_node.get("includes")
                args = inc_node.get("args", [])
                if not includes and args:
                    includes = self._resolve_include(args[0], current_idx)
                if includes:
                    inc_idx = includes[0]
                    inc_file = self.config_list[inc_idx]
                    inc_filepath = inc_file.get("file", "")
                    inc_exact_path = ["config", inc_idx, "parsed"]
                    result[hide_name] = (inc_filepath, inc_exact_path)
                    break  # first matching include per pass type

        return result

    def _merge_sibling_include_hidden(
        self,
        ast_list: List[Any],
        filepath: str,
        proxy_hidden: set,
        fastcgi_hidden: set,
        uwsgi_hidden: set,
    ) -> None:
        """Read hide_header directives from sibling include files so that
        compliant snippets (e.g. php_fastcgi.conf) avoid false positives."""
        current_idx = next(
            (i for i, c in enumerate(self.config_list) if c.get("file") == filepath),
            -1
        )
        _dir_to_set = {
            "proxy_hide_header":   proxy_hidden,
            "fastcgi_hide_header": fastcgi_hidden,
            "uwsgi_hide_header":   uwsgi_hidden,
        }
        for node in ast_list:
            if not isinstance(node, dict) or node.get("directive") != "include":
                continue
            includes = node.get("includes")
            args = node.get("args", [])
            if not includes and args:
                includes = self._resolve_include(args[0], current_idx)
            if not includes:
                continue
            for inc_idx in includes:
                inc_ast = self.config_list[inc_idx].get("parsed", [])
                for inc_node in inc_ast:
                    if not isinstance(inc_node, dict):
                        continue
                    d = inc_node.get("directive", "")
                    inc_args = inc_node.get("args", [])
                    target_set = _dir_to_set.get(d)
                    if target_set is not None and inc_args and not inc_args[0].startswith("$"):
                        target_set.add(inc_args[0].lower())

    # ------------------------------------------------------------------
    # Entry point
    # ------------------------------------------------------------------
    def scan(self, parser_output: Dict[str, Any]) -> List[Dict[str, Any]]:
        self.config_list = parser_output.get("config", [])
        uncompliances = []

        for config_idx, config_file in enumerate(self.config_list):
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

        # Pull hide_header directives from sibling include files into hidden sets
        # so compliant included snippets prevent false positives.
        self._merge_sibling_include_hidden(
            ast_list, filepath,
            current_proxy_hidden, current_fastcgi_hidden, current_uwsgi_hidden
        )

        # Resolve sibling include targets: if a pass directive and an include
        # co-exist in this block, remediations go into the included file.
        sibling_target = self._find_sibling_include_target(ast_list, filepath)

        for idx, node in enumerate(ast_list):
            if not isinstance(node, dict):
                continue

            if self._should_skip_block(node):
                continue

            dir_name = node.get("directive")

            if dir_name == "proxy_pass":
                tgt = sibling_target.get("proxy_hide_header")
                tgt_fp = tgt[0] if tgt else filepath
                tgt_ep = tgt[1] if tgt else exact_path

                if "x-powered-by" not in current_proxy_hidden:
                    uncompliances.append({
                        "file": tgt_fp,
                        "remediations": [{
                            "action": "add",
                            "directive": "proxy_hide_header",
                            "args": ["X-Powered-By"],
                            "line": node.get("line"),
                            "logical_context": logical_context.copy(),
                            "exact_path": tgt_ep.copy(),
                        }]
                    })
                if "server" not in current_proxy_hidden:
                    uncompliances.append({
                        "file": tgt_fp,
                        "remediations": [{
                            "action": "add",
                            "directive": "proxy_hide_header",
                            "args": ["Server"],
                            "line": node.get("line"),
                            "logical_context": logical_context.copy(),
                            "exact_path": tgt_ep.copy(),
                        }]
                    })

            elif dir_name == "fastcgi_pass":
                tgt = sibling_target.get("fastcgi_hide_header")
                tgt_fp = tgt[0] if tgt else filepath
                tgt_ep = tgt[1] if tgt else exact_path

                if "x-powered-by" not in current_fastcgi_hidden:
                    uncompliances.append({
                        "file": tgt_fp,
                        "remediations": [{
                            "action": "add",
                            "directive": "fastcgi_hide_header",
                            "args": ["X-Powered-By"],
                            "line": node.get("line"),
                            "logical_context": logical_context.copy(),
                            "exact_path": tgt_ep.copy(),
                        }]
                    })

            elif dir_name == "uwsgi_pass":
                tgt = sibling_target.get("uwsgi_hide_header")
                tgt_fp = tgt[0] if tgt else filepath
                tgt_ep = tgt[1] if tgt else exact_path

                if "x-powered-by" not in current_uwsgi_hidden:
                    uncompliances.append({
                        "file": tgt_fp,
                        "remediations": [{
                            "action": "add",
                            "directive": "uwsgi_hide_header",
                            "args": ["X-Powered-By"],
                            "line": node.get("line"),
                            "logical_context": logical_context.copy(),
                            "exact_path": tgt_ep.copy(),
                        }]
                    })
                if "server" not in current_uwsgi_hidden:
                    uncompliances.append({
                        "file": tgt_fp,
                        "remediations": [{
                            "action": "add",
                            "directive": "uwsgi_hide_header",
                            "args": ["Server"],
                            "line": node.get("line"),
                            "logical_context": logical_context.copy(),
                            "exact_path": tgt_ep.copy(),
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
