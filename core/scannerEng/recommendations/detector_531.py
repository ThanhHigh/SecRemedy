import json
from typing import Dict, List, Any
from core.scannerEng.base_recom import BaseRecom, RecomID


class Detector531(BaseRecom):
    def __init__(self):
        super().__init__(RecomID.CIS_5_3_1)

    def _get_directives_at_level(self, dirs: List[Dict[str, Any]], exact_path: List[Any], config_list: List[Dict[str, Any]]):
        for i, d in enumerate(dirs):
            d_path = exact_path + [i]
            f_idx = d_path[1]
            yield d, f_idx, d_path

            if d.get("directive") == "include":
                inc_list = d.get("includes", [])
                # If parser didn't provide includes, try to guess from args (for mock tests)
                # if not inc_list and d.get("args"):
                #     inc_arg = d["args"][0].split('/')[-1].replace('*', '')
                #     for idx, c in enumerate(config_list):
                #         c_file = c.get("file", "")
                #         if inc_arg and c_file.endswith(inc_arg):
                #             if idx not in inc_list:
                #                 inc_list.append(idx)

                for inc_idx in inc_list:
                    if inc_idx < len(config_list):
                        inc_dirs = config_list[inc_idx].get("parsed", [])
                        inc_path = ["config", inc_idx, "parsed"]
                        yield from self._get_directives_at_level(inc_dirs, inc_path, config_list)

    def _get_headers_state(self, dirs_at_level: List[Any], inherited_state: str):
        has_any_add_header = False
        xcto_headers = []
        for d, f_idx, d_path in dirs_at_level:
            if d.get("directive") == "add_header":
                has_any_add_header = True
                args = d.get("args", [])
                if args and args[0].lower() == "x-content-type-options":
                    xcto_headers.append((d, f_idx, d_path))

        if xcto_headers:
            is_valid = False
            invalid_headers = []
            for d, f_idx, d_path in xcto_headers:
                args = d.get("args", [])
                if len(args) >= 3 and args[1].replace('"', '').replace("'", "") == "nosniff" and args[-1] == "always":
                    is_valid = True
                else:
                    invalid_headers.append((d, f_idx, d_path))
            if is_valid:
                return "VALID", []
            else:
                return "MISSING", invalid_headers
        else:
            if has_any_add_header:
                return "MISSING", []
            else:
                return inherited_state, []

    def _add_remediation(self, f_idx: int, action: str, directive: str, args: List[str], logical_context: List[str], exact_path: List[Any], config_list: List[Dict[str, Any]], all_remediations: List[Dict[str, Any]], unique_remediations: set):
        file_path = config_list[f_idx].get("file", "")
        rem = {
            "file": file_path,
            "remediations": [{
                "action": action,
                "directive": directive,
                "args": args,
                "logical_context": logical_context,
                "exact_path": exact_path
            }]
        }
        rem_str = json.dumps(rem, sort_keys=True)
        if rem_str not in unique_remediations:
            unique_remediations.add(rem_str)
            all_remediations.append(rem)

    def _evaluate_block(self, block_type: str, dirs_at_level: List[Any], exact_path: List[Any], inherited_state: str, logical_context: List[str], http_state: str, config_list: List[Dict[str, Any]], all_remediations: List[Dict[str, Any]], unique_remediations: set):
        current_state, invalid_headers = self._get_headers_state(
            dirs_at_level, inherited_state)

        # 1. Generate REPLACE remediations for invalid headers in this block
        for d, f_idx, d_path in invalid_headers:
            self._add_remediation(f_idx, "replace", "add_header", [
                                  "X-Content-Type-Options", '"nosniff"', "always"], logical_context, d_path, config_list, all_remediations, unique_remediations)

        # 2. Check if we need to ADD
        if current_state == "MISSING" and not invalid_headers:
            has_location = any(d.get("directive") ==
                               "location" for d, _, _ in dirs_at_level)
            should_add = False
            if block_type == "server" and not has_location:
                should_add = True
            elif block_type == "location":
                should_add = True
            elif block_type == "server" and has_location:
                pass

            if should_add:
                f_idx = exact_path[1]
                self._add_remediation(f_idx, "add", "add_header", [
                                      "X-Content-Type-Options", '"nosniff"', "always"], logical_context, exact_path, config_list, all_remediations, unique_remediations)
                current_state = "VALID"  # Downstream inherits this

        # 3. Recurse into child blocks
        for d, f_idx, d_path in dirs_at_level:
            if "block" in d:
                new_block_type = d.get("directive")
                if new_block_type in ("http", "server", "location"):
                    new_logical_context = logical_context + [new_block_type]
                    new_exact_path = d_path + ["block"]
                    new_dirs_at_level = list(self._get_directives_at_level(
                        d["block"], new_exact_path, config_list))

                    # Pass the correct inherited state
                    if new_block_type == "server" and block_type == "main":
                        pass_state = http_state
                    else:
                        pass_state = current_state

                    self._evaluate_block(new_block_type, new_dirs_at_level, new_exact_path, pass_state,
                                         new_logical_context, http_state, config_list, all_remediations, unique_remediations)

    def scan(self, parser_output: Dict[str, Any]) -> List[Dict[str, Any]]:
        config_list = parser_output.get("config", [])

        # 1. Compute http_state
        http_state = "MISSING"
        for f_idx, config in enumerate(config_list):
            for i, d in enumerate(config.get("parsed", [])):
                if d.get("directive") == "http":
                    d_path = ["config", f_idx, "parsed", i, "block"]
                    http_dirs = list(self._get_directives_at_level(
                        d.get("block", []), d_path, config_list))
                    http_state, _ = self._get_headers_state(
                        http_dirs, "MISSING")
                    break

        all_remediations = []
        unique_remediations = set()

        # Start evaluation from the root of all files
        for f_idx, config in enumerate(config_list):
            root_exact_path = ["config", f_idx, "parsed"]
            root_dirs = list(self._get_directives_at_level(
                config.get("parsed", []), root_exact_path, config_list))
            self._evaluate_block("main", root_dirs, root_exact_path, "MISSING", [
            ], http_state, config_list, all_remediations, unique_remediations)

        return self._group_by_file(all_remediations)
