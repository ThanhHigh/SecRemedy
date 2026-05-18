import json
from typing import Dict, List, Any
from core.scannerEng.base_recom import BaseRecom, RecomID


class BlockNode:
    def __init__(self, block_type: str, exact_path: List[Any], f_idx: int):
        self.block_type = block_type
        self.exact_path = exact_path
        self.f_idx = f_idx
        self.children = []
        self.has_add_header = False
        self.has_valid_xcto = False
        self.invalid_xcto = []
        self.clean_descendants = True
        self.needs_xcto_directly = False
        self.subtree_needs = False


class Detector531(BaseRecom):
    def __init__(self):
        super().__init__(RecomID.CIS_5_3_1)

    def _should_skip_block(self, node: Dict[str, Any]) -> bool:
        if not isinstance(node, dict):
            return False
        if node.get("directive") != "server":
            return False

        block = node.get("block", [])
        has_server_name_catchall = False
        has_https_redirect = False

        for child in block:
            if not isinstance(child, dict):
                continue
            dir_name = child.get("directive")
            args = child.get("args", [])

            if dir_name == "server_name" and "_" in args:
                has_server_name_catchall = True

            if dir_name == "return":
                if len(args) >= 2 and args[0] in ("301", "302", "307", "308") and args[1].startswith("https://"):
                    has_https_redirect = True
                elif len(args) == 1 and args[0].startswith("https://"):
                    has_https_redirect = True

        return has_server_name_catchall or has_https_redirect

    def _get_directives_at_level(self, dirs: List[Dict[str, Any]], exact_path: List[Any], config_list: List[Dict[str, Any]]):
        for i, d in enumerate(dirs):
            if self._should_skip_block(d):
                continue

            d_path = exact_path + [i]
            f_idx = d_path[1]
            yield d, f_idx, d_path

            if d.get("directive") == "include":
                inc_list = d.get("includes", [])

                for inc_idx in inc_list:
                    if inc_idx < len(config_list):
                        inc_dirs = config_list[inc_idx].get("parsed", [])
                        inc_path = ["config", inc_idx, "parsed"]
                        yield from self._get_directives_at_level(inc_dirs, inc_path, config_list)

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

    def _build_tree(self, block_type: str, dirs_at_level: List[Any], exact_path: List[Any], f_idx: int, config_list: List[Dict[str, Any]]) -> BlockNode:
        node = BlockNode(block_type, exact_path, f_idx)

        for d, c_f_idx, c_path in dirs_at_level:
            dir_name = d.get("directive")
            if dir_name == "add_header":
                node.has_add_header = True
                args = d.get("args", [])
                if args and args[0].lower() == "x-content-type-options":
                    if len(args) >= 3 and args[1].replace('"', '').replace("'", "") == "nosniff" and args[-1] == "always":
                        node.has_valid_xcto = True
                    else:
                        node.invalid_xcto.append((d, c_f_idx, c_path))
            elif "block" in d:
                new_block_type = dir_name
                if new_block_type in ("http", "server", "location"):
                    new_exact_path = c_path + ["block"]
                    new_dirs_at_level = list(self._get_directives_at_level(d["block"], new_exact_path, config_list))
                    child_node = self._build_tree(new_block_type, new_dirs_at_level, new_exact_path, c_f_idx, config_list)
                    node.children.append(child_node)

        # Check clean_descendants
        for child in node.children:
            if child.has_add_header or not child.clean_descendants:
                node.clean_descendants = False
                break

        # Check needs_xcto_directly
        has_location_child = any(c.block_type == "location" for c in node.children)
        if block_type == "server" and not has_location_child:
            node.needs_xcto_directly = True
        elif block_type == "location":
            node.needs_xcto_directly = True

        # Check subtree_needs
        node.subtree_needs = node.needs_xcto_directly
        for child in node.children:
            if child.subtree_needs:
                node.subtree_needs = True

        return node

    # def _traverse_and_remediate(self, node: BlockNode, inherited_valid: bool, logical_context: List[str], config_list: List[Dict[str, Any]], all_remediations: List[Dict[str, Any]], unique_remediations: set):
    #     # 1. Generate REPLACE remediations for invalid headers in this block
    #     for d, c_f_idx, c_path in node.invalid_xcto:
    #         self._add_remediation(c_f_idx, "replace", "add_header",
    #                               ["X-Content-Type-Options", '"nosniff"', "always"],
    #                               logical_context, c_path, config_list, all_remediations, unique_remediations)

    #     # 2. Determine current valid state
    #     current_valid = node.has_valid_xcto or len(node.invalid_xcto) > 0
    #     if not current_valid:
    #         if node.has_add_header:
    #             current_valid = False
    #         else:
    #             current_valid = inherited_valid

    #     # 3. Add header if needed
    #     if not current_valid:
    #         if node.clean_descendants:
    #             if node.subtree_needs:
    #                 self._add_remediation(node.f_idx, "add", "add_header",
    #                                       ["X-Content-Type-Options", '"nosniff"', "always"],
    #                                       logical_context, node.exact_path, config_list, all_remediations, unique_remediations)
    #                 current_valid = True
    #         else:
    #             if node.needs_xcto_directly:
    #                 self._add_remediation(node.f_idx, "add", "add_header",
    #                                       ["X-Content-Type-Options", '"nosniff"', "always"],
    #                                       logical_context, node.exact_path, config_list, all_remediations, unique_remediations)
    #                 current_valid = True

    #     # 4. Recurse into children
    #     for child in node.children:
    #         child_context = logical_context + [child.block_type]
    #         self._traverse_and_remediate(child, current_valid, child_context, config_list, all_remediations, unique_remediations)

    def _traverse_and_remediate(self, node: BlockNode, inherited_valid: bool, logical_context: List[str], config_list: List[Dict[str, Any]], all_remediations: List[Dict[str, Any]], unique_remediations: set):
    # 1. Fix invalid existing headers
        for d, c_f_idx, c_path in node.invalid_xcto:
            self._add_remediation(c_f_idx, "replace", "add_header",
                                ["X-Content-Type-Options", '"nosniff"', "always"],
                                logical_context, c_path, config_list, all_remediations, unique_remediations)

        # 2. Determine if THIS block needs header
        has_it = node.has_valid_xcto or len(node.invalid_xcto) > 0
        
        # If server level + missing -> Add to server
        if node.block_type == "server" and not has_it:
            self._add_remediation(node.f_idx, "add", "add_header",
                                ["X-Content-Type-Options", '"nosniff"', "always"],
                                logical_context, node.exact_path, config_list, all_remediations, unique_remediations)
            has_it = True

        # If location level + breaks inheritance (has other headers) + missing -> Add to location
        if node.block_type == "location" and node.has_add_header and not has_it:
            self._add_remediation(node.f_idx, "add", "add_header",
                                ["X-Content-Type-Options", '"nosniff"', "always"],
                                logical_context, node.exact_path, config_list, all_remediations, unique_remediations)
            has_it = True

        # 3. Handle state for children
        current_valid = has_it if (node.has_add_header or has_it) else inherited_valid

        # 4. Recurse
        for child in node.children:
            child_context = logical_context + [child.block_type]
            self._traverse_and_remediate(child, current_valid, child_context, config_list, all_remediations, unique_remediations)

    @staticmethod
    def _collect_included_indices(config_list: List[Dict[str, Any]]) -> set:
        included = set()

        def _walk(directives):
            for d in directives:
                if not isinstance(d, dict):
                    continue
                for idx in d.get("includes", []):
                    included.add(idx)
                if "block" in d:
                    _walk(d["block"])

        for config in config_list:
            _walk(config.get("parsed", []))
        return included

    def scan(self, parser_output: Dict[str, Any]) -> List[Dict[str, Any]]:
        config_list = parser_output.get("config", [])

        # 0. Identify files that are included by others (already visited via include traversal)
        included_indices = self._collect_included_indices(config_list)

        all_remediations = []
        unique_remediations = set()

        # Start evaluation from root files only (skip included files)
        for f_idx, config in enumerate(config_list):
            if f_idx in included_indices:
                continue

            root_exact_path = ["config", f_idx, "parsed"]
            root_dirs = list(self._get_directives_at_level(config.get("parsed", []), root_exact_path, config_list))

            # Build AST Tree for this root file
            root_node = self._build_tree("main", root_dirs, root_exact_path, f_idx, config_list)

            # Traverse and remediate
            self._traverse_and_remediate(root_node, False, [], config_list, all_remediations, unique_remediations)

        return self._group_by_file(all_remediations)
