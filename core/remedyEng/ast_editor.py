"""Utilities for navigating and modifying Nginx AST structures based on context paths."""

from __future__ import annotations

import copy
import json
import re
import shlex
from typing import Any, Dict, List, Union

import crossplane
from core.remedyEng.debug_logger import info as debug_info, verbose as debug_verbose, trace as debug_trace, enabled as debug_enabled


class ASTEditor:
    """Navigate and modify Nginx AST structures using context paths."""

    @staticmethod
    def _normalize_action(action: Any) -> str:
        """Normalize scanner action keywords to remediation engine vocabulary."""
        if not isinstance(action, str):
            return ""

        normalized = action.strip().lower()
        if normalized == "modify":
            return "replace"
        return normalized

    @staticmethod
    def _extract_context_path(remediation: Dict[str, Any]) -> List[Union[str, int]]:
        """Extract exact context path from supported remediation context variants."""
        context = remediation.get("context")
        if isinstance(context, list):
            return context

        if isinstance(context, dict):
            exact_path = context.get("exact_path")
            if isinstance(exact_path, list):
                return exact_path

        top_level_exact = remediation.get("exact_path")
        if isinstance(top_level_exact, list):
            return top_level_exact

        return []

    @staticmethod
    def _extract_logical_context(remediation: Dict[str, Any]) -> str:
        """Extract logical context hint (e.g. http/server) if available."""
        logical_context = remediation.get("logical_context")
        if isinstance(logical_context, str):
            return logical_context.strip().lower()

        if isinstance(logical_context, list) and logical_context:
            first = logical_context[0]
            if isinstance(first, str):
                return first.strip().lower()

        context = remediation.get("context")
        if isinstance(context, str):
            return context.strip().lower()

        if isinstance(context, dict):
            logical = context.get("logical_context")
            if isinstance(logical, list) and logical:
                first = logical[0]
                if isinstance(first, str):
                    return first.strip().lower()

        return ""

    @staticmethod
    def _split_value_as_args(value: Any) -> List[str]:
        """Split scanner value field into nginx directive args safely."""
        if not isinstance(value, str):
            return []

        stripped = value.strip()
        if not stripped:
            return []

        try:
            return shlex.split(stripped)
        except ValueError:
            return stripped.split()

    @staticmethod
    def _parse_location_block_from_value(value: Any) -> Dict[str, Any]:
        """Parse simple location block string into args/block payload."""
        if not isinstance(value, str):
            return {}

        text = value.strip()
        if not text:
            return {}

        match = re.match(r"^location\s+(.+?)\s*\{(.*)\}\s*$", text, flags=re.DOTALL)
        if not match:
            return {}

        args_part = match.group(1).strip()
        block_part = match.group(2).strip()

        # Keep nginx regex escapes (e.g. /\\.) intact for location patterns.
        args = args_part.split()

        if not args:
            return {}

        block: List[Dict[str, Any]] = []
        for raw_line in block_part.splitlines():
            line = raw_line.strip().rstrip(";")
            if not line:
                continue

            try:
                tokens = shlex.split(line)
            except ValueError:
                tokens = line.split()

            if not tokens:
                continue

            block.append({"directive": tokens[0], "args": tokens[1:]})

        return {"args": args, "block": block}

    @staticmethod
    def _build_normalized_remediation(remediation: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize scanner remediation payload to engine-internal shape."""
        action = ASTEditor._normalize_action(remediation.get("action", ""))
        directive = remediation.get("directive", "")
        if not isinstance(directive, str):
            directive = ""

        context_path = ASTEditor._extract_context_path(remediation)
        logical_context = ASTEditor._extract_logical_context(remediation)

        normalized: Dict[str, Any] = {
            "action": action,
            "context": context_path,
            "exact_path": context_path,
            "directive": directive,
        }

        if logical_context:
            normalized["logical_context"] = logical_context

        if "args" in remediation:
            normalized["args"] = remediation.get("args")

        if "block" in remediation:
            normalized["block"] = remediation.get("block")

        if "value" in remediation:
            normalized["value"] = remediation.get("value")

        if "config" in remediation:
            normalized["config"] = remediation.get("config")

        if action == "add" and directive in {"server", "location"} and isinstance(remediation.get("block"), list):
            normalized["action"] = "add_block"

        if directive == "error_page" and "args" not in normalized:
            parsed_args = ASTEditor._split_value_as_args(remediation.get("value"))
            if parsed_args:
                normalized["args"] = parsed_args

        if directive == "return" and "args" not in normalized:
            parsed_args = ASTEditor._split_value_as_args(remediation.get("value"))
            if parsed_args:
                normalized["args"] = parsed_args

        if directive == "server_tokens" and "args" not in normalized:
            parsed_args = ASTEditor._split_value_as_args(remediation.get("value"))
            if parsed_args:
                normalized["args"] = parsed_args

        if directive == "server" and action == "add":
            # Scanner 2221 encodes full server block creation as action=add + config string.
            # Map it to add_block so existing handler path can consume it.
            normalized["action"] = "add_block"

        if directive == "location" and action == "add_block" and "args" not in normalized:
            parsed_location = ASTEditor._parse_location_block_from_value(remediation.get("value"))
            if parsed_location:
                normalized.update(parsed_location)

        return normalized
    
    @staticmethod
    def _normalize_file_path(file_path: str) -> str:
        """
        Normalize file paths for comparison.
        Handles: ./path, path, /path, and normalizes slashes.
        
        Args:
            file_path: File path to normalize
            
        Returns:
            Normalized path (lowercase, no leading ./, forward slashes)
        """
        if not isinstance(file_path, str):
            return ""
        
        normalized = file_path.strip()
        # Remove leading ./
        if normalized.startswith("./"):
            normalized = normalized[2:]
        # Remove leading /
        if normalized.startswith("/"):
            normalized = normalized[1:]
        # Normalize slashes
        normalized = normalized.replace("\\", "/")
        # Lowercase for comparison
        normalized = normalized.lower()
        return normalized

    @staticmethod
    def to_context_scan(scan_result: Dict, rule_id: str) -> Dict[str, List[Dict]]:
        """
        Return all remediations grouped by file for the given rule id.
        
        Returns a dict mapping file paths to lists of remediations for that file.
        Each remediation includes: action, context, directive, args (if present).

        Expected scan_result shape:
        scan_result -> recommendations[] -> uncompliances[] -> remediations[] -> context[]
        
        Returns:
            {
              "file_path1": [
                {"action": "delete", "context": [...], "directive": "listen"},
                {"action": "delete", "context": [...], "directive": "listen"}
              ],
              "file_path2": [
                {"action": "replace", "context": [...], "directive": "server_tokens", "args": ["off"]}
              ]
            }
            or empty dict {} if rule not found
        """
        result: Dict[str, List[Dict]] = {}
        
        if not isinstance(scan_result, dict) or not isinstance(rule_id, str):
            return result

        normalized_rule_id = rule_id.strip()
        if normalized_rule_id.startswith("CIS_"):
            normalized_rule_id = normalized_rule_id.replace("CIS_", "", 1).replace("_", ".")

        recommendations = scan_result.get("recommendations", [])
        if not isinstance(recommendations, list):
            return result

        for recommendation in recommendations:
            if not isinstance(recommendation, dict):
                continue

            recommendation_id = recommendation.get("id")
            if recommendation_id != normalized_rule_id:
                continue

            uncompliances = recommendation.get("uncompliances", [])
            if not isinstance(uncompliances, list):
                return result

            # Process each uncompliance (file)
            for uncompliance in uncompliances:
                if not isinstance(uncompliance, dict):
                    continue

                file_path = uncompliance.get("file")
                if not file_path:
                    continue

                remediations = uncompliance.get("remediations", [])
                if not isinstance(remediations, list):
                    continue

                # Collect all remediations for this file
                file_remediations = []
                for remediation in remediations:
                    if not isinstance(remediation, dict):
                        continue

                    remediation_dict = ASTEditor._build_normalized_remediation(remediation)
                    if not remediation_dict.get("directive"):
                        continue

                    file_remediations.append(remediation_dict)

                if file_remediations:
                    result[file_path] = file_remediations

            return result

        return result

    @staticmethod
    def _find_file_in_config(ast_config: Dict, file_path: str) -> int:
        """
        Find the index of a file in ast_config["config"] array.
        Uses normalized path comparison for flexibility.
        
        Args:
            ast_config: The full AST config (parser output)
            file_path: File path to search for
            
        Returns:
            Index of the matching config entry, or -1 if not found
        """
        if not isinstance(ast_config, dict):
            return -1
        
        config_list = ast_config.get("config", [])
        if not isinstance(config_list, list):
            return -1
        
        normalized_search = ASTEditor._normalize_file_path(file_path)
        if debug_enabled():
            debug_verbose("BLOCK_MATCH", f"Searching for file '{file_path}' -> normalized '{normalized_search}'")
        if not normalized_search:
            return -1
        
        for index, config_entry in enumerate(config_list):
            if not isinstance(config_entry, dict):
                continue
            
            entry_file = config_entry.get("file", "")
            normalized_entry = ASTEditor._normalize_file_path(entry_file)
            
            if normalized_entry == normalized_search:
                if debug_enabled():
                    debug_info("BLOCK_MATCH", f"Found file '{entry_file}' at index {index}", {"search": normalized_search, "entry": normalized_entry})
                return index
        
        return -1

    @staticmethod
    def path_is_valid(data: Any, path: List[Union[str, int]]) -> bool:
        """Return True if path exists in AST, or ends at valid append index (index == len(list))."""
        if not isinstance(path, list) or not path:
            return False
        current = data
        for index, key in enumerate(path):
            if isinstance(key, int):
                if not isinstance(current, list):
                    return False
                if key > len(current):
                    return False
                if key == len(current):
                    return index == len(path) - 1
                current = current[key]
            else:
                if not isinstance(current, dict) or key not in current:
                    return False
                current = current[key]
        return True

    @staticmethod
    def get_child_ast_config(data: Any, context: List[Union[str, int]]) -> Any:
        """
        Navigate to a specific location in the AST using a context path.
        
        Args:
            data: The root AST data structure
            context: List of keys/indices to navigate (e.g., ["config", 0, "parsed", 5, "block", 2])
        
        Returns:
            The value at the specified context path, or None if not found.
        """
        current = data
        for key in context:
            if isinstance(key, int):
                if not isinstance(current, list) or key >= len(current):
                    return None
                current = current[key]
            else:
                if not isinstance(current, dict) or key not in current:
                    return None
                current = current[key]
        return current


    @staticmethod
    def append_to_context(data: Any, context: List[Union[str, int]], item: Any) -> bool:
        """
        Append an item to a list at a specific context location.
        
        Args:
            data: The root AST data structure
            context: List of keys/indices to navigate to the list
            item: The item to append
        
        Returns:
            True if successful, False otherwise.
        """
        target = ASTEditor.get_child_ast_config(data, context)
        if not isinstance(target, list):
            return False
        
        target.append(copy.deepcopy(item))
        return True

    @staticmethod
    def insert_to_context(data: Any, context: List[Union[str, int]], index: int, item: Any) -> bool:
        """
        Insert an item to a list at a specific context location and index.
        
        Args:
            data: The root AST data structure
            context: List of keys/indices to navigate to the list
            index: Index to insert at
            item: The item to insert
        
        Returns:
            True if successful, False otherwise.
        """
        target = ASTEditor.get_child_ast_config(data, context)
        if not isinstance(target, list) or index < 0 or index > len(target):
            return False
        
        target.insert(index, copy.deepcopy(item))
        return True

    @staticmethod
    def remove_by_context(data: Any, context: List[Union[str, int]]) -> bool:
        """
        Remove an item at a specific context location.
        
        Args:
            data: The root AST data structure
            context: List of keys/indices to navigate
        
        Returns:
            True if successful, False otherwise.
        """
        if not context:
            return False

        current = data
        for key in context[:-1]:
            if isinstance(key, int):
                if not isinstance(current, list) or key >= len(current):
                    return False
                current = current[key]
            else:
                if not isinstance(current, dict) or key not in current:
                    return False
                current = current[key]

        last_key = context[-1]
        if isinstance(last_key, int):
            if not isinstance(current, list) or last_key >= len(current):
                return False
            del current[last_key]
            return True
        else:
            if not isinstance(current, dict) or last_key not in current:
                return False
            del current[last_key]
            return True

    @staticmethod
    def ast_to_config_text(parsed_ast: Any, indent_spaces: int = 4) -> str:
        """Render a parsed AST list to nginx config text."""
        if not isinstance(parsed_ast, list):
            return ""

        try:
            return crossplane.build(parsed_ast, indent=indent_spaces, tabs=False)
        except Exception:
            return ""

    @staticmethod
    def ast_to_json_text(ast_data: Any) -> str:
        """Render AST data to stable JSON text for diff fallback."""
        return json.dumps(ast_data, indent=2, sort_keys=True)

    @staticmethod
    def _build_patch_node(patch: Dict[str, Any]) -> Dict[str, Any]:
        node: Dict[str, Any] = {}

        directive = patch.get("directive")
        if isinstance(directive, str) and directive:
            node["directive"] = directive

        if "args" in patch:
            args = patch.get("args")
            node["args"] = copy.deepcopy(args) if isinstance(args, list) else []

        if "block" in patch and isinstance(patch.get("block"), list):
            node["block"] = copy.deepcopy(patch.get("block"))

        if "config" in patch:
            node["config"] = copy.deepcopy(patch.get("config"))

        return node

    @staticmethod
    def _patch_dedupe_key(patch: Dict[str, Any]) -> tuple:
        """Stable key for conflict resolution: same path may host multiple sibling directives.

        When ``_rule_id`` is set (multi-rule batch merge), the key is scoped per rule so
        distinct CIS rules never drop each other's patches solely because they target the
        same structural tuple.
        """
        ep = tuple(patch.get("exact_path") or ())
        directive = str(patch.get("directive") or "")
        args = patch.get("args")
        args_key = tuple(args) if isinstance(args, list) else ()
        action = str(patch.get("action") or "")
        block_val = patch.get("block")
        if isinstance(block_val, (dict, list)):
            block_sig = json.dumps(block_val, sort_keys=True)
        elif block_val is None:
            block_sig = ""
        else:
            block_sig = str(block_val)
        base = (ep, directive, args_key, action, block_sig)
        rid = patch.get("_rule_id")
        if isinstance(rid, str) and rid:
            return (rid, base)
        return base

    @staticmethod
    def _path_sort_key(path: List[Union[str, int]]) -> tuple:
        signature = []
        for item in path:
            if isinstance(item, int):
                signature.append((0, item))
            else:
                signature.append((1, str(item)))
        return (len(path), tuple(signature))

    @staticmethod
    def _upsert_in_list(block_list: Any, directive: str, args: Any, block: Any = None) -> bool:
        if not isinstance(block_list, list) or not isinstance(directive, str) or not directive:
            return False

        replacement = {"directive": directive, "args": copy.deepcopy(args) if isinstance(args, list) else []}
        if isinstance(block, list):
            replacement["block"] = copy.deepcopy(block)

        # nginx may repeat allow lines; each trust network needs its own directive node.
        if directive == "allow":
            block_list.append(replacement)
            return True

        # Multiple error_page lines differ by status-code prefix; same prefix updates in place.
        if directive == "error_page" and isinstance(args, list) and len(args) >= 2:
            key = tuple(args[:-1])
            for item in block_list:
                if not isinstance(item, dict) or item.get("directive") != "error_page":
                    continue
                cur_args = item.get("args") or []
                if isinstance(cur_args, list) and len(cur_args) >= 2 and tuple(cur_args[:-1]) == key:
                    item.clear()
                    item.update(replacement)
                    return True
            block_list.append(replacement)
            return True

        if directive == "deny" and isinstance(args, list) and args == ["all"]:
            for i in range(len(block_list) - 1, -1, -1):
                item = block_list[i]
                if isinstance(item, dict) and item.get("directive") == "deny" and item.get("args") == ["all"]:
                    block_list.pop(i)
            block_list.append(replacement)
            return True

        # Match add_header by header name (args[0]); do not clobber other add_header lines.
        if directive == "add_header" and isinstance(args, list) and len(args) > 0:
            header_key = args[0]
            for item in block_list:
                if not isinstance(item, dict) or item.get("directive") != "add_header":
                    continue
                iargs = item.get("args") or []
                if len(iargs) > 0 and iargs[0] == header_key:
                    item.clear()
                    item.update(replacement)
                    return True
            block_list.append(replacement)
            return True

        if directive in {"proxy_set_header", "grpc_set_header"} and isinstance(args, list) and len(args) > 0:
            header_key = args[0]
            for item in block_list:
                if not isinstance(item, dict) or item.get("directive") != directive:
                    continue
                iargs = item.get("args") or []
                if len(iargs) > 0 and iargs[0] == header_key:
                    item.clear()
                    item.update(replacement)
                    return True
            block_list.append(replacement)
            return True

        if directive == "fastcgi_param" and isinstance(args, list) and len(args) > 0:
            param_key = args[0]
            for item in block_list:
                if not isinstance(item, dict) or item.get("directive") != "fastcgi_param":
                    continue
                iargs = item.get("args") or []
                if len(iargs) > 0 and iargs[0] == param_key:
                    item.clear()
                    item.update(replacement)
                    return True
            block_list.append(replacement)
            return True

        for item in block_list:
            if isinstance(item, dict) and item.get("directive") == directive:
                item.update(replacement)
                return True

        block_list.append(replacement)
        return True

    @staticmethod
    def _apply_patch(data: Any, patch: Dict[str, Any]) -> bool:
        exact_path = patch.get("exact_path")
        if not isinstance(exact_path, list) or not exact_path:
            return False

        action = ASTEditor._normalize_action(patch.get("action", ""))
        parent_path = exact_path[:-1]
        target_key = exact_path[-1]
        parent = ASTEditor.get_child_ast_config(data, parent_path) if parent_path else data
        target = ASTEditor.get_child_ast_config(data, exact_path)
        directive = patch.get("directive", "")
        args = patch.get("args", [])
        block = patch.get("block")

        if debug_enabled():
            debug_verbose("PATCH_PLAN", f"Applying patch action={action} exact_path={exact_path} directive={directive}", patch)

        if action == "delete":
            if isinstance(target_key, int) and isinstance(parent, list) and 0 <= target_key < len(parent):
                parent.pop(target_key)
                if debug_enabled():
                    debug_info("PATCH_APPLY", f"DELETE succeeded at {exact_path}", {"action": "delete", "exact_path": exact_path})
                return True
            if isinstance(parent, dict) and isinstance(target_key, str) and target_key in parent:
                del parent[target_key]
                if debug_enabled():
                    debug_info("PATCH_APPLY", f"DELETE succeeded at {exact_path}", {"action": "delete", "exact_path": exact_path})
                return True
            if debug_enabled():
                debug_info("PATCH_APPLY", f"DELETE failed at {exact_path}", {"reason": "target not found", "action": "delete", "exact_path": exact_path})
            return False

        if action in {"replace", "modify", "modify_directive"}:
            if isinstance(parent, list) and isinstance(target_key, int) and 0 <= target_key < len(parent):
                replacement = ASTEditor._build_patch_node(patch)
                if not replacement:
                    if debug_enabled():
                        debug_info("PATCH_APPLY", f"REPLACE failed (empty replacement) at {exact_path}", {"action": "replace", "exact_path": exact_path})
                    return False
                parent[target_key] = replacement
                if debug_enabled():
                    debug_info("PATCH_APPLY", f"REPLACE succeeded at {exact_path}", {"action": "replace", "exact_path": exact_path})
                return True

            if isinstance(target, dict):
                if isinstance(directive, str) and directive and target.get("directive") not in {directive, ""}:
                    return False
                if isinstance(directive, str) and directive:
                    target["directive"] = directive
                if isinstance(args, list):
                    target["args"] = copy.deepcopy(args)
                if isinstance(block, list):
                    target["block"] = copy.deepcopy(block)
                if debug_enabled():
                    debug_info("PATCH_APPLY", f"MODIFY succeeded at {exact_path}", {"action": action, "exact_path": exact_path})
                return True

            if isinstance(target, list) and isinstance(directive, str) and directive:
                return ASTEditor._upsert_in_list(target, directive, args, block)
            if debug_enabled():
                debug_info("PATCH_APPLY", f"REPLACE/MODIFY failed at {exact_path}", {"reason": "target mismatch or invalid", "action": action, "exact_path": exact_path})
            return False

        if action in {"upsert", "add", "add_directive"}:
            if (
                isinstance(parent, list)
                and isinstance(target_key, int)
                and target_key == len(parent)
                and target is None
            ):
                return ASTEditor._upsert_in_list(parent, directive, args, block)

            if isinstance(target, list):
                return ASTEditor._upsert_in_list(target, directive, args, block)

            if isinstance(target, dict):
                if isinstance(directive, str) and directive and target.get("directive") not in {directive, ""}:
                    return False
                if isinstance(args, list):
                    target["args"] = copy.deepcopy(args)
                if isinstance(block, list):
                    target["block"] = copy.deepcopy(block)
                return True

            if debug_enabled():
                debug_info("PATCH_APPLY", f"UPSERT/ADD failed at {exact_path}", {"action": action, "exact_path": exact_path})
            return False

        if action == "add_block":
            insert_list = ASTEditor.get_child_ast_config(data, exact_path)
            if isinstance(insert_list, list):
                inner = patch.get("block")
                if isinstance(inner, dict) and inner.get("directive"):
                    insert_list.append(copy.deepcopy(inner))
                    if debug_enabled():
                        debug_info("PATCH_APPLY", f"ADD_BLOCK succeeded at {exact_path}", {"action": "add_block", "exact_path": exact_path})
                    return True
                node = ASTEditor._build_patch_node(patch)
                if node.get("directive"):
                    insert_list.append(node)
                    if debug_enabled():
                        debug_info("PATCH_APPLY", f"ADD_BLOCK succeeded at {exact_path}", {"action": "add_block", "exact_path": exact_path})
                    return True
            if debug_enabled():
                debug_info("PATCH_APPLY", f"ADD_BLOCK failed at {exact_path}", {"action": "add_block", "exact_path": exact_path})
            return False

        if action == "append":
            if isinstance(target, list):
                target.append(ASTEditor._build_patch_node(patch))
                return True
            if isinstance(parent, list):
                parent.append(ASTEditor._build_patch_node(patch))
                return True
            if debug_enabled():
                debug_info("PATCH_APPLY", f"APPEND failed at {exact_path}", {"action": "append", "exact_path": exact_path})
            return False

        if action == "insert_at":
            insert_list = ASTEditor.get_child_ast_config(data, exact_path)
            try:
                insert_index = int(patch.get("index", 0))
            except (TypeError, ValueError):
                insert_index = 0
            node = patch.get("block")
            if isinstance(node, dict) and node.get("directive"):
                inner = copy.deepcopy(node)
            else:
                inner = ASTEditor._build_patch_node(patch)
            if isinstance(insert_list, list) and isinstance(inner, dict) and inner.get("directive"):
                idx = max(0, min(insert_index, len(insert_list)))
                insert_list.insert(idx, inner)
                if debug_enabled():
                    debug_info("PATCH_APPLY", f"INSERT_AT succeeded at {exact_path} idx={idx}", patch)
                return True
            if debug_enabled():
                debug_info("PATCH_APPLY", f"INSERT_AT failed at {exact_path}", patch)
            return False

        if action == "insert_after":
            if isinstance(parent, list) and isinstance(target_key, int):
                insert_index = min(target_key + 1, len(parent))
                parent.insert(insert_index, ASTEditor._build_patch_node(patch))
                return True
            if debug_enabled():
                debug_info("PATCH_APPLY", f"INSERT_AFTER failed at {exact_path}", {"action": "insert_after", "exact_path": exact_path})
            return False

        if debug_enabled():
            debug_info("PATCH_APPLY", f"Unknown action {action} at {exact_path}", {"action": action, "exact_path": exact_path})
        return False

    @staticmethod
    def apply_reverse_path_patches(
        ast_data: Any,
        patches: Any,
        *,
        dedupe: bool = True,
    ) -> Any:
        """Apply patch list with reverse-path ordering.

        When dedupe=True (default), patches sharing the same _patch_dedupe_key collapse
        and only the highest (priority, _order) is kept (single-rule remediation).

        When dedupe=False, every normalized patch is applied — required when merging
        patch lists from multiple CIS rules against one baseline AST, since distinct
        remediations can legitimately reuse the same key (e.g. sibling directives).
        """
        if not isinstance(ast_data, list) or not isinstance(patches, list):
            return copy.deepcopy(ast_data)

        normalized_patches: List[Dict[str, Any]] = []
        for index, patch in enumerate(patches):
            if not isinstance(patch, dict):
                continue

            exact_path = ASTEditor._extract_context_path(patch)
            if not exact_path:
                continue

            try:
                priority_value = int(patch.get("priority", 0))
            except (TypeError, ValueError):
                priority_value = 0

            normalized = copy.deepcopy(patch)
            normalized["action"] = ASTEditor._normalize_action(normalized.get("action", ""))
            normalized["exact_path"] = exact_path
            normalized["priority"] = priority_value
            normalized["_order"] = index
            normalized_patches.append(normalized)

        if debug_enabled():
            debug_verbose("PATCH_PLAN", f"Normalized patches count: {len(normalized_patches)}")
        if dedupe:
            selected: Dict[tuple, Dict[str, Any]] = {}
            for patch in normalized_patches:
                key = ASTEditor._patch_dedupe_key(patch)
                current = selected.get(key)
                if current is None:
                    selected[key] = patch
                    continue

                current_rank = (current.get("priority", 0), current.get("_order", -1))
                new_rank = (patch.get("priority", 0), patch.get("_order", -1))
                if new_rank >= current_rank:
                    selected[key] = patch

            apply_candidates = list(selected.values())
        else:
            apply_candidates = normalized_patches

        working = copy.deepcopy(ast_data)

        # Phase 1: Identify replace patches that would overwrite deeper patches.
        # These must apply FIRST so deeper patches can modify the replaced result.
        def _is_prefix_of(shorter, longer):
            """Check if shorter path is a strict prefix of longer path."""
            if len(shorter) >= len(longer):
                return False
            return list(longer[:len(shorter)]) == list(shorter)

        all_paths = [tuple(p["exact_path"]) for p in apply_candidates]
        shallow_replaces = []
        remaining = []
        for p in apply_candidates:
            path = tuple(p["exact_path"])
            # Only promote structural server/http block replaces to phase 1.
            # Location-level replaces should use normal deepest-first ordering.
            is_structural = p.get("directive") in {"server", "http", ""}
            if (p.get("action") == "replace" and is_structural
                    and any(_is_prefix_of(path, other) for other in all_paths)):
                shallow_replaces.append(p)
            else:
                remaining.append(p)

        # Apply shallow replaces first (shallowest first)
        if shallow_replaces:
            shallow_replaces.sort(
                key=lambda item: (ASTEditor._path_sort_key(item["exact_path"]), item.get("priority", 0)),
            )
            for patch in shallow_replaces:
                if debug_enabled():
                    debug_trace("PATCH_APPLY", "Applying shallow replace (phase 1)", patch)
                ASTEditor._apply_patch(working, patch)

        # Phase 2: All other patches in standard reverse-path order
        ordered_patches = sorted(
            remaining,
            key=lambda item: (ASTEditor._path_sort_key(item["exact_path"]), item.get("priority", 0), item.get("_order", 0)),
            reverse=True,
        )

        if debug_enabled():
            debug_verbose("PATCH_PLAN", f"Selected patches count: {len(ordered_patches)} + {len(shallow_replaces)} shallow replaces; ordering will be applied in reverse-path order")
            try:
                keys = [p.get("exact_path") for p in ordered_patches]
                debug_trace("PATCH_PLAN", f"Ordered exact_paths: {keys}")
            except Exception:
                pass

        for patch in ordered_patches:
            if debug_enabled():
                debug_trace("PATCH_APPLY", f"Applying ordered patch", patch)
            ASTEditor._apply_patch(working, patch)

        return working


    # @staticmethod
    # def set_by_context(data: Any, context: List[Union[str, int]], value: Any) -> bool:
    #     """
    #     Set a value at a specific location in the AST using a context path.
        
    #     Args:
    #         data: The root AST data structure
    #         context: List of keys/indices to navigate
    #         value: The value to set
        
    #     Returns:
    #         True if successful, False otherwise.
    #     """
    #     if not context:
    #         return False

    #     current = data
    #     for key in context[:-1]:
    #         if isinstance(key, int):
    #             if not isinstance(current, list) or key >= len(current):
    #                 return False
    #             current = current[key]
    #         else:
    #             if not isinstance(current, dict) or key not in current:
    #                 return False
    #             current = current[key]

    #     last_key = context[-1]
    #     if isinstance(last_key, int):
    #         if not isinstance(current, list) or last_key >= len(current):
    #             return False
    #         current[last_key] = copy.deepcopy(value)
    #         return True
    #     else:
    #         if not isinstance(current, dict):
    #             return False
    #         current[last_key] = copy.deepcopy(value)
    #         return True