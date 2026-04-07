"""Utilities for navigating and modifying Nginx AST structures based on context paths."""

from __future__ import annotations

import copy
from typing import Any, Dict, List, Union


class ASTEditor:
    """Navigate and modify Nginx AST structures using context paths."""
    
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

                    context = remediation.get("context")
                    if not isinstance(context, list):
                        continue

                    # Build remediation dict with all relevant fields
                    remediation_dict = {
                        "action": remediation.get("action", ""),
                        "context": context,
                        "directive": remediation.get("directive", "")
                    }
                    
                    # Include optional fields
                    if "args" in remediation:
                        remediation_dict["args"] = remediation.get("args")
                    if "block" in remediation:
                        remediation_dict["block"] = remediation.get("block")

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
        if not normalized_search:
            return -1
        
        for index, config_entry in enumerate(config_list):
            if not isinstance(config_entry, dict):
                continue
            
            entry_file = config_entry.get("file", "")
            normalized_entry = ASTEditor._normalize_file_path(entry_file)
            
            if normalized_entry == normalized_search:
                return index
        
        return -1

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