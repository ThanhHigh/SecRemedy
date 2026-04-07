"""Utilities for navigating and modifying Nginx AST structures based on context paths."""

from __future__ import annotations

import copy
from typing import Any, Dict, List, Union


class ASTEditor:
    """Navigate and modify Nginx AST structures using context paths."""
    
    @staticmethod
    def to_context_scan(scan_result: Dict, rule_id: str) -> List[Union[str, int]]:
        """Return the first remediation context path for the given rule id.

        Expected scan_result shape:
        scan_result -> recommendations[] -> uncompliances[] -> remediations[] -> context[]
        """
        if not isinstance(scan_result, dict) or not isinstance(rule_id, str):
            return []

        normalized_rule_id = rule_id.strip()
        if normalized_rule_id.startswith("CIS_"):
            normalized_rule_id = normalized_rule_id.replace("CIS_", "", 1).replace("_", ".")

        recommendations = scan_result.get("recommendations", [])
        if not isinstance(recommendations, list):
            return []

        for recommendation in recommendations:
            if not isinstance(recommendation, dict):
                continue

            recommendation_id = recommendation.get("id")
            if recommendation_id != normalized_rule_id:
                continue

            uncompliances = recommendation.get("uncompliances", [])
            if not isinstance(uncompliances, list):
                return []

            for uncompliance in uncompliances:
                if not isinstance(uncompliance, dict):
                    continue

                remediations = uncompliance.get("remediations", [])
                if not isinstance(remediations, list):
                    continue

                for remediation in remediations:
                    if not isinstance(remediation, dict):
                        continue

                    context = remediation.get("context")
                    if isinstance(context, list):
                        return context

            return []

        return []


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