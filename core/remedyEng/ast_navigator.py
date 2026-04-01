"""Utilities for navigating and modifying Nginx AST structures based on context paths."""

from __future__ import annotations

import copy
from typing import Any, List, Union


class ASTNavigator:
    """Navigate and modify Nginx AST structures using context paths."""

    @staticmethod
    def get_by_context(data: Any, context: List[Union[str, int]]) -> Any:
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
    def set_by_context(data: Any, context: List[Union[str, int]], value: Any) -> bool:
        """
        Set a value at a specific location in the AST using a context path.
        
        Args:
            data: The root AST data structure
            context: List of keys/indices to navigate
            value: The value to set
        
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
            current[last_key] = copy.deepcopy(value)
            return True
        else:
            if not isinstance(current, dict):
                return False
            current[last_key] = copy.deepcopy(value)
            return True

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
        target = ASTNavigator.get_by_context(data, context)
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
        target = ASTNavigator.get_by_context(data, context)
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
            if not isinstance(current, dict) and last_key in current:
                return False
            del current[last_key]
            return True
