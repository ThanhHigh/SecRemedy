from core.recom_registry import RECOMMENDATION_REGISTRY, RecomID
from core.remedyEng.base_remedy import BaseRemedy
from core.remedyEng.ast_editor import ASTEditor
import copy

REMEDY_FIX_EXAMPLE = ""
REMEDY_INPUT_REQUIRE = []


class Remediate251(BaseRemedy):
    def __init__(self) -> None:
        super().__init__(RECOMMENDATION_REGISTRY[RecomID.CIS_2_5_1])
        self.has_input = False
        self.has_guide_detail = False
        self.remedy_guide_detail = REMEDY_FIX_EXAMPLE
        self.remedy_input_require = REMEDY_INPUT_REQUIRE

    def remediate(self) -> None:
        """
        Apply remediation for Rule 2.5.1: Ensure server_tokens directive is set to off.
        
        Action: REPLACE - Sets server_tokens args to ["off"]
        """
        self.child_ast_modified = {}
        
        # Process each file that has violations
        for file_path, remediations in self.child_ast_config.items():
            if file_path not in self.child_scan_result:
                continue
            
            if not isinstance(remediations, dict) or "parsed" not in remediations:
                continue
            
            # Deep copy the parsed section for modification
            parsed_copy = copy.deepcopy(remediations["parsed"])
            
            # Get violations for this file
            file_violations = self.child_scan_result[file_path]
            if not isinstance(file_violations, list):
                continue
            
            # Apply each violation fix
            for violation in file_violations:
                if not isinstance(violation, dict):
                    continue
                
                action = violation.get("action", "")
                context = violation.get("context", [])
                directive = violation.get("directive", "")
                args = violation.get("args", [])
                
                # For rule 2.5.1, we expect action="replace"
                if action != "replace" or directive != "server_tokens":
                    continue
                
                # Convert context to relative path within this file
                # Original context: ["config", 0, "parsed", N, ...]
                # We need: [N, ...] (relative to parsed)
                relative_context = self._get_relative_context(context)
                if not relative_context:
                    continue
                
                # Navigate to the target and modify
                target = ASTEditor.get_child_ast_config(parsed_copy, relative_context)
                if target and isinstance(target, dict) and target.get("directive") == "server_tokens":
                    target["args"] = copy.deepcopy(args)
            
            # Store modified config
            self.child_ast_modified[file_path] = {
                "parsed": parsed_copy
            }
    
    @staticmethod
    def _get_relative_context(full_context):
        """
        Convert full context path to relative context within parsed section.
        
        Full context: ["config", 0, "parsed", 5, "block", 2]
        Relative context: [5, "block", 2]
        """
        if not isinstance(full_context, list):
            return []
        
        # Find "parsed" key in context
        try:
            parsed_index = full_context.index("parsed")
            # Return everything after "parsed"
            return full_context[parsed_index + 1:]
        except (ValueError, IndexError):
            return []
