from core.recom_registry import RECOMMENDATION_REGISTRY, RecomID
from core.remedyEng.base_remedy import BaseRemedy
from core.remedyEng.ast_editor import ASTEditor
import copy

REMEDY_FIX_EXAMPLE = "server {\n\n    # Standard HTTPS (TCP)\n    listen 443 ssl;\n\n    # HTTP/3 (UDP)\n    listen 443 quic reuseport;\n\n    # ... SSL/TLS configuration ...\n}"
REMEDY_INPUT_REQUIRE = []

class Remediate241(BaseRemedy):
    def __init__(self) -> None:
        super().__init__(RECOMMENDATION_REGISTRY[RecomID.CIS_2_4_1])
        self.has_input = False
        self.has_guide_detail = True
        self.remedy_guide_detail = REMEDY_FIX_EXAMPLE
        self.remedy_input_require = REMEDY_INPUT_REQUIRE

    def remediate(self) -> None:
        """
        Apply remediation for Rule 2.4.1: Ensure NGINX only listens on authorized ports.
        
        Action: DELETE - Removes unauthorized listen directives.
        Note: May have multiple violations per file.
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
            
            # Apply each violation fix (may be multiple deletes per file)
            # Important: Process in reverse order of context depth to avoid index shifting
            deletions_applied = []
            for violation in file_violations:
                if not isinstance(violation, dict):
                    continue
                
                action = violation.get("action", "")
                context = violation.get("context", [])
                directive = violation.get("directive", "")
                
                # For rule 2.4.1, we expect action="delete"
                if action != "delete" or directive != "listen":
                    continue
                
                # Convert context to relative path within this file
                relative_context = self._get_relative_context(context)
                if not relative_context:
                    continue
                
                # Use ASTEditor to remove the item at this path
                success = ASTEditor.remove_by_context(parsed_copy, relative_context)
                if success:
                    deletions_applied.append(relative_context)
            
            # Store modified config only if changes were made
            self.child_ast_modified[file_path] = {
                "parsed": parsed_copy
            }
    
    @staticmethod
    def _get_relative_context(full_context):
        """
        Convert full context path to relative context within parsed section.
        
        Full context: ["config", 0, "parsed", 5, "block", 1]
        Relative context: [5, "block", 1]
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
