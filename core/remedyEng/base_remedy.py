from __future__ import annotations

import copy
import difflib
import json
from abc import ABC, abstractmethod
from typing import Any, List

from core.recom_registry import Recommendation
from core.remedyEng.ast_editor import ASTEditor

class BaseRemedy:
    """Base class for all remedies. """
    id: str
    title: str
    description: str
    audit_procedure: str
    impact: str
    remediation: str

    has_guide_detail: bool = True
    remedy_guide_detail: str = ""

    user_pre_decision: bool = True #Apply the remedy or not before apply diff
    user_final_desision: bool = True #Apply the remedy or not after apply diff 

    has_input: bool = False
    remedy_input_require: List[str] = []
    user_inputs: List[Any] = []

    child_scan_result: Any = None #Locator for Child AST config
    child_ast_config: Any = None
    child_ast_modified: Any = None


    def __init__(self, recommendation: Recommendation | None = None) -> None:
        self.id = "0.0.0"
        self.title = "Base Remediation Title"
        self.description = "Base Remediation Description"
        self.audit_procedure = "Base Remediation Audit Procedure"
        self.impact = "Base Remediation Impact"
        self.remediation = "Base Remediation Remediation"

        if recommendation is not None:
            self.id = recommendation.id.value
            self.title = recommendation.title
            self.description = recommendation.description
            self.audit_procedure = recommendation.audit_procedure
            self.impact = recommendation.impact
            self.remediation = recommendation.remediation_procedure

    def read_child_scan_result(self, scan_result: Any) -> None:
        """Get the specific uncompliance entry from scan_result.json that this remedy addresses."""
        # This is a placeholder implementation. Subclasses should override this method.
        rule_id = self.id
        result = ASTEditor.to_context_scan(
            scan_result= scan_result,
            rule_id= rule_id
        )
        self.child_scan_result = result

    def read_child_ast_config(self, ast_config: Any) -> None:
        """Get the AST of the config file to be remediated."""
        # This is a placeholder implementation. Subclasses should override this method.
        if self.child_scan_result is not None:
            self.child_ast_config = ASTEditor.get_child_ast_config(
                data= ast_config,
                context= self.child_scan_result
            )


    def remediate(self) -> Any:
        """
        Main method to apply remediation.
        Args:
            scan_result: The specific uncompliance entry from scan_result.json that this remedy addresses.
            ast_config: The AST of the config file to be remediated.
        Returns:
            A remediated AST config JSON for this rule.
        """
        # This is a placeholder implementation. Subclasses should override this method.
        
        

    def interact_with_user(self) -> None:
        """Prompt user for any required variables before remediation."""
        pass


    



























    # @abstractmethod
    # def impact_warning(self, config_json: Any) -> bool:
    #     """Return True when this rule is violated."""

    # @abstractmethod
    # def remediate(self, config_json: Any) -> Any:
    #     """Return a remediated config JSON for this rule."""

    # @abstractmethod
    # def interact_with_user(self) -> None:
    #     """Prompt user for any required variables before remediation."""

    # def snapshot(self, before_state: Any, after_state: Any) -> None:
    #     """Store deep-copied snapshots for safe dry-run and diff generation."""
    #     self._before_state = copy.deepcopy(before_state)
    #     self._after_state = copy.deepcopy(after_state)

    # def get_diff(self) -> str:
    #     """Generate a unified diff between pre- and post-remediation states."""
    #     if self._before_state is None or self._after_state is None:
    #         return ""

    #     before_json = json.dumps(self._before_state, indent=2, ensure_ascii=False, sort_keys=True)
    #     after_json = json.dumps(self._after_state, indent=2, ensure_ascii=False, sort_keys=True)

    #     if before_json == after_json:
    #         return ""

    #     diff_lines = difflib.unified_diff(
    #         before_json.splitlines(),
    #         after_json.splitlines(),
    #         fromfile=f"before_{self.id}",
    #         tofile=f"after_{self.id}",
    #         lineterm="",
    #     )
    #     return "\n".join(diff_lines)
