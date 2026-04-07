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

    child_scan_result: Any = {} #File-grouped remediations: {file_path: [remediations]}
    child_ast_config: Any = {} #File-grouped AST configs: {file_path: {parsed: [...]}}
    child_ast_modified: Any = {} #File-grouped modified configs: {file_path: {parsed: [...]}}


    def __init__(self, recommendation: Recommendation | None = None) -> None:
        self.id = "0.0.0"
        self.title = "Base Remediation Title"
        self.description = "Base Remediation Description"
        self.audit_procedure = "Base Remediation Audit Procedure"
        self.impact = "Base Remediation Impact"
        self.remediation = "Base Remediation Remediation"
        
        # Initialize file-grouped data structures
        self.child_scan_result = {}
        self.child_ast_config = {}
        self.child_ast_modified = {}

        if recommendation is not None:
            self.id = recommendation.id.value
            self.title = recommendation.title
            self.description = recommendation.description
            self.audit_procedure = recommendation.audit_procedure
            self.impact = recommendation.impact
            self.remediation = recommendation.remediation_procedure

    def read_child_scan_result(self, scan_result: Any) -> None:
        """
        Extract all violations for this rule from scan_result, grouped by file.
        
        Populates: self.child_scan_result = {file_path: [remediations]}
        where each remediation has: {action, context, directive, [args], [block]}
        
        Args:
            scan_result: Full scan_result.json data
        """
        rule_id = self.id
        result = ASTEditor.to_context_scan(
            scan_result=scan_result,
            rule_id=rule_id
        )
        self.child_scan_result = result  # Dict: {file_path: [remediations]}

    def read_child_ast_config(self, ast_config: Any) -> None:
        """
        Extract AST sections for all files that have violations.
        
        For each file in child_scan_result:
        1. Find the file entry in ast_config["config"] array
        2. Extract its "parsed" section (the actual AST)
        3. Store in child_ast_config[file_path] = {parsed: [...]}
        
        Populates: self.child_ast_config = {file_path: {parsed: [...]}}
        
        Args:
            ast_config: Full parser_output.json (ast_config["config"] array)
        """
        self.child_ast_config = {}
        
        if not isinstance(self.child_scan_result, dict) or not self.child_scan_result:
            return
        
        if not isinstance(ast_config, dict):
            return
        
        # For each file that has violations
        for file_path in self.child_scan_result.keys():
            # Find the file in ast_config["config"] array
            file_index = ASTEditor._find_file_in_config(ast_config, file_path)
            
            if file_index == -1:
                # File not found, skip it
                continue
            
            # Extract the config entry for this file
            config_list = ast_config.get("config", [])
            if not isinstance(config_list, list) or file_index >= len(config_list):
                continue
            
            file_entry = config_list[file_index]
            if not isinstance(file_entry, dict):
                continue
            
            # Store the parsed section for this file
            parsed = file_entry.get("parsed")
            if parsed is not None:
                self.child_ast_config[file_path] = {
                    "parsed": copy.deepcopy(parsed)
                }


    def remediate(self) -> None:
        """
        Main method to apply remediation. Override in child classes.
        
        Flow:
        1. Access self.child_ast_config = {file_path: {parsed: [...]}}
        2. Access self.child_scan_result = {file_path: [remediations]}
        3. Access self.user_inputs[] (if has_input=True)
        4. For each file:
           - Get remediations from child_scan_result[file_path]
           - Get parsed AST from child_ast_config[file_path]["parsed"]
           - Apply mutations using ASTEditor methods
           - Deep copy modified parsed to child_ast_modified[file_path]
        5. Populate: self.child_ast_modified = {file_path: {parsed: [...modified...]}}
        
        Available data:
        - self.child_scan_result: {file => [{action, context, directive, args?, block?}]}
        - self.child_ast_config: {file => {parsed: [AST nodes]}}
        - self.user_inputs: List of user-provided inputs (if has_input=True)
        
        Returns: None (modifies self.child_ast_modified in place)
        """
        # Override in child classes
        
        
        

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
