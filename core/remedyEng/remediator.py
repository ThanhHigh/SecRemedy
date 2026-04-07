"""Handler for remediations defined in scan_result.json."""

from __future__ import annotations

import copy
import json
from typing import Any, Dict, List, Type
import argparse

from core.remedyEng.base_remedy import BaseRemedy
from core.recom_registry import RECOMMENDATION_REGISTRY, RecomID

from core.remedyEng.recommendations.remediate_241 import Remediate241
from core.remedyEng.recommendations.remediate_242 import Remediate242
from core.remedyEng.recommendations.remediate_251 import Remediate251
from core.remedyEng.recommendations.remediate_252 import Remediate252
from core.remedyEng.recommendations.remediate_253 import Remediate253
from core.remedyEng.recommendations.remediate_31 import Remediate31
from core.remedyEng.recommendations.remediate_32 import Remediate32
from core.remedyEng.recommendations.remediate_33 import Remediate33
from core.remedyEng.recommendations.remediate_34 import Remediate34
from core.remedyEng.recommendations.remediate_411 import Remediate411

from core.remedyEng.ast_editor import ASTEditor
from core.remedyEng.terminal_ui import TerminalUI

class Remediator:
    """Apply remediation through all Child Remedies base on Results, interact with User, Generate new AST """
    ast_config: dict = {}
    ast_scan: dict = {}

    


    # ---------------------------------------------------------------------------
    # Remediation Registry: tất cả Remediation class, mapped bằng RecomID (Enum)
    # ---------------------------------------------------------------------------
    REMEDIATION_REGISTRY: Dict[RecomID, Type[BaseRemedy]] = {
        RecomID.CIS_2_4_1: Remediate241,
        RecomID.CIS_2_4_2: Remediate242,
        RecomID.CIS_2_5_1: Remediate251,
        RecomID.CIS_2_5_2: Remediate252,
        RecomID.CIS_2_5_3: Remediate253,
        RecomID.CIS_3_1: Remediate31,
        RecomID.CIS_3_2: Remediate32,
        RecomID.CIS_3_3: Remediate33,
        RecomID.CIS_3_4: Remediate34,
        RecomID.CIS_4_1_1: Remediate411,
    }

    def __init__(self) -> None:
        pass

    def display_header(self) -> None:
        """Display a header for the remediation process."""
        TerminalUI.get_instance().display_remedy_header()

    def get_input_ast(self) -> None:
        """Get the File Names from user and return 2 ASTs """
        self.ast_config = TerminalUI.get_instance().get_ast_config()
        self.ast_scan = TerminalUI.get_instance().get_ast_scan()
        
    # For in Remediation Registry, each Remediate call the function TerminalUI of specific for that remediation, display information
    # Input for user if has, In TerminalUI wait for user input, get the information, start to apply Remediate as hard code
    # Each of output the difference between before and after, so to user agree or not, if agree write to new AST, if not then copy the old AST
    # Finally all the Loop get the new AST, check for syntax, if valid build them to new config files
    # if not valid, print the error and stop the process.

    def call_the_UI(self, remedy_cls: BaseRemedy) -> None:
        """Call the TerminalUI to display information and get user input if needed."""
        remedy = remedy_cls() # Instantiate the remedy class
        TerminalUI.get_instance().display_remedy_info(remedy)

    def call_UI_remedy_info(self) -> None:
        """Call the TerminalUI to display information for all remedies."""
        for remedy_cls in self.REMEDIATION_REGISTRY.values():
            if remedy_cls == self.REMEDIATION_REGISTRY[RecomID.CIS_2_4_1]:
                self.call_the_UI(remedy_cls)

    def call_user_TUI_input(self) -> None:
        """Call the TerminalUI to get input from user for all remedies that require input."""
        for remedy_cls in self.REMEDIATION_REGISTRY.values():
            remedy = remedy_cls() # Instantiate the remedy class
            if remedy.has_input:
                TerminalUI.get_instance().user_input(
                    remedy_require_inputs=remedy.remedy_input_require,
                    user_inputs_list=remedy.user_inputs, 
                    remedy_id=remedy.id
                )

    def call_user_interact_TUI(self) -> None:
        """Combine TUI remedy info and TUI user input"""
        for remedy_cls in self.REMEDIATION_REGISTRY.values():
            remedy = remedy_cls() # Instantiate the remedy class
            TerminalUI.get_instance().display_remedy_info(remedy)
            pre_decision = TerminalUI.get_instance().display_remedy_decision(pre_diff=True)
            if pre_decision:
                if remedy.has_input:
                    TerminalUI.get_instance().user_input(
                        remedy_require_inputs=remedy.remedy_input_require,
                        user_inputs_list=remedy.user_inputs, 
                        remedy_id=remedy.id
                    )
            else:
                TerminalUI.get_instance().display_remedy_rejected(remedy)

    def split_ast_input(self) -> None:
        """Split the AST input into specific AST for each remedy."""
        for remedy_cls in self.REMEDIATION_REGISTRY.values():
            remedy = remedy_cls() # Instantiate the remedy class
            remedy.read_child_scan_result(self.ast_scan) # Get the AST scan first
            remedy.read_child_ast_config(self.ast_config)
    
    def apply_remediations(self) -> dict:
        """
        Orchestrate the full remediation flow for all applicable rules.
        
        Flow:
        1. Instantiate each remedy from REMEDIATION_REGISTRY
        2. For each remedy:
           a. Display remedy info via TerminalUI
           b. Collect user inputs if required
           c. Get decision from user (pre-interaction)
           d. If approved: Call remedy.remediate() to apply fixes
           e. Display diff and get final decision
           f. If approved: Merge modified AST back into full ast_config
        3. Return: Updated ast_config with all approved remediations
        
        Returns:
            Modified ast_config dictionary
        """
        modified_ast_config = copy.deepcopy(self.ast_config)
        
        for remedy_cls in self.REMEDIATION_REGISTRY.values():
            remedy = remedy_cls()
            
            # Display remedy information
            TerminalUI.get_instance().display_remedy_info(remedy)
            
            # Ask if user wants to proceed
            pre_decision = TerminalUI.get_instance().display_remedy_decision(pre_diff=True)
            if not pre_decision:
                TerminalUI.get_instance().display_remedy_rejected(remedy)
                continue
            
            # Collect user inputs if needed
            if remedy.has_input:
                TerminalUI.get_instance().user_input(
                    remedy_require_inputs=remedy.remedy_input_require,
                    user_inputs_list=remedy.user_inputs,
                    remedy_id=remedy.id
                )
            
            # Extract violations and AST sections for this rule
            remedy.read_child_scan_result(self.ast_scan)
            remedy.read_child_ast_config(modified_ast_config)
            
            # Skip if no violations for this rule
            if not remedy.child_scan_result:
                print(f"No violations found for Rule {remedy.id}. Skipping.")
                continue
            
            # Apply remediation
            remedy.remediate()
            
            # Display diff (would show before/after comparison)
            # TODO: Implement diff display
            
            # Ask for final approval
            final_decision = TerminalUI.get_instance().display_remedy_decision(pre_diff=False)
            if not final_decision:
                TerminalUI.get_instance().display_remedy_rejected(remedy)
                continue
            
            # Merge modifications back into full ast_config
            modified_ast_config = self.merge_remediation(
                modified_ast_config,
                remedy.child_ast_modified
            )
        
        return modified_ast_config
    
    def merge_remediation(self, ast_config: dict, child_ast_modified: dict) -> dict:
        """
        Merge file-grouped modifications back into the full ast_config.
        
        For each file in child_ast_modified:
        1. Find the file entry in ast_config["config"] array
        2. Replace its "parsed" section with the modified version
        
        Args:
            ast_config: Full AST config to merge into
            child_ast_modified: File-grouped modifications {file_path: {parsed: [...]}}
        
        Returns:
            Updated ast_config with merged modifications
        """
        if not isinstance(child_ast_modified, dict) or not child_ast_modified:
            return ast_config
        
        if not isinstance(ast_config, dict):
            return ast_config
        
        # Deep copy to avoid modifying original
        result = copy.deepcopy(ast_config)
        config_list = result.get("config", [])
        
        if not isinstance(config_list, list):
            return result
        
        # For each modified file
        for file_path, modified_data in child_ast_modified.items():
            if not isinstance(modified_data, dict) or "parsed" not in modified_data:
                continue
            
            # Find the file in config array
            file_index = ASTEditor._find_file_in_config(result, file_path)
            if file_index == -1:
                continue
            
            # Replace the parsed section
            if file_index < len(config_list):
                config_list[file_index]["parsed"] = copy.deepcopy(modified_data["parsed"])
        
        return result


















































    # def __init__(self, debug: bool = True) -> None:
    #     self._before_state: Any | None = None
    #     self._after_state: Any | None = None
    #     self.debug = debug
    #     self.errors: List[str] = []

    # def _debug(self, msg: str) -> None:
    #     """Print debug message."""
    #     if self.debug:
    #         print(f"[DEBUG] {msg}")

    # def _normalize_context(self, config: Any, context: List[Any]) -> List[Any]:
    #     """
    #     Normalize context path from full AST format to extracted config format.
        
    #     If the context starts with ["config", 0] but we have an extracted config
    #     (with "parsed" field directly), adjust by removing those prefixes.
        
    #     Args:
    #         config: The config dict being processed
    #         context: The original context path from scan_result
        
    #     Returns:
    #         The normalized context path
    #     """
    #     # Check if context starts with "config" and we have an extracted config
    #     if context and context[0] == "config" and isinstance(config, dict) and "parsed" in config:
    #         # Remove "config", 0 prefix since we already have the extracted config
    #         adjusted = context[2:] if len(context) > 2 else context[1:]
    #         self._debug(f"Context normalized: {context} -> {adjusted}")
    #         return adjusted
        
    #     return context

    # def apply_remediation(
    #     self,
    #     config_json: Any,
    #     file_path: str,
    #     remediation: Dict[str, Any],
    # ) -> tuple[bool, Any]:
    #     """
    #     Apply a single remediation instruction to the config.
        
    #     This function:
    #     1. Normalizes the context path for the current config format
    #     2. Validates that the target exists at the given context
    #     3. Applies the remediation action (replace or add)
    #     4. Validates the result
        
    #     Args:
    #         config_json: The parsed config structure (could be wrapped or extracted)
    #         file_path: The file path from the uncompliance (for reference)
    #         remediation: The remediation dict with action, context, directive, args
        
    #     Returns:
    #         Tuple of (success: bool, modified_config: Any)
    #     """
    #     config = copy.deepcopy(config_json)
    #     action = remediation.get("action", "").lower()
    #     context = remediation.get("context", [])
    #     directive = remediation.get("directive", "")
    #     args = remediation.get("args", [])

    #     self._debug(f"\nApplying remediation: action={action}, directive={directive}, file={file_path}")
    #     self._debug(f"Original context: {context}")

    #     # Step 1: Normalize context for extracted config format
    #     context = self._normalize_context(config, context)
    #     self._debug(f"Normalized context: {context}")

    #     # Step 2: Validate that target exists
    #     target = ASTEditor.get_by_context(config, context)
    #     if target is None:
    #         error_msg = f"Failed to navigate to context {context} - target is None (path doesn't exist in AST)"
    #         self._debug(f"ERROR: {error_msg}")
    #         self.errors.append(f"{file_path}: {error_msg}")
    #         return False, config
        
    #     self._debug(f"Target found, type: {type(target).__name__}, size: {len(str(target))} chars")

    #     # Step 3: Apply the remediation action
    #     if action == "replace":
    #         return self._apply_replace(config, context, directive, args, file_path)
    #     elif action == "add":
    #         return self._apply_add(config, context, directive, args, file_path)
    #     else:
    #         error_msg = f"Unknown action: {action}"
    #         self._debug(f"ERROR: {error_msg}")
    #         self.errors.append(f"{file_path}: {error_msg}")
    #         return False, config

    # def _apply_replace(
    #     self,
    #     config: Any,
    #     context: List[int | str],
    #     directive: str,
    #     args: Any,
    #     file_path: str,
    # ) -> tuple[bool, Any]:
    #     """Replace a directive's args at the given context."""
    #     target = ASTEditor.get_by_context(config, context)
    #     if target is None:
    #         error_msg = f"REPLACE failed: Cannot navigate to context {context}"
    #         self._debug(f"ERROR: {error_msg}")
    #         self.errors.append(f"{file_path}: {error_msg}")
    #         return False, config

    #     if isinstance(target, dict):
    #         # Single directive case
    #         if target.get("directive") == directive:
    #             self._debug(f"✓ REPLACE: Found '{directive}' in dict block, updating args")
    #             target["args"] = copy.deepcopy(args)
    #             return True, config
    #         else:
    #             error_msg = f"REPLACE failed: Target is dict but directive mismatch. Expected '{directive}', got '{target.get('directive')}'"
    #             self._debug(f"ERROR: {error_msg}")
    #             self.errors.append(f"{file_path}: {error_msg}")
    #             return False, config
    #     elif isinstance(target, list):
    #         # List of directives case - find and replace
    #         for i, item in enumerate(target):
    #             if isinstance(item, dict) and item.get("directive") == directive:
    #                 self._debug(f"✓ REPLACE: Found '{directive}' at index {i} in list, updating args")
    #                 item["args"] = copy.deepcopy(args)
    #                 return True, config
    #         error_msg = f"REPLACE failed: Directive '{directive}' not found in list at context {context}"
    #         self._debug(f"ERROR: {error_msg}")
    #         self.errors.append(f"{file_path}: {error_msg}")
    #         return False, config
    #     else:
    #         error_msg = f"REPLACE failed: Target is {type(target).__name__} at context {context}, expected dict or list"
    #         self._debug(f"ERROR: {error_msg}")
    #         self.errors.append(f"{file_path}: {error_msg}")
    #         return False, config

    # def _apply_add(
    #     self,
    #     config: Any,
    #     context: List[int | str],
    #     directive: str,
    #     args: Any,
    #     file_path: str,
    # ) -> tuple[bool, Any]:
    #     """Add a new directive/block at the given context."""
    #     target = ASTEditor.get_by_context(config, context)
    #     if target is None:
    #         error_msg = f"ADD failed: Cannot navigate to context {context}"
    #         self._debug(f"ERROR: {error_msg}")
    #         self.errors.append(f"{file_path}: {error_msg}")
    #         return False, config

    #     if isinstance(target, list):
    #         # Add to a list at context
    #         new_item = {"directive": directive, "args": copy.deepcopy(args)}
    #         self._debug(f"✓ ADD: Appending new '{directive}' block to list at context {context}")
    #         target.append(new_item)
    #         return True, config
    #     else:
    #         error_msg = f"ADD failed: Target is {type(target).__name__} at context {context}, expected list. Cannot append."
    #         self._debug(f"ERROR: {error_msg}")
    #         self.errors.append(f"{file_path}: {error_msg}")
    #         return False, config

    # def apply_recommendation(
    #     self,
    #     config_json: Any,
    #     recommendation: Dict[str, Any],
    # ) -> Dict[str, Any]:
    #     """
    #     Apply all remediations for a single recommendation.
        
    #     Args:
    #         config_json: The parsed config structure
    #         recommendation: The recommendation dict from scan_result.json
        
    #     Returns:
    #         Dict with success status, applied steps, and modified config
    #     """
    #     result_config = copy.deepcopy(config_json)
    #     applied_count = 0
    #     failed_count = 0

    #     for uncompliance in recommendation.get("uncompliances", []):
    #         file_path = uncompliance.get("file", "")
    #         for remediation in uncompliance.get("remediations", []):
    #             success, result_config = self.apply_remediation(
    #                 result_config, file_path, remediation
    #             )
    #             if success:
    #                 applied_count += 1
    #             else:
    #                 failed_count += 1

    #     return {
    #         "applied": applied_count,
    #         "failed": failed_count,
    #         "config": result_config,
    #     }

    # def apply_all_recommendations(
    #     self,
    #     config_json: Any,
    #     scan_result: Dict[str, Any],
    #     target_rec_ids: List[str] | None = None,
    # ) -> Dict[str, Any]:
    #     """
    #     Apply all recommendations from scan_result to config.
        
    #     Args:
    #         config_json: The parsed config structure
    #         scan_result: The scan_result.json content
    #         target_rec_ids: Optional list of recommendation IDs to apply.
    #                       If None, apply all.
        
    #     Returns:
    #         Dict with applied/failed counts, diffs, and final config
    #     """
    #     self._before_state = copy.deepcopy(config_json)
    #     self.errors = []
    #     working_config = copy.deepcopy(config_json)

    #     total_applied = 0
    #     total_failed = 0
    #     diffs: Dict[str, str] = {}

    #     for rec in scan_result.get("recommendations", []):
    #         rec_id = rec.get("id", "")
            
    #         if target_rec_ids and rec_id not in target_rec_ids:
    #             continue

    #         self._debug(f"\n--- Processing recommendation {rec_id} ---")
    #         before = copy.deepcopy(working_config)
    #         result = self.apply_recommendation(working_config, rec)
            
    #         working_config = result["config"]
    #         total_applied += result["applied"]
    #         total_failed += result["failed"]

    #         # Generate diff for this recommendation if changed
    #         if before != working_config:
    #             diff = self._generate_diff(before, working_config, rec_id)
    #             if diff:
    #                 diffs[rec_id] = diff

    #     self._after_state = copy.deepcopy(working_config)

    #     return {
    #         "total_applied": total_applied,
    #         "total_failed": total_failed,
    #         "config": working_config,
    #         "diffs": diffs,
    #         "errors": self.errors,
    #     }

    # def _generate_diff(self, before: Any, after: Any, label: str) -> str:
    #     """Generate a unified diff string."""
    #     import difflib

    #     before_json = json.dumps(before, indent=2, ensure_ascii=False, sort_keys=True)
    #     after_json = json.dumps(after, indent=2, ensure_ascii=False, sort_keys=True)

    #     if before_json == after_json:
    #         return ""

    #     diff_lines = difflib.unified_diff(
    #         before_json.splitlines(),
    #         after_json.splitlines(),
    #         fromfile=f"before_{label}",
    #         tofile=f"after_{label}",
    #         lineterm="",
    #     )
    #     return "\n".join(diff_lines)

    # def get_before_state(self) -> Any:
    #     """Get the state before any remediations."""
    #     return copy.deepcopy(self._before_state) if self._before_state else None

    # def get_after_state(self) -> Any:
    #     """Get the state after remediations."""
    #     return copy.deepcopy(self._after_state) if self._after_state else None
