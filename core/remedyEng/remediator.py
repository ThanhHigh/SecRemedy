"""Handler for remediations defined in scan_result.json."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Dict, List, Optional, Type

from core.remedyEng.base_remedy import BaseRemedy
from core.recom_registry import RecomID

from core.remedyEng.recommendations.remediate_241 import Remediate241
from core.remedyEng.recommendations.remediate_242 import Remediate242
from core.remedyEng.recommendations.remediate_251 import Remediate251
from core.remedyEng.recommendations.remediate_252 import Remediate252
from core.remedyEng.recommendations.remediate_253 import Remediate253
from core.remedyEng.recommendations.remediate_32 import Remediate32
from core.remedyEng.recommendations.remediate_34 import Remediate34
from core.remedyEng.recommendations.remediate_411 import Remediate411
from core.remedyEng.recommendations.remediate_511 import Remediate511
from core.remedyEng.recommendations.remediate_531 import Remediate531
from core.remedyEng.recommendations.remediate_532 import Remediate532

from core.remedyEng.ast_editor import ASTEditor
from core.remedyEng.terminal_ui import TerminalUI

class Remediator:
    """Apply remediation through all Child Remedies base on Results, interact with User, Generate new AST """
    ast_config: dict = {}
    ast_scan: dict = {}
    ast_baseline: dict = {}
    applied_history: List[dict] = []

    


    # ---------------------------------------------------------------------------
    # Remediation Registry: tất cả Remediation class, mapped bằng RecomID (Enum)
    # ---------------------------------------------------------------------------
    REMEDIATION_REGISTRY: Dict[RecomID, Type[BaseRemedy]] = {
        RecomID.CIS_2_4_1: Remediate241,
        RecomID.CIS_2_4_2: Remediate242,
        RecomID.CIS_2_5_1: Remediate251,
        RecomID.CIS_2_5_2: Remediate252,
        RecomID.CIS_2_5_3: Remediate253,
        RecomID.CIS_3_2: Remediate32,
        RecomID.CIS_3_4: Remediate34,
        RecomID.CIS_4_1_1: Remediate411,
        RecomID.CIS_5_1_1: Remediate511,
        RecomID.CIS_5_3_1: Remediate531,
        RecomID.CIS_5_3_2: Remediate532,
    }

    def __init__(self, strict_placement: bool = False, strict_json_validation: bool = False) -> None:
        self.ast_config = {}
        self.ast_scan = {}
        self.ast_baseline = {}
        self.applied_history = []
        self.strict_placement = strict_placement
        self.strict_json_validation = strict_json_validation

    def display_header(self) -> None:
        """Display a header for the remediation process."""
        TerminalUI.get_instance().display_remedy_header()

    def get_input_ast(self, config_path: Optional[str] = None, scan_path: Optional[str] = None) -> None:
        """Get the File Names from user and return 2 ASTs """
        if config_path:
            with Path(config_path).expanduser().resolve().open("r", encoding="utf-8") as f:
                self.ast_config = json.load(f)
        else:
            self.ast_config = TerminalUI.get_instance().get_ast_config()

        if scan_path:
            with Path(scan_path).expanduser().resolve().open("r", encoding="utf-8") as f:
                self.ast_scan = json.load(f)
        else:
            self.ast_scan = TerminalUI.get_instance().get_ast_scan()

    # For each remedy, inject global flags so they can adjust their behavior accordingly (e.g. strict placement may disable certain "add" actions that can't be confidently placed)
    # This Strict is Additional Feature
    def _configure_remedy_flags(self, remedy: BaseRemedy) -> None:
        """Inject global CLI flags into remedy instances."""
        remedy.strict_placement = self.strict_placement
        remedy.strict_json_validation = self.strict_json_validation

    def _filter_validated_changes(self, remedy: BaseRemedy) -> dict:
        """Keep only per-file AST mutations that pass structural validation."""
        validated = {}
        for file_path, modified in remedy.child_ast_modified.items():
            before_ast = remedy.child_ast_config.get(file_path, {}).get("parsed")
            after_ast = modified.get("parsed") if isinstance(modified, dict) else None
            is_valid, errors = remedy._validate_ast_mutation(before_ast, after_ast)
            if is_valid:
                validated[file_path] = modified
                continue

            TerminalUI.get_instance().display_validation_warning(
                f"Rule {remedy.id} failed AST validation for {file_path}: {'; '.join(errors)}"
            )
        return validated
        
    # For in Remediation Registry, each Remediate call the function TerminalUI of specific for that remediation, display information
    # Input for user if has, In TerminalUI wait for user input, get the information, start to apply Remediate as hard code
    # Each of output the difference between before and after, so to user agree or not, if agree write to new AST, if not then copy the old AST
    # Finally all the Loop get the new AST, check for syntax, if valid build them to new config files
    # if not valid, print the error and stop the process.

    def split_ast_input(self) -> None:
        """Split the AST input into specific AST for each remedy."""
        for remedy_cls in self.REMEDIATION_REGISTRY.values():
            remedy = remedy_cls() # Instantiate the remedy class
            remedy.read_child_scan_result(self.ast_scan) # Get the AST scan first
            remedy.read_child_ast_config(self.ast_config)

    def _prepare_remedy(self, remedy: BaseRemedy, ast_config: dict) -> bool:
        """Populate remedy state and return True only when violations exist."""
        self._configure_remedy_flags(remedy)
        remedy.read_child_scan_result(self.ast_scan)
        if not remedy.child_scan_result:
            return False

        remedy.read_child_ast_config(ast_config)
        return bool(remedy.child_ast_config)
    
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
        self.ast_baseline = copy.deepcopy(self.ast_config)
        self.applied_history = []
        modified_ast_config = copy.deepcopy(self.ast_baseline)
        
        for remedy_cls in self.REMEDIATION_REGISTRY.values():
            remedy = remedy_cls()

            if not self._prepare_remedy(remedy, modified_ast_config):
                print(f"No violations found for Rule {remedy.id}. Skipping.")
                continue
            
            # Display remedy information
            TerminalUI.get_instance().display_remedy_info(remedy)
            
            # Ask if user wants to proceed
            pre_decision = TerminalUI.get_instance().display_remedy_decision(pre_diff=True)
            if not pre_decision:
                TerminalUI.get_instance().display_remedy_rejected(remedy)
                continue
            
            # Collect user inputs if needed
            if remedy.has_input:
                if not TerminalUI.get_instance().collect_and_validate_user_inputs(remedy):
                    TerminalUI.get_instance().display_remedy_rejected(remedy)
                    continue
            
            # Apply remediation
            remedy.remediate()
            remedy.child_ast_modified = self._filter_validated_changes(remedy)

            approved_changes = {}
            accepted_count = 0
            rejected_count = 0
            unchanged_count = 0
            fallback_count = 0
            for file_path in remedy.get_affected_files():
                payload = remedy.build_file_diff_payload(file_path)

                if payload["mode"] == "ast":
                    fallback_count += 1

                TerminalUI.get_instance().display_remedy_file_diff(
                    remedy_id=remedy.id,
                    file_path=file_path,
                    violation_count=payload["violation_count"],
                    mode=payload["mode"],
                    diff_text=payload["diff_text"],
                )

                if not payload["diff_text"]:
                    remedy.file_approval_status[file_path] = False
                    unchanged_count += 1
                    continue

                file_decision = TerminalUI.get_instance().display_file_diff_decision()
                remedy.file_approval_status[file_path] = file_decision

                if file_decision:
                    accepted_count += 1
                    approved_changes[file_path] = remedy.child_ast_modified[file_path]
                else:
                    rejected_count += 1

            TerminalUI.get_instance().display_remedy_summary(
                remedy_id=remedy.id,
                accepted=accepted_count,
                rejected=rejected_count,
                unchanged=unchanged_count,
                fallback=fallback_count,
            )

            if not approved_changes:
                TerminalUI.get_instance().display_remedy_rejected(remedy)
                continue

            modified_ast_config = self.merge_remediation(modified_ast_config, approved_changes)

            self.applied_history.append(
                {
                    "remedy_id": remedy.id,
                    "remedy_class": remedy_cls.__name__,
                    "user_inputs": list(remedy.user_inputs),
                    "approved_files": sorted(list(approved_changes.keys())),
                    "touched_files": sorted(list(remedy.get_affected_files())),
                }
            )
        
        self.ast_config = modified_ast_config
        return modified_ast_config

    def get_remedy_class_by_id(self, remedy_id: str) -> Optional[Type[BaseRemedy]]:
        """Resolve a remediation class from registry by rule id string."""
        for remedy_cls in self.REMEDIATION_REGISTRY.values():
            remedy = remedy_cls()
            if remedy.id == remedy_id:
                return remedy_cls
        return None

    def replay_history(self, excluded_remedy_id: Optional[str] = None) -> dict:
        """Rebuild AST from baseline by replaying approved remedy history."""
        rebuilt = copy.deepcopy(self.ast_baseline)
        for record in self.applied_history:
            remedy_id = record.get("remedy_id", "")
            if excluded_remedy_id and remedy_id == excluded_remedy_id:
                continue

            remedy_cls = self.get_remedy_class_by_id(remedy_id)
            if remedy_cls is None:
                continue

            rebuilt = self.apply_remedy_record(remedy_cls, rebuilt, record)

        self.ast_config = rebuilt
        return rebuilt

    def apply_remedy_record(self, remedy_cls: Type[BaseRemedy], ast_input: dict, record: dict) -> dict:
        """Apply one remedy non-interactively using a stored record."""
        modified_ast_config = copy.deepcopy(ast_input)
        remedy = remedy_cls()
        self._configure_remedy_flags(remedy)

        stored_inputs = record.get("user_inputs", [])
        if isinstance(stored_inputs, list):
            remedy.user_inputs = list(stored_inputs)

        remedy.read_child_scan_result(self.ast_scan)
        remedy.read_child_ast_config(modified_ast_config)
        if not remedy.child_scan_result:
            return modified_ast_config

        remedy.remediate()
        remedy.child_ast_modified = self._filter_validated_changes(remedy)
        approved_files = set(record.get("approved_files", []))
        approved_changes = {
            file_path: remedy.child_ast_modified[file_path]
            for file_path in remedy.get_affected_files()
            if file_path in approved_files and file_path in remedy.child_ast_modified
        }

        if not approved_changes:
            return modified_ast_config

        return self.merge_remediation(modified_ast_config, approved_changes)

    def apply_single_remedy_interactive(self, remedy_id: str, ast_input: dict) -> tuple[dict, Optional[dict]]:
        """Apply only one remedy interactively and return updated AST and record."""
        remedy_cls = self.get_remedy_class_by_id(remedy_id)
        if remedy_cls is None:
            TerminalUI.get_instance().display_validation_warning(
                f"Cannot find remedy class for rule {remedy_id}."
            )
            return ast_input, None

        modified_ast_config = copy.deepcopy(ast_input)
        remedy = remedy_cls()

        if not self._prepare_remedy(remedy, modified_ast_config):
            TerminalUI.get_instance().display_validation_warning(
                f"No violations found for Rule {remedy.id}."
            )
            return modified_ast_config, None

        TerminalUI.get_instance().display_remedy_info(remedy)
        pre_decision = TerminalUI.get_instance().display_remedy_decision(pre_diff=True)
        if not pre_decision:
            TerminalUI.get_instance().display_remedy_rejected(remedy)
            return modified_ast_config, None

        if remedy.has_input:
            if not TerminalUI.get_instance().collect_and_validate_user_inputs(remedy):
                TerminalUI.get_instance().display_remedy_rejected(remedy)
                return modified_ast_config, None

        remedy.remediate()
        remedy.child_ast_modified = self._filter_validated_changes(remedy)
        approved_changes = {}
        accepted_count = 0
        rejected_count = 0
        unchanged_count = 0
        fallback_count = 0

        for file_path in remedy.get_affected_files():
            payload = remedy.build_file_diff_payload(file_path)
            if payload["mode"] == "ast":
                fallback_count += 1

            TerminalUI.get_instance().display_remedy_file_diff(
                remedy_id=remedy.id,
                file_path=file_path,
                violation_count=payload["violation_count"],
                mode=payload["mode"],
                diff_text=payload["diff_text"],
            )

            if not payload["diff_text"]:
                unchanged_count += 1
                continue

            file_decision = TerminalUI.get_instance().display_file_diff_decision()
            if file_decision:
                accepted_count += 1
                approved_changes[file_path] = remedy.child_ast_modified[file_path]
            else:
                rejected_count += 1

        TerminalUI.get_instance().display_remedy_summary(
            remedy_id=remedy.id,
            accepted=accepted_count,
            rejected=rejected_count,
            unchanged=unchanged_count,
            fallback=fallback_count,
        )

        if not approved_changes:
            return modified_ast_config, None

        merged = self.merge_remediation(modified_ast_config, approved_changes)
        record = {
            "remedy_id": remedy.id,
            "remedy_class": remedy_cls.__name__,
            "user_inputs": list(remedy.user_inputs),
            "approved_files": sorted(list(approved_changes.keys())),
            "touched_files": sorted(list(remedy.get_affected_files())),
        }
        return merged, record
    
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


