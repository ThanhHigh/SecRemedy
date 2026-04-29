import argparse
import json
from pathlib import Path

from typing import Any, List

from core.remedyEng.debug_print import debug_print

parser = argparse.ArgumentParser()




class TerminalUI:
    """Terminal-based user interface for the remediation engine."""

    _instance = None

    def __new__(cls, *args, **kwargs):
        # Keep a single shared instance for the entire process.
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        # Prevent re-running initialization on repeated construction.
        if self._initialized:
            return
        self._initialized = True

    @classmethod
    def get_instance(cls) -> "TerminalUI":
        """Return the shared singleton instance."""
        return cls()
   
    def display_remedy_header(self) -> None:
        """Display a header for the remediation process."""
        print("=" * 60)
        print("Starting Remediation Process 🚀".center(60))
        print("=" * 60)

    def display_remedy_closer(self) -> None:
        """Display a closing message for the remediation process."""
        print("\n" + "=" * 60)
        print("Remediation Process Completed 🎉".center(60))
        print("=" * 60 + "\n")

    def display_remedy_rejected(self, remedy) -> None:
        """Display a message when a remedy is rejected by the user."""
        print("\n" + "-" * 60)
        print(f"[NOT APPLIED]: {remedy.id} - {remedy.title}".center(60))
        print("-" * 60 + "\n")

    def get_ast_config(self) -> dict:
        """Load the AST config from a specified directory."""
        user_input = input("Enter config file path: ").strip()
        config_file = Path(user_input).expanduser().resolve()

        if not config_file.is_file():
            raise FileNotFoundError(f"File not found: {config_file}")
        if not config_file.suffix == ".json":
            raise ValueError(f"Invalid file type: {config_file}. Expected a .json file.")

        print(f"Using config file: {config_file}")

        ast_config = {}

        try:
            with open(config_file, "r") as f:
                ast_config = json.load(f)
        except Exception as e:
            raise RuntimeError(f"Error reading file: {e}")

        return ast_config
    
    def get_ast_scan(self) -> dict:
        """Load the AST scan results from a specified directory."""
        user_input = input("Enter scan result file path: ").strip()
        scan_file = Path(user_input).expanduser().resolve()

        if not scan_file.is_file():
            raise FileNotFoundError(f"File not found: {scan_file}")
        if not scan_file.suffix == ".json":
            raise ValueError(f"Invalid file type: {scan_file}. Expected a .json file.")

        print(f"Using scan result file: {scan_file}")

        scan_result = {}

        try:
            with open(scan_file, "r") as f:
                scan_result = json.load(f)
        except Exception as e:
            raise RuntimeError(f"Error reading file: {e}")

        return scan_result
    

    def display_remedy_info(self, remedy) -> None:
        """Display information about the remedy being applied."""
        print("\n" + "-" * 60)
        print(f"Applying Remedy: {remedy.id} - {remedy.title}".center(60))
        print("-" * 60)
        print(f"Description: {remedy.description}")
        print(f"Audit Procedure: {remedy.audit_procedure}")
        print(f"Impact: {remedy.impact}")
        print(f"Remediation Steps: {remedy.remediation}")
        if remedy.has_guide_detail:
            print(f"Additional Details: \n{remedy.remedy_guide_detail}")
        print("-" * 60 + "\n")

    def display_user_guidance(self, remedy) -> None:
        """Display step-by-step input guidance for a remedy."""
        try:
            guidance = remedy.get_user_guidance()
        except Exception as exc:
            self.display_validation_warning(f"Could not render guidance for {remedy.id}: {exc}")
            return

        if not guidance:
            return

        print("\n" + "=" * 60)
        print(f"Input Guidance: {remedy.id}".center(60))
        print("=" * 60)
        print(guidance)
        print("=" * 60 + "\n")

    def display_remedy_decision(self, pre_diff: bool) -> bool:
        """Ask the user whether to apply the remedy."""
        if (pre_diff):
            print("Do you want to apply this remedy before seeing the diff? (y/n)")
        else:
            print("Do you want to apply this remedy after seeing the diff? (y/n)")
        while True:
            user_input = input().strip().lower()
            if user_input in ("y", "yes"):
                return True
            elif user_input in ("n", "no"):
                return False
            else:
                print("Invalid input. Please enter 'y' or 'n'.")

    def display_remedy_file_diff(self, remedy_id: str, file_path: str, violation_count: int, mode: str, diff_text: str) -> None:
        """Display per-file diff for one remedy review step."""
        print("\n" + "=" * 60)
        print(f"Reviewing {remedy_id} -> {file_path}".center(60))
        print("=" * 60)
        print(f"Violations in file: {violation_count}")
        if mode == "ast":
            print("Diff mode: AST fallback (config render unavailable)")
        else:
            print("Diff mode: Config text")
        print("-" * 60)
        if diff_text:
            print(diff_text)
        else:
            print("No effective changes detected for this file.")
        print("-" * 60)

    def display_file_diff_decision(self) -> bool:
        """Ask whether to apply changes for the currently displayed file."""
        print("Apply this file change? (y/n)")
        while True:
            user_input = input().strip().lower()
            if user_input in ("y", "yes"):
                return True
            if user_input in ("n", "no"):
                return False
            print("Invalid input. Please enter 'y' or 'n'.")

    def display_remedy_summary(self, remedy_id: str, accepted: int, rejected: int, unchanged: int, fallback: int) -> None:
        """Display per-remedy review summary after file-level decisions."""
        print("\n" + "~" * 60)
        print(f"Summary for Remedy {remedy_id}".center(60))
        print("~" * 60)
        print(f"Accepted files : {accepted}")
        print(f"Rejected files : {rejected}")
        print(f"Unchanged files: {unchanged}")
        print(f"AST fallback   : {fallback}")
        print("~" * 60 + "\n")

    def display_output_saved(self, output_path: str) -> None:
        """Display where remediated AST was written."""
        print(f"Remediated AST saved to: {output_path}")

    def display_validation_header(self, iteration: int) -> None:
        """Display validation loop header."""
        print("\n" + "#" * 60)
        print(f"Validation Loop - Iteration {iteration}".center(60))
        print("#" * 60)

    def display_validation_ok(self, config_path: str) -> None:
        """Display successful nginx syntax check."""
        print(f"Syntax dry-run PASSED: {config_path}")

    def display_validation_warning(self, message: str) -> None:
        """Display warning in validation/replay flow."""
        print(f"[WARNING] {message}")

    def display_validation_pass_with_warnings(
        self,
        config_path: str,
        error_paths: List[str],
        environment_errors: List[str],
        environment_guidance: List[str],
        raw_error: str,
    ) -> None:
        """Display result when syntax is acceptable but environment dependencies fail."""
        print("\n" + "~" * 60)
        print("Syntax dry-run PASSED with environment warnings".center(60))
        print("~" * 60)
        print(f"Generated config: {config_path}")
        if error_paths:
            print("Environment-related paths:")
            for path in error_paths:
                print(f"- {path}")

        if environment_errors:
            print("Detected environment issues:")
            for message in environment_errors:
                print(f"- {message}")

        if environment_guidance:
            print("Suggested manual fixes on target server:")
            for hint in environment_guidance:
                print(f"- {hint}")

        if raw_error:
            print("-" * 60)
            print(raw_error.strip())
        print("~" * 60)

    def display_validation_errors(
        self,
        error_paths: List[str],
        raw_error: str,
        status: str,
        syntax_errors: List[str],
        environment_errors: List[str],
        unknown_errors: List[str],
    ) -> None:
        """Display categorized validation failures and concise raw output."""
        print("\n" + "!" * 60)
        if status == "FAIL_SYNTAX":
            print("Syntax check FAILED (remediation-related)".center(60))
        else:
            print("Syntax check FAILED (unknown cause)".center(60))
        print("!" * 60)
        if error_paths:
            print("Referenced paths:")
            for path in error_paths:
                print(f"- {path}")
        else:
            print("Referenced paths: (none extracted)")

        if syntax_errors:
            print("Likely remediation syntax issues:")
            for message in syntax_errors:
                print(f"- {message}")

        if environment_errors:
            print("Environment-related messages (informational):")
            for message in environment_errors:
                print(f"- {message}")

        if unknown_errors:
            print("Unclassified error messages:")
            for message in unknown_errors:
                print(f"- {message}")

        print("-" * 60)
        if raw_error:
            print(raw_error.strip())
        print("!" * 60)

    def ask_post_error_action(self) -> str:
        """Ask what to do when syntax check fails."""
        print("Choose action: [r] rollback one remedy, [a] reapply one remedy, [s] stop")
        while True:
            user_input = input().strip().lower()
            if user_input in {"r", "rollback"}:
                return "rollback"
            if user_input in {"a", "reapply"}:
                return "reapply"
            if user_input in {"s", "stop"}:
                return "stop"
            print("Invalid input. Enter r, a, or s.")

    def ask_remedy_id(self, candidate_ids: List[str]) -> str:
        """Ask user to choose one remedy id from candidates or free text."""
        if candidate_ids:
            print("Candidate remedies:")
            for remedy_id in candidate_ids:
                print(f"- {remedy_id}")
        print("Enter remedy id:")
        return input().strip()
        
    def user_input(self, remedy_require_inputs: List[str], user_inputs_list, remedy_id: str) -> None:
        print(f"Remedy {remedy_id} requires additional information from you.")
        for require in remedy_require_inputs:
            print(f"Please provide: \n{require}")
            user_input = input().strip()
            user_inputs_list.append(user_input)

        # For debug
        # Is the user input list is work as desire
        debug_print(f"{remedy_id}: User provided inputs: {user_inputs_list}")

    def collect_and_validate_user_inputs(self, remedy) -> bool:
        """Collect inputs for one remedy and validate before applying remediation."""
        if not remedy.has_input:
            return True

        self.display_user_guidance(remedy)

        while True:
            remedy.user_inputs = []
            for require in remedy.remedy_input_require:
                print(f"Please provide:\n{require}")
                user_input = input().strip()
                remedy.user_inputs.append(user_input)

            if hasattr(remedy, "resolve_user_inputs"):
                remedy.resolve_user_inputs()

            is_valid, error_msg = remedy._validate_user_inputs()
            if is_valid:
                debug_print(f"{remedy.id}: Validated user inputs: {remedy.user_inputs}")
                return True

            print(f"[VALIDATION ERROR] {error_msg}")
            print("Retry this remedy input? (y/n)")
            retry = input().strip().lower()
            if retry not in {"y", "yes"}:
                self.display_validation_warning(f"Skipping {remedy.id} due to invalid inputs.")
                return False

