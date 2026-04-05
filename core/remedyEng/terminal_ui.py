import argparse
import json
from pathlib import Path

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
        print(f"Applying Remedy: {remedy.title}".center(60))
        print("-" * 60)
        print(f"Description: {remedy.description}")
        print(f"Audit Procedure: {remedy.audit_procedure}")
        print(f"Impact: {remedy.impact}")
        print(f"Remediation Steps: {remedy.remediation}")
        if remedy.remedy_detail:
            print(f"Additional Details: {remedy.remedy_detail}")
        print("-" * 60 + "\n")