import os

_BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _abs(rel: str) -> str:
    return os.path.join(_BASE, rel)


def parser_output_path(port: int) -> str:
    return _abs(f"tmp/contracts/parsers_output/parser_output_{port}.json")


def scan_result_path(port: int) -> str:
    return _abs(f"tmp/contracts/scan_result/scan_result_{port}.json")


def diff_path(port: int) -> str:
    return _abs(f"tmp/contracts/diff/diff_{port}.json")


def hardened_dir(port: int) -> str:
    return _abs(f"tmp/hardened_configs/{port}")


def before_remediation_contract() -> str:
    return _abs("core/contracts/before_remediation.json")


def report_path(port: int) -> str:
    return _abs(f"tmp/contracts/scan_report/scan_report_{port}.md")
