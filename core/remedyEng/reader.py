"""
Step 1 — Scan Result Reader

Load scan_result.json, filter fail recommendations,
flatten tất cả remediations[] thành list phẳng RemediationItem.
"""

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class RemediationItem:
    file: str
    action: str             # "add" | "replace" | "delete"
    directive: str
    args: list[str] = field(default_factory=list)
    block: list[dict] = field(default_factory=list)
    line: int = 0
    logical_context: list[str] = field(default_factory=list)
    exact_path: list[Any] = field(default_factory=list)


class ScanResultReader:
    def load(self, scan_result_path: str) -> list[RemediationItem]:
        """
        Filter status=fail, flatten uncompliances → remediations thành flat list.
        """
        path = Path(scan_result_path)
        if not path.exists():
            raise FileNotFoundError(f"scan_result not found: {scan_result_path}")

        with open(path, encoding="utf-8") as f:
            data = json.load(f)

        items: list[RemediationItem] = []
        for rec in data.get("recommendations", []):
            if rec.get("status") != "fail":
                continue
            for unc in rec.get("uncompliances", []):
                file_path = unc.get("file", "")
                for rem in unc.get("remediations", []):
                    items.append(RemediationItem(
                        file=file_path,
                        action=rem["action"],
                        directive=rem["directive"],
                        args=rem.get("args", []),
                        block=rem.get("block", []),
                        line=rem.get("line", 0),
                        logical_context=rem.get("logical_context", []),
                        exact_path=rem["exact_path"],
                    ))
        return items
