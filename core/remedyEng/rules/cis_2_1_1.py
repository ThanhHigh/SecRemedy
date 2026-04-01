import copy
from typing import Any, Dict, List

try:
    from ..base import BaseRemediation
except ImportError:  # pragma: no cover - support direct script execution
    try:
        from core.remedyEng.base import BaseRemediation
    except ImportError:
        from base import BaseRemediation


class HideVersionRule(BaseRemediation):
    """CIS 2.1.1 - Ensure server_tokens directive is set to off."""

    rule_id = "CIS-2.1.1"
    description = "Ensure server_tokens directive is set to off"

    def check(self, config_json: Any) -> bool:
        parsed = self._extract_parsed(config_json)
        http_block = self._find_http_block(parsed)
        if http_block is None:
            return False

        directive = self._find_server_tokens_directive(http_block)
        if directive is None:
            return True

        args = directive.get("args", [])
        if not args:
            return True

        return str(args[0]).lower() != "off"

    def fix(self, config_json: Any) -> Any:
        updated = copy.deepcopy(config_json)
        parsed = self._extract_parsed(updated)
        http_block = self._find_http_block(parsed)
        if http_block is None:
            return updated

        directive = self._find_server_tokens_directive(http_block)
        if directive is None:
            http_block.append({"directive": "server_tokens", "args": ["off"]})
            return updated

        directive["args"] = ["off"]
        return updated

    @staticmethod
    def _extract_parsed(config_json: Any) -> List[Dict[str, Any]]:
        if isinstance(config_json, dict):
            parsed = config_json.get("parsed")
            if isinstance(parsed, list):
                return parsed
            return []

        if isinstance(config_json, list):
            return config_json

        return []

    @staticmethod
    def _find_http_block(parsed: List[Dict[str, Any]]) -> 'List[Dict[str, Any]] | None':
        for node in parsed:
            if not isinstance(node, dict):
                continue
            if node.get("directive") == "http" and isinstance(node.get("block"), list):
                return node["block"]
        return None

    @staticmethod
    def _find_server_tokens_directive(http_block: List[Dict[str, Any]]) -> Dict[str, Any] | None:
        for node in http_block:
            if not isinstance(node, dict):
                continue
            if node.get("directive") == "server_tokens":
                return node
        return None
