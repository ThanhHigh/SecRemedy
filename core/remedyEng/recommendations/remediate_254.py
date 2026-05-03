from __future__ import annotations

import copy
from typing import Any, List

from core.recom_registry import RECOMMENDATION_REGISTRY, RecomID
from core.remedyEng.ast_editor import ASTEditor
from core.remedyEng.base_remedy import BaseRemedy


REMEDY_FIX_EXAMPLE = """Rule 2.5.4 Example (Hide upstream information headers):

For reverse proxy (proxy_pass):
proxy_hide_header X-Powered-By;
proxy_hide_header Server;

For FastCGI (fastcgi_pass):
fastcgi_hide_header X-Powered-By;
"""

REMEDY_INPUT_REQUIRE: List[str] = []


class Remediate254(BaseRemedy):
    def __init__(self) -> None:
        super().__init__(RECOMMENDATION_REGISTRY[RecomID.CIS_2_5_4])
        self.has_input = False
        self.has_guide_detail = True
        self.remedy_guide_detail = REMEDY_FIX_EXAMPLE
        self.remedy_input_require = REMEDY_INPUT_REQUIRE

    def remediate(self) -> None:
        """Apply Rule 2.5.4 by adding hide_header directives in valid proxy contexts."""
        self.child_ast_modified = {}

        if not isinstance(self.child_ast_config, dict) or not self.child_ast_config:
            return

        for file_path, file_data in self.child_ast_config.items():
            if file_path not in self.child_scan_result:
                continue

            parsed = file_data.get("parsed") if isinstance(file_data, dict) else None
            if not isinstance(parsed, list):
                continue

            parsed_copy = copy.deepcopy(parsed)
            file_remediations = self.child_scan_result.get(file_path, [])
            if not isinstance(file_remediations, list):
                continue

            patches = []
            for remediation in file_remediations:
                if not isinstance(remediation, dict):
                    continue

                if remediation.get("action") not in {"add", "add_directive"}:
                    continue

                directive = remediation.get("directive")
                if directive not in {"proxy_hide_header", "fastcgi_hide_header"}:
                    continue

                args = remediation.get("args", [])
                if not isinstance(args, list) or not args or not isinstance(args[0], str):
                    continue

                hide_args = [args[0]]
                target_contexts = self._resolve_target_contexts(parsed_copy, remediation, directive)
                for target_ctx in target_contexts:
                    target_list = ASTEditor.get_child_ast_config(parsed_copy, target_ctx)
                    if not isinstance(target_list, list):
                        continue
                    if Remediate254._hide_header_present(target_list, directive, hide_args):
                        continue
                    patches.append({
                        "action": "append",
                        "exact_path": target_ctx,
                        "directive": directive,
                        "args": copy.deepcopy(hide_args),
                        "priority": 0,
                    })

            parsed_copy = ASTEditor.apply_reverse_path_patches(parsed_copy, patches)
            self.child_ast_modified[file_path] = {"parsed": parsed_copy}

    def _resolve_target_contexts(
        self,
        parsed_nodes: List[Any],
        remediation: dict,
        directive: str,
    ) -> List[List[Any]]:
        """Resolve safe insertion targets for hide_header directives."""
        contexts: List[List[Any]] = []

        rel_ctx = self._relative_context(remediation.get("context", []))
        if rel_ctx:
            target = ASTEditor.get_child_ast_config(parsed_nodes, rel_ctx)
            if isinstance(target, list):
                contexts.append(rel_ctx)
            elif isinstance(target, dict):
                block_ctx = rel_ctx + ["block"]
                block_target = ASTEditor.get_child_ast_config(parsed_nodes, block_ctx)
                if isinstance(block_target, list):
                    contexts.append(block_ctx)

        # Empty relative context maps to parsed root list and is never a valid insertion target.
        if not contexts:
            upstream_directive = "proxy_pass" if directive == "proxy_hide_header" else "fastcgi_pass"
            contexts = self._find_parent_block_contexts_for_directive(parsed_nodes, upstream_directive)

        # Final fallback by logical scope if scanner context is missing/malformed.
        if not contexts:
            logical_context = remediation.get("logical_context")
            if logical_context == "http":
                contexts = self._find_block_contexts(parsed_nodes, "http")
            elif logical_context == "server":
                contexts = self._find_block_contexts(parsed_nodes, "server")
            elif logical_context == "location":
                contexts = self._find_block_contexts(parsed_nodes, "location")

        return contexts

    @staticmethod
    def _find_parent_block_contexts_for_directive(parsed_nodes: List[Any], directive_name: str) -> List[List[Any]]:
        """Find unique parent block-list contexts that contain the target upstream directive."""
        directive_contexts = BaseRemedy._find_directive_contexts(parsed_nodes, directive_name)
        unique_contexts: List[List[Any]] = []
        seen = set()

        for context in directive_contexts:
            if not context:
                continue
            parent_ctx = context[:-1]
            key = tuple(parent_ctx)
            if key in seen:
                continue
            seen.add(key)
            unique_contexts.append(parent_ctx)

        return unique_contexts

    @staticmethod
    def _hide_header_present(block_list: List[Any], directive: str, args: List[str]) -> bool:
        """True if block_list already has equivalent hide_header line."""
        target_header = args[0].strip().lower() if args and isinstance(args[0], str) else ""
        if not target_header:
            return True

        for item in block_list:
            if not isinstance(item, dict):
                continue
            if item.get("directive") != directive:
                continue
            existing_args = item.get("args", [])
            if not isinstance(existing_args, list) or not existing_args:
                continue
            existing_header = existing_args[0].strip().lower() if isinstance(existing_args[0], str) else ""
            if existing_header == target_header:
                return True

        return False

    def get_user_guidance(self) -> str:
        return """Rule 2.5.4 (Hide upstream information headers):

This rule has NO user input - remediation is automatic.

What it does:
├─ For proxy_pass contexts: adds
│  • proxy_hide_header X-Powered-By;
│  • proxy_hide_header Server;
└─ For fastcgi_pass contexts: adds
   • fastcgi_hide_header X-Powered-By;

Purpose:
├─ Prevent backend technology disclosure in response headers
└─ Reduce reconnaissance signals for attackers

Verify:
✓ nginx -T 2>/dev/null | grep -Ei "(proxy|fastcgi)_hide_header"
✓ curl -k -I https://127.0.0.1 | grep -Ei "^(Server|X-Powered-By)"
  (Should not expose backend stack details)
"""
