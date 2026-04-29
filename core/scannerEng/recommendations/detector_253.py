from typing import Dict, List, Any, Optional
from core.scannerEng.base_recom import BaseRecom
from core.recom_registry import RecomID


class Detector253(BaseRecom):
    def __init__(self):
        super().__init__(RecomID.CIS_2_5_3)

    def scan(self, parser_output: Dict[str, Any]) -> List[Dict[str, Any]]:
        uncompliances = []

        for config_idx, config_file in enumerate(parser_output.get("config", [])):
            filepath = config_file.get("file", "")

            # Chỉ xử lý các file có đuôi .conf
            if not filepath.endswith(".conf"):
                continue

            parsed_ast = config_file.get("parsed", [])
            base_exact_path = ["config", config_idx, "parsed"]

            server_matches = self.traverse_directive(
                target_directive="server",
                directives=parsed_ast,
                filepath=filepath,
                logical_context=[],
                exact_path=base_exact_path
            )

            for match in server_matches:
                server_block = match["directive"]
                logical_context = match["logical_context"] + ["server"]
                exact_path = match["exact_path"]

                result = self._analyze_server_block(
                    server_block, filepath, logical_context, exact_path)
                if result:
                    uncompliances.append(result)

        return self._group_by_file(uncompliances)

    def _is_deny_hidden_location(self, loc: dict) -> bool:
        args = loc.get("args", [])
        if len(args) >= 2:
            arg0 = args[0].strip('"\'')
            arg1 = args[1].strip('"\'')
            if arg0 == "~" and arg1 == "/\\.":
                return True
        return False

    def _is_acme_location(self, loc: dict) -> bool:
        args = loc.get("args", [])
        if len(args) >= 2:
            arg0 = args[0].strip('"\'')
            arg1 = args[1].strip('"\'')
            if arg0 == "^~" and "/.well-known/acme-challenge/" in arg1:
                return True
        return False

    def _check_deny_location_validity(self, loc: dict) -> bool:
        block = loc.get("block", [])
        if not block:
            return False
        has_deny_all = False
        has_allow = False
        for d in block:
            if d.get("directive") == "deny":
                args = d.get("args", [])
                if args == ["all"]:
                    has_deny_all = True
            elif d.get("directive") == "allow":
                has_allow = True

        if has_allow and not has_deny_all:
            return False
        if not has_deny_all:
            return False
        return True

    def _analyze_server_block(self, server_block: dict, filepath: str, logical_context: list, exact_path: list) -> dict:
        locations = []
        block_array = server_block.get("block", [])
        for idx, child in enumerate(block_array):
            if child.get("directive") == "location":
                locations.append((idx, child))

        deny_loc = None
        deny_idx = -1
        acme_loc = None
        acme_idx = -1

        for idx, child in locations:
            if self._is_deny_hidden_location(child):
                deny_loc = child
                deny_idx = idx
            elif self._is_acme_location(child):
                acme_loc = child
                acme_idx = idx

        remediations = []

        if deny_loc is None:
            rem = {
                "action": "add",
                "directive": "location",
                "args": ["/"],
                "logical_context": logical_context,
                "exact_path": exact_path + ["block"],
                "block": []
            }
            if acme_loc is None:
                rem["block"].append({
                    "directive": "location",
                    "args": ["^~", "/.well-known/acme-challenge/"],
                    "block": [{"directive": "allow", "args": ["all"]}]
                })
            rem["block"].append({
                "directive": "location",
                "args": ["~", "/\\."],
                "block": [{"directive": "deny", "args": ["all"]}]
            })
            remediations.append(rem)
        else:
            if not self._check_deny_location_validity(deny_loc):
                rem = {
                    "action": "replace",
                    "directive": "location",
                    "args": deny_loc.get("args", []),
                    "logical_context": logical_context,
                    "exact_path": exact_path + ["block", deny_idx],
                    "block": [
                        {"directive": "deny", "args": ["all"]},
                        {"directive": "return", "args": ["404"]}
                    ]
                }
                remediations.append(rem)
            else:
                if acme_loc is not None and acme_idx > deny_idx:
                    rem = {
                        "action": "replace",
                        "directive": "location",
                        "logical_context": logical_context,
                        "exact_path": exact_path + ["block", deny_idx],
                        "block": [
                            {"directive": "deny", "args": ["all"]}
                        ]
                    }
                    remediations.append(rem)

        if remediations:
            return {
                "file": filepath,
                "remediations": remediations
            }
        return None
