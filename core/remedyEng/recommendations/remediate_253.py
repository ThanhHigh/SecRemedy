from core.recom_registry import RECOMMENDATION_REGISTRY, RecomID
from core.remedyEng.base_remedy import BaseRemedy
from core.remedyEng.ast_editor import ASTEditor
import copy
import os

REMEDY_FIX_EXAMPLE = """Rule 2.5.3 Example (Hide Sensitive Files):
├─ Input 1: root_path (web root directory)
│          Example: /var/www/html
│          WARNING: Will be checked but not enforced
│
├─ Input 2: server_name (optional override)
│          Example: (leave empty to skip)
│
├─ Result will be TWO location blocks:
│  # FIRST - Allow ACME challenges (for Let's Encrypt)
│  location ~ /\\.well-known/acme-challenge/ {
│    allow all;
│    access_log on;
│  }
│
│  # SECOND - Deny all hidden files (starting with .)
│  location ~ /\\. {
│    deny all;
│    access_log off;
│    log_not_found off;
│  }
│
├─ Important: Order matters! ACME allow MUST come before deny
├─ Without ACME exception, certbot renewal will fail
└─ Verify: curl http://your-server/.git (should return 403)
           curl http://your-server/.well-known/acme-challenge/test (should return 404, not 403)
"""
REMEDY_INPUT_REQUIRE = [
    "root_path (web root directory, will warn if not found)",
    "server_name (optional override, leave empty to skip)",
]


class Remediate253(BaseRemedy):
    def __init__(self) -> None:
        super().__init__(RECOMMENDATION_REGISTRY[RecomID.CIS_2_5_3])
        self.has_input = True
        self.has_guide_detail = True
        self.remedy_guide_detail = REMEDY_FIX_EXAMPLE
        self.remedy_input_require = REMEDY_INPUT_REQUIRE

    def _validate_user_inputs(self) -> tuple[bool, str]:
        """
        Validate user inputs for hidden file remediation.
        
        Returns:
            (is_valid: bool, error_message: str)
            Warnings (root_path not found) are printed but don't block
        """
        if len(self.user_inputs) < 1:
            return (False, "Missing root_path input")
        
        root_path = self.user_inputs[0].strip()
        
        # Validate root_path
        if not root_path:
            return (False, "root_path cannot be empty")
        if not root_path.startswith("/"):
            return (False, "root_path must be absolute (start with /)")
        
        # Warn if path doesn't exist (but don't block)
        if not os.path.exists(root_path):
            print(f"  ⚠️  Warning: root_path '{root_path}' does not exist or is not accessible")
            print(f"      (Continuing anyway - make sure it exists when nginx starts)")
        
        # Validate server_name if provided (optional)
        if len(self.user_inputs) > 1:
            server_name = self.user_inputs[1].strip()
            if server_name:
                # Reject if it contains whitespace
                if any(c.isspace() for c in server_name):
                    return (False, f"server_name '{server_name}' contains invalid characters")
                # After stripping nginx-safe non-alnum chars (_.*), remainder must be alnum or empty
                remainder = server_name.replace("_", "").replace(".", "").replace("*", "")
                if remainder and not remainder.isalnum():
                    return (False, f"server_name '{server_name}' contains invalid characters")
        
        return (True, "")

    @staticmethod
    def normalize_server_blocks_acme_order(parsed: list) -> None:
        """Ensure ACME location precedes deny-hidden in every server block (batch-safe)."""

        def walk(nodes):
            if not isinstance(nodes, list):
                return
            for node in nodes:
                if not isinstance(node, dict):
                    continue
                if node.get("directive") == "server":
                    inner = node.get("block")
                    if isinstance(inner, list):
                        Remediate253._ensure_acme_before_deny(inner)
                blk = node.get("block")
                if isinstance(blk, list):
                    walk(blk)

        walk(parsed)

    def _build_patches_253(self):
        result = {}
        if not isinstance(self.child_ast_config, dict) or not self.child_ast_config:
            return result

        root_path = self.user_inputs[0].strip() if len(self.user_inputs) > 0 else ""
        server_name = self.user_inputs[1].strip() if len(self.user_inputs) > 1 else ""

        for file_path, file_data in self.child_ast_config.items():
            if file_path not in self.child_scan_result:
                continue
            parsed = file_data.get("parsed") if isinstance(file_data, dict) else None
            if not isinstance(parsed, list):
                continue

            parsed_copy = copy.deepcopy(parsed)
            patches: list = []

            for remediation in self.child_scan_result[file_path]:
                if not isinstance(remediation, dict):
                    continue
                action = remediation.get("action")
                if action not in {"add", "add_block", "replace"}:
                    continue
                if remediation.get("directive") != "location":
                    continue

                rel_ctx = self._relative_context(ASTEditor._extract_context_path(remediation))
                target_contexts = []
                if rel_ctx:
                    target_contexts = [rel_ctx]
                elif remediation.get("logical_context") == "server":
                    target_contexts = self._find_block_contexts(parsed_copy, "server")

                if not target_contexts:
                    continue

                location_block = remediation.get("block", [])
                if action == "replace":
                    replace_args = remediation.get("args", [])
                    if not isinstance(replace_args, list):
                        replace_args = []
                    # Scanner expects deny-hidden to contain only deny all
                    replace_block = [{"directive": "deny", "args": ["all"]}]

                    # Check if target actually exists at the specified path
                    target_node = ASTEditor.get_child_ast_config(parsed_copy, rel_ctx)
                    if isinstance(target_node, dict) and target_node.get("directive") == "location":
                        # Target exists - replace it
                        patches.append({
                            "action": "replace",
                            "exact_path": rel_ctx,
                            "directive": "location",
                            "args": replace_args if replace_args else target_node.get("args", ["~", "/\\."]),
                            "block": copy.deepcopy(replace_block),
                            "priority": 0,
                        })
                    else:
                        # Target doesn't exist - add ACME + deny locations to
                        # the parent server block instead
                        parent_ctx = rel_ctx[:-1] if rel_ctx else []
                        if not parent_ctx:
                            for tc in target_contexts:
                                parent_ctx = tc
                                break
                        if parent_ctx:
                            parent_list = ASTEditor.get_child_ast_config(parsed_copy, parent_ctx)
                            # Add ACME location (empty block)
                            acme_args = ["^~", "/.well-known/acme-challenge/"]
                            acme_idx = Remediate253._location_child_index(
                                parent_list if isinstance(parent_list, list) else [], acme_args
                            )
                            if acme_idx is None:
                                patches.append({
                                    "action": "add_block",
                                    "exact_path": parent_ctx,
                                    "block": {"directive": "location", "args": acme_args, "block": []},
                                    "priority": 0,
                                })
                            # Add deny-hidden location
                            deny_args = replace_args if replace_args else ["~", "/\\."]
                            deny_idx = Remediate253._location_child_index(
                                parent_list if isinstance(parent_list, list) else [], deny_args
                            )
                            if deny_idx is None:
                                patches.append({
                                    "action": "add_block",
                                    "exact_path": parent_ctx,
                                    "block": {"directive": "location", "args": deny_args, "block": copy.deepcopy(replace_block)},
                                    "priority": 0,
                                })
                    continue

                if not isinstance(location_block, list):
                    continue

                for target_ctx in target_contexts:
                    target_list = ASTEditor.get_child_ast_config(parsed_copy, target_ctx)
                    if not isinstance(target_list, list):
                        continue

                    has_nested_locations = any(
                        isinstance(location_node, dict) and location_node.get("directive") == "location"
                        for location_node in location_block
                    )

                    if has_nested_locations:
                        for location_node in location_block:
                            if not isinstance(location_node, dict) or location_node.get("directive") != "location":
                                continue

                            node_copy = copy.deepcopy(location_node)
                            if root_path and self._is_deny_hidden_location(node_copy):
                                # Scanner expects deny-hidden to contain only deny all
                                node_copy["block"] = [{"directive": "deny", "args": ["all"]}]

                            if self._is_acme_location(node_copy):
                                node_copy["block"] = []

                            loc_args = node_copy.get("args", [])
                            idx = Remediate253._location_child_index(target_list, loc_args)
                            if idx is not None:
                                blk = node_copy.get("block")
                                patches.append({
                                    "action": "replace",
                                    "exact_path": list(target_ctx) + [idx],
                                    "directive": "location",
                                    "args": copy.deepcopy(loc_args),
                                    "block": copy.deepcopy(blk) if isinstance(blk, list) else [],
                                    "priority": 0,
                                })
                            else:
                                patches.append({
                                    "action": "add_block",
                                    "exact_path": target_ctx,
                                    "block": copy.deepcopy(node_copy),
                                    "priority": 0,
                                })
                    else:
                        acme_location = {
                            "directive": "location",
                            "args": ["^~", "/.well-known/acme-challenge/"],
                            "block": [],
                        }
                        deny_location = {
                            "directive": "location",
                            "args": copy.deepcopy(remediation.get("args", ["~", "/\\."])),
                            # Scanner expects deny-hidden to contain only deny all
                            "block": [{"directive": "deny", "args": ["all"]}],
                        }

                        acme_idx = Remediate253._location_child_index(target_list, acme_location["args"])
                        if acme_idx is not None:
                            patches.append({
                                "action": "replace",
                                "exact_path": list(target_ctx) + [acme_idx],
                                "directive": "location",
                                "args": copy.deepcopy(acme_location["args"]),
                                "block": copy.deepcopy(acme_location["block"]),
                                "priority": 0,
                            })
                        else:
                            patches.append({
                                "action": "add_block",
                                "exact_path": target_ctx,
                                "block": copy.deepcopy(acme_location),
                                "priority": 0,
                            })

                        deny_args = deny_location["args"]
                        deny_idx = Remediate253._location_child_index(target_list, deny_args)
                        if deny_idx is not None:
                            deny_blk = deny_location.get("block")
                            patches.append({
                                "action": "replace",
                                "exact_path": list(target_ctx) + [deny_idx],
                                "directive": "location",
                                "args": copy.deepcopy(deny_args),
                                "block": copy.deepcopy(deny_blk) if isinstance(deny_blk, list) else [],
                                "priority": 0,
                            })
                        else:
                            patches.append({
                                "action": "add_block",
                                "exact_path": target_ctx,
                                "block": copy.deepcopy(deny_location),
                                "priority": 0,
                            })

                    if server_name:
                        patches.append({
                            "action": "upsert",
                            "exact_path": target_ctx,
                            "directive": "server_name",
                            "args": [server_name],
                            "priority": 2,
                        })

            if patches:
                result[file_path] = [{**p, "_253_acme_order": True} for p in patches]

        return result

    def collect_patches(self):
        is_valid, _ = self._validate_user_inputs()
        if not is_valid:
            return {}
        return self._build_patches_253()

    def remediate(self) -> None:
        r"""
        Apply remediation for Rule 2.5.3: Block access to hidden files.
        
        CRITICAL: Adds TWO location blocks:
        1. Allow /\.well-known/acme-challenge/ (MUST come first for ACME validation)
        2. Deny all /\. (hidden files)
        
        User inputs: [root_path, server_name (optional)]
        """
        self.child_ast_modified = {}

        is_valid, error_msg = self._validate_user_inputs()
        if not is_valid:
            print(f"  Validation error: {error_msg}")
            return

        for file_path, patches in self._build_patches_253().items():
            parsed_copy = copy.deepcopy(self.child_ast_config[file_path]["parsed"])
            parsed_copy = ASTEditor.apply_reverse_path_patches(parsed_copy, patches)
            Remediate253.normalize_server_blocks_acme_order(parsed_copy)
            self.child_ast_modified[file_path] = {"parsed": parsed_copy}

    @staticmethod
    def _is_deny_hidden_location(node: dict) -> bool:
        args = node.get("args", [])
        if len(args) >= 2:
            return args[0].strip('"\'') == "~" and args[1].strip('"\'') == "/\\."
        return False

    @staticmethod
    def _is_acme_location(node: dict) -> bool:
        args = node.get("args", [])
        if len(args) >= 2:
            arg_str = args[1].strip('"\'')
            modifier = args[0].strip('"\'')
            # Match both regex (~) and prefix (^~) modifiers for acme challenge path
            return modifier in {"~", "^~"} and (".well-known/acme-challenge" in arg_str or r"\.well-known/acme-challenge" in arg_str)
        return False

    @staticmethod
    def _location_child_index(block_list: list, args: list) -> int | None:
        if not isinstance(block_list, list) or not isinstance(args, list):
            return None
        for i, item in enumerate(block_list):
            if isinstance(item, dict) and item.get("directive") == "location" and item.get("args") == args:
                return i
        return None

    @staticmethod
    def _ensure_acme_before_deny(block_list: list) -> None:
        r"""
        Reorder location blocks so ACME (/\.well-known/acme-challenge/) comes before 
        deny hidden files (/\.). This is critical for ACME renewal to work correctly.
        
        Args:
            block_list: The block list to potentially reorder
        """
        if not isinstance(block_list, list) or len(block_list) < 2:
            return
        
        acme_index = -1
        deny_index = -1
        
        for index, item in enumerate(block_list):
            if not isinstance(item, dict) or item.get("directive") != "location":
                continue
            if acme_index == -1 and Remediate253._is_acme_location(item):
                acme_index = index
            if deny_index == -1 and Remediate253._is_deny_hidden_location(item):
                deny_index = index
            if acme_index >= 0 and deny_index >= 0:
                break
        
        # If both exist and deny comes first, reorder
        if acme_index >= 0 and deny_index >= 0 and deny_index < acme_index:
            acme_node = block_list.pop(acme_index)
            block_list.insert(deny_index, acme_node)

    @staticmethod
    def _upsert_in_block(block_list, directive, args):
        """
        Update or insert directive within a block.
        
        Args:
            block_list: List of directives to modify
            directive: Directive name (e.g., "root", "server_name")
            args: Directive args
        """
        for item in block_list:
            if isinstance(item, dict) and item.get("directive") == directive:
                item["args"] = copy.deepcopy(args)
                return
        block_list.append({"directive": directive, "args": copy.deepcopy(args)})

    def get_user_guidance(self) -> str:
        """Return step-by-step guidance for hidden file blocking."""
        return """Rule 2.5.3 Example (Deny Hidden Files & Allow ACME):
├─ Input 1: root_path (path to web root)
│          Example: /var/www/html
│          Will warn if not found, but won't block
│
├─ Input 2: server_name (optional, leave empty to skip)
│          Example: (empty)
│          Used to override in same server block if needed
│
├─ Critical Points:
│  1. This rule creates TWO location blocks
│  2. ACME allow block MUST come FIRST
│  3. Without this, certbot renewal will fail with 403
│
├─ Resulting nginx.conf structure:
│  server {
│    # Allow Let's Encrypt validation requests
│    location ~ /\\.well-known/acme-challenge/ {
│      allow all;
│      access_log on;
│    }
│
│    # Block all other hidden files (.git, .env, etc.)
│    location ~ /\\. {
│      deny all;
│      access_log off;
│      log_not_found off;
│      root /var/www/html;
│    }
│  }
│
├─ Order matters in nginx!
│  - More specific patterns evaluated first
│  - ACME path will match before general deny-all
│
└─ Verify:
   ✓ curl http://your-server/.well-known/acme-challenge/test (404 Not Found)
   ✓ curl http://your-server/.git (403 Forbidden)
   ✓ certbot renewal works smoothly
"""