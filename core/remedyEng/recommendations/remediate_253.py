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
            if server_name and not server_name.replace("_", "").replace(".", "").replace("*", "").isalnum():
                return (False, f"server_name '{server_name}' contains invalid characters")
        
        return (True, "")

    def remediate(self) -> None:
        """
        Apply remediation for Rule 2.5.3: Block access to hidden files.
        
        CRITICAL: Adds TWO location blocks:
        1. Allow /\.well-known/acme-challenge/ (MUST come first for ACME validation)
        2. Deny all /\. (hidden files)
        
        User inputs: [root_path, server_name (optional)]
        """
        self.child_ast_modified = {}
        
        # Validate user inputs first
        is_valid, error_msg = self._validate_user_inputs()
        if not is_valid:
            print(f"  Validation error: {error_msg}")
            return
        
        if not isinstance(self.child_ast_config, dict) or not self.child_ast_config:
            return

        root_path = self.user_inputs[0].strip() if len(self.user_inputs) > 0 else ""
        server_name = self.user_inputs[1].strip() if len(self.user_inputs) > 1 else ""

        for file_path, file_data in self.child_ast_config.items():
            if file_path not in self.child_scan_result:
                continue
            parsed = file_data.get("parsed") if isinstance(file_data, dict) else None
            if not isinstance(parsed, list):
                continue

            parsed_copy = copy.deepcopy(parsed)
            for remediation in self.child_scan_result[file_path]:
                if not isinstance(remediation, dict):
                    continue
                if remediation.get("action") != "add_block":
                    continue
                if remediation.get("directive") != "location":
                    continue

                rel_ctx = self._relative_context(remediation.get("context", []))
                target_list = ASTEditor.get_child_ast_config(parsed_copy, rel_ctx)
                if not isinstance(target_list, list):
                    continue

                location_args = remediation.get("args", ["~", "/\\."])
                location_block = remediation.get("block", [])
                if not isinstance(location_args, list) or not isinstance(location_block, list):
                    continue

                # Make a copy of the base block from scanner
                block_copy = copy.deepcopy(location_block)
                
                # USER-DRIVEN EXTENSION: Add root directive if provided
                if root_path:
                    self._upsert_in_block(block_copy, "root", [root_path])

                # Add the main deny-hidden-files location block
                self._upsert_location_block(target_list, location_args, block_copy)

                # CRITICAL FIX: Also add ACME allow location block BEFORE the deny block
                # This ensures Let's Encrypt certbot can validate domain ownership
                self._add_acme_exception_location(target_list)

                # Optional server_name override at parent level if requested
                if server_name:
                    self._upsert_in_block(target_list, "server_name", [server_name])

            self.child_ast_modified[file_path] = {"parsed": parsed_copy}

    @staticmethod
    def _add_acme_exception_location(target_list: list) -> None:
        """
        Add location block to allow ACME challenges (.well-known/acme-challenge/).
        
        This MUST be placed BEFORE the deny-all location block for proper nginx matching.
        Uses more specific regex match (~) rather than pattern match (^~) to ensure
        it's evaluated before the broader deny pattern.
        
        Args:
            target_list: List to add location block to (typically server block)
        """
        acme_location_args = ["~", "/\\.well-known/acme-challenge/"]
        acme_location_block = [
            {"directive": "allow", "args": ["all"]},
            {"directive": "access_log", "args": ["on"]}
        ]
        
        # Check if ACME location already exists
        for item in target_list:
            if (isinstance(item, dict) and 
                item.get("directive") == "location" and 
                item.get("args") == acme_location_args):
                # Already exists, don't add duplicate
                return
        
        # Find the position of the deny location block (if it exists)
        deny_index = -1
        for i, item in enumerate(target_list):
            if (isinstance(item, dict) and 
                item.get("directive") == "location" and 
                item.get("args") and
                len(item.get("args", [])) >= 2 and
                item.get("args")[1] == "/\\."):
                deny_index = i
                break
        
        # Create ACME location block
        acme_location = {
            "directive": "location",
            "args": copy.deepcopy(acme_location_args),
            "block": copy.deepcopy(acme_location_block)
        }
        
        # Insert BEFORE deny block (if it exists) or append at end
        if deny_index >= 0:
            target_list.insert(deny_index, acme_location)
        else:
            # Deny block not found yet, append and it will come after
            target_list.append(acme_location)

    @staticmethod
    def _upsert_location_block(block_list, args, location_block):
        """
        Update or insert location block with given args and block content.
        
        Args:
            block_list: List to modify
            args: Location args (e.g., ["~", "/\\."])
            location_block: Block content (list of directives)
        """
        for item in block_list:
            if not isinstance(item, dict):
                continue
            if item.get("directive") == "location" and item.get("args") == args:
                item["block"] = copy.deepcopy(location_block)
                return
        block_list.append(
            {
                "directive": "location",
                "args": copy.deepcopy(args),
                "block": copy.deepcopy(location_block),
            }
        )

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