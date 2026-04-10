from core.recom_registry import RECOMMENDATION_REGISTRY, RecomID
from core.remedyEng.base_remedy import BaseRemedy
from core.remedyEng.ast_editor import ASTEditor
import copy

REMEDY_FIX_EXAMPLE = """Rule 2.4.2 Example (Default Server Block - Catch-All):

Catches requests to unknown domain names and rejects them cleanly.

Structure to create (or update):
  server {
    listen 80 default_server;
    listen [::]:80 default_server;
    listen 443 ssl default_server;
    listen [::]:443 ssl default_server;
    listen 443 quic default_server;
    listen [::]:443 quic default_server;
    
    server_name _;          # Wildcard - matches anything
    
    ssl_reject_handshake on;  # Prevent TLS cert leakage for unknown domains
    return 444;               # Close connection (nginx code: close connection)
  }

Important: This block MUST be FIRST in http block (CIS requirement).
Use --strict-placement flag to enforce position 0 insertion.
"""
REMEDY_INPUT_REQUIRE = [
    "server_name (default: '_' for wildcard)",
]


class Remediate242(BaseRemedy):
    def __init__(self) -> None:
        super().__init__(RECOMMENDATION_REGISTRY[RecomID.CIS_2_4_2])
        self.has_input = True
        self.has_guide_detail = True
        self.remedy_guide_detail = REMEDY_FIX_EXAMPLE
        self.remedy_input_require = REMEDY_INPUT_REQUIRE
        self.strict_placement = False  # Set via CLI --strict-placement

    def _validate_user_inputs(self) -> tuple[bool, str]:
        """
        Validate user inputs for default server configuration.
        
        Returns:
            (is_valid: bool, error_message: str)
        """
        if len(self.user_inputs) < 1:
            # Default to _ (wildcard)
            self.user_inputs = ["_"]
            return (True, "")
        
        server_name = self.user_inputs[0].strip()
        
        # If empty, default to _
        if not server_name:
            self.user_inputs[0] = "_"
            return (True, "")
        
        # Validate server_name format
        if not (server_name == "_" or server_name.replace(".", "").replace("-", "").isalnum()):
            return (False, f"server_name '{server_name}' is invalid (use '_' for wildcard or domain names)")
        
        return (True, "")

    def remediate(self) -> None:
        """
        Apply remediation for Rule 2.4.2: Create default (catch-all) server block.
        
        This block rejects requests for unknown hostnames.
        CRITICAL: Must be placed FIRST in http block (CIS requirement).
        
        Uses CLI flag: --strict-placement (optional, default: False)
        - If True: use position 0 insertion
        - If False: append to end (safe default)
        
        User input: [server_name]  (default: "_" for wildcard)
        """
        self.child_ast_modified = {}
        
        # Validate user inputs first
        is_valid, error_msg = self._validate_user_inputs()
        if not is_valid:
            print(f"  Validation error: {error_msg}")
            return
        
        if not isinstance(self.child_ast_config, dict) or not self.child_ast_config:
            return

        server_name = self.user_inputs[0].strip() if len(self.user_inputs) > 0 else "_"
        if not server_name:
            server_name = "_"

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
                
                action = remediation.get("action", "")
                context = remediation.get("context", [])
                directive = remediation.get("directive", "")
                
                rel_ctx = self._relative_context(context)
                target_list = ASTEditor.get_child_ast_config(parsed_copy, rel_ctx)
                if not isinstance(target_list, list):
                    continue

                # CASE 1: add_directive - Add directives to existing server block
                if action in {"add", "add_directive"} and directive in {"return", "ssl_reject_handshake"}:
                    args = remediation.get("args", [])
                    if isinstance(args, list):
                        self._upsert_in_block(target_list, directive, args)
                    
                    # Also add server_name if not already present
                    self._upsert_in_block(target_list, "server_name", [server_name])
                
                # CASE 2: add_block - Create entire default server block
                # (NEW FEATURE to handle full server block creation)
                elif action == "add_block" and directive == "server":
                    position_hint = remediation.get("position", -1)
                    
                    # Create the default server block structure
                    default_server_block = self._build_default_server_block(server_name)
                    
                    # Insert at position 0 if strict_placement enabled and position_hint == 0
                    if self.strict_placement and position_hint == 0:
                        # Insert at beginning of http block (position 0)
                        success = ASTEditor.insert_to_context(parsed_copy, rel_ctx, 0, default_server_block)
                        if success:
                            print(f"  ✓ Inserted default server block at position 0 (CIS-compliant)")
                        else:
                            # Fallback to append
                            ASTEditor.append_to_context(parsed_copy, rel_ctx, default_server_block)
                    else:
                        # Default: append to end (safe)
                        if position_hint == 0:
                            print(f"  ℹ️  Position 0 specified but --strict-placement flag not set")
                            print(f"     Use --strict-placement to enforce CIS placement requirement")
                        ASTEditor.append_to_context(parsed_copy, rel_ctx, default_server_block)

            self.child_ast_modified[file_path] = {"parsed": parsed_copy}

    @staticmethod
    def _build_default_server_block(server_name: str) -> dict:
        """
        Build a complete default (catch-all) server block structure.
        
        This block:
        - Listens on all ports (80, 443) for both IPv4 and IPv6
        - Matches any server_name (via _ wildcard)
        - Returns 444 (nginx: close connection) for HTTP
        - Returns ssl_reject_handshake on for HTTPS (prevents cert info leakage)
        
        Args:
            server_name: server_name value to use (typically "_")
            
        Returns:
            Dict representing the server block
        """
        block_directives = [
            {"directive": "listen", "args": ["80", "default_server"]},
            {"directive": "listen", "args": ["[::]:80", "default_server"]},
            {"directive": "listen", "args": ["443", "ssl", "default_server"]},
            {"directive": "listen", "args": ["[::]:443", "ssl", "default_server"]},
            {"directive": "listen", "args": ["443", "quic", "default_server"]},
            {"directive": "listen", "args": ["[::]:443", "quic", "default_server"]},
            {"directive": "server_name", "args": [server_name]},
            {"directive": "ssl_reject_handshake", "args": ["on"]},
            {"directive": "return", "args": ["444"]}
        ]
        
        return {
            "directive": "server",
            "args": [],
            "block": block_directives
        }

    @staticmethod
    def _upsert_in_block(block_list, directive, args):
        """Update or insert directive within a block."""
        if not isinstance(block_list, list):
            return
        for item in block_list:
            if isinstance(item, dict) and item.get("directive") == directive:
                item["args"] = copy.deepcopy(args)
                return
        block_list.append({"directive": directive, "args": copy.deepcopy(args)})

    def get_user_guidance(self) -> str:
        """Return step-by-step guidance for default server configuration."""
        return """Rule 2.4.2 Example (Reject Unknown Hostnames):

This creates a catch-all server block that rejects requests
for domains not explicitly defined elsewhere.

Input:
├─ server_name (default: '_' for wildcard)
├─ Example: _
└─ Leave empty to use default wildcard

What it does:
├─ Catches ALL unmatched requests
├─ Returns 444 (close connection) for HTTP
├─ Returns ssl_reject_handshake for HTTPS
└─ Prevents info leakage for unknown domains

Result - adds this server block to http block:
server {
  listen 80 default_server;
  listen [::]:80 default_server;
  listen 443 ssl default_server;
  listen [::]:443 ssl default_server;
  listen 443 quic default_server;
  listen [::]:443 quic default_server;
  
  server_name _;
  ssl_reject_handshake on;
  return 444;
}

CRITICAL: CIS requires this block FIRST in http block.
Use flag: --strict-placement (enables position 0 insertion)

Without this flag: appended to end (safe but not CIS-compliant order)
With this flag: inserted at position 0 (CIS-compliant)

Verify:
✓ curl -I http://random-domain.invalid (connection refused)
✓ nginx -t (config is valid)
✓ nginx process starts without errors
"""