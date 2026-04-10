from core.recom_registry import RECOMMENDATION_REGISTRY, RecomID
from core.remedyEng.base_remedy import BaseRemedy
from core.remedyEng.ast_editor import ASTEditor
import copy

REMEDY_FIX_EXAMPLE = """Rule 3.3 Example (Error Logging with Level):

Enables detailed error logging at the info level.

Input format: <log_file_path>:<log_level>
├─ Log file path: absolute path to error log
├─ Log level: one of: debug, info, notice, warn, error, crit, alert, emerg
└─ CIS recommends: info or notice

Example input: /var/log/nginx/error.log:info

Result: error_log /var/log/nginx/error.log info;
(placed in main/global context)

Log levels (in order of verbosity):
├─ debug   - very detailed (most verbose)
├─ info    - informational messages (CIS recommendation)
├─ notice  - normal but significant condition (CIS acceptable)
├─ warn    - warning conditions
├─ error   - error conditions (default)
├─ crit    - critical conditions (severe)
├─ alert   - alerts (very severe)
└─ emerg   - emergency (system unusable - least verbose)

Verify:
├─ Config loads: nginx -t
├─ Validation checks: run nginx -t and review generated diff for error_log directive
└─ No runtime log tail verification required in remediation flow
"""
REMEDY_INPUT_REQUIRE = [
    "Log file path and level (format: /var/log/nginx/error.log:info)",
]


class Remediate33(BaseRemedy):
    def __init__(self) -> None:
        super().__init__(RECOMMENDATION_REGISTRY[RecomID.CIS_3_3])
        self.has_input = True
        self.has_guide_detail = True
        self.remedy_guide_detail = REMEDY_FIX_EXAMPLE
        self.remedy_input_require = REMEDY_INPUT_REQUIRE

    def _validate_user_inputs(self) -> tuple[bool, str]:
        """
        Validate user inputs for error logging configuration.
        
        Checks:
        - Input format is <path>:<level>
        - Log level is valid nginx value
        - Log path is absolute
        
        Returns:
            (is_valid: bool, error_message: str)
        """
        if len(self.user_inputs) < 1:
            return (False, "Missing input: log_file_path:log_level (e.g., /var/log/nginx/error.log:info)")
        
        spec = self.user_inputs[0].strip()
        if not spec:
            return (False, "Input cannot be empty")
        
        # Parse input - simple format: path:level
        parts = spec.split(":")
        if len(parts) < 2:
            return (False, f"Format invalid: '{spec}'. Use format: <path>:<level> (e.g., /var/log/nginx/error.log:info)")
        
        log_file_path = parts[0].strip()
        log_level = parts[1].strip()
        
        # Validate log file path
        if not log_file_path:
            return (False, "Log file path cannot be empty")
        if not log_file_path.startswith("/"):
            return (False, f"Log file path must be absolute (start with /). Got: {log_file_path}")
        
        # Validate log level
        allowed_levels = ["debug", "info", "notice", "warn", "error", "crit", "alert", "emerg"]
        if log_level.lower() not in allowed_levels:
            return (False, f"Log level '{log_level}' is invalid. Allowed: {', '.join(allowed_levels)}")
        
        return (True, "")

    def remediate(self) -> None:
        """
        Apply remediation for Rule 3.3: Set error logging with appropriate level.

        Input format: "<log_file_path>:<log_level>"
        Example: "/var/log/nginx/error.log:info"
        
        Log level MUST be valid nginx value.
        """
        self.child_ast_modified = {}
        
        # Validate user inputs first
        is_valid, error_msg = self._validate_user_inputs()
        if not is_valid:
            print(f"  Validation error: {error_msg}")
            return
        
        if not isinstance(self.child_ast_config, dict) or not self.child_ast_config:
            return

        # Parse the input
        spec = self.user_inputs[0].strip()
        parts = spec.split(":")
        log_file_path = parts[0].strip()
        log_level = parts[1].strip().lower()
        
        # Build args for error_log directive
        error_log_args = [log_file_path, log_level]

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
                if remediation.get("directive") != "error_log":
                    continue

                context = remediation.get("context", [])
                rel_ctx = self._relative_context(context)
                if not rel_ctx:
                    continue

                # Verify scope is global (main context) as per CIS requirement
                scope = self._infer_scope(rel_ctx)
                if scope != "global":
                    print(f"  ⚠️  Warning: error_log setting should be in main/global context, not {scope}")

                action = remediation.get("action")
                if action in {"modify_directive", "replace"}:
                    target = ASTEditor.get_child_ast_config(parsed_copy, rel_ctx)
                    if isinstance(target, dict) and target.get("directive") == "error_log":
                        target["args"] = error_log_args
                elif action in {"add", "add_directive"}:
                    target_list = ASTEditor.get_child_ast_config(parsed_copy, rel_ctx)
                    if isinstance(target_list, list):
                        self._upsert_in_block(target_list, "error_log", error_log_args)

            self.child_ast_modified[file_path] = {"parsed": parsed_copy}

    @staticmethod
    def _infer_scope(relative_context) -> str:
        """Infer scope (global/per_server/location) from relative context depth."""
        if not isinstance(relative_context, list):
            return "global"
        block_count = relative_context.count("block")
        if block_count <= 1:
            return "global"
        if block_count == 2:
            return "per_server"
        return "location"

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
        """Return step-by-step guidance for error logging configuration."""
        return """Rule 3.3 Example (Error Logging Level):

Enables detailed error logging at a specified level.

Input format:
├─ <log_file_path>:<log_level>
├─ Example: /var/log/nginx/error.log:info
└─ Both parts required

Log file path:
├─ Must be absolute (start with /)
├─ Examples: /var/log/nginx/error.log
│            /var/log/nginx/errors.log
└─ Directory must exist and be writable by nginx user

Log levels (choose one):
├─ debug    - Very detailed, troubleshooting only (most verbose)
├─ info     - Informational messages ← CIS RECOMMENDS
├─ notice   - Normal but significant ← CIS ACCEPTABLE  
├─ warn     - Warning conditions (default for most)
├─ error    - Error conditions (nginx default)
├─ crit     - Critical severity
├─ alert    - Alert severity
└─ emerg    - Emergency (system unusable - least verbose)

Result: error_log /var/log/nginx/error.log info;
(placed in main/global context - not per-server)

Important:
├─ Must be in GLOBAL context (main block)
├─ Per-server error_log overrides are allowed
├─ More verbose = more disk I/O (watch storage)
└─ CIS recommends: info or notice

Verify:
├─ 1. nginx -t (config syntax check)
├─ 2. review generated diff contains expected error_log path and level
├─ 3. confirm validation loop reports successful nginx -t
└─ 4. keep runtime log observation optional outside remediation flow
"""