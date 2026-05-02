from core.recom_registry import RECOMMENDATION_REGISTRY, RecomID
from core.remedyEng.base_remedy import BaseRemedy
from core.remedyEng.ast_editor import ASTEditor
import copy

REMEDY_FIX_EXAMPLE = "http {\n\n    # Enable global logging using the detailed JSON format from Rec 3.1\n    access_log /var/log/nginx/access.json main_access_json;\n\n    server {\n\n        # Inherits the global log setting, or can be overridden:\n        access_log /var/log/nginx/example.com.access.json main_access_json;\n\n        location / {\n            # ...\n        }\n\n        # Exception: Disable logging for favicon to reduce noise (Optional)\n        location = /favicon.ico {\n            access_log      off;\n            log_not_found   off;\n        }\n    }\n}"
REMEDY_INPUT_REQUIRE = [
    "log_file_path (scope can be global/per_server/location. \nUse format<scope>: path to log file, <scope>: other path log file), ...",
    "log_not_found_control"
]


class Remediate32(BaseRemedy):
    def __init__(self) -> None:
        super().__init__(RECOMMENDATION_REGISTRY[RecomID.CIS_3_2])
        self.has_input = True
        self.has_guide_detail = True
        self.remedy_guide_detail = REMEDY_FIX_EXAMPLE
        self.remedy_input_require = REMEDY_INPUT_REQUIRE

    def _validate_user_inputs(self) -> tuple[bool, str]:
        """
        Validate user inputs for Rule 3.2.
        
        Access logging path must be absolute (start with /) or disable (off).
        """
        if len(self.user_inputs) < 1:
            return (False, "Missing log file path")
        
        log_spec = self.user_inputs[0].strip()
        if not log_spec:
            return (False, "Log file path cannot be empty")
        
        # Parse scope:path pairs and validate absolute paths
        items = [item.strip() for item in log_spec.split(",") if item.strip()]
        for item in items:
            if ":" in item:
                scope, path = item.split(":", 1)
                path_tokens = path.strip().split()
                if path_tokens and path_tokens[0] != "off":
                    if not path_tokens[0].startswith("/"):
                        return (False, f"Log file path must be absolute: {path_tokens[0]}")
            else:
                path_tokens = item.split()
                if path_tokens and path_tokens[0] != "off":
                    if not path_tokens[0].startswith("/"):
                        return (False, f"Log file path must be absolute: {path_tokens[0]}")
        
        return (True, "")

    def remediate(self) -> None:
        """
        Apply remediation for Rule 3.2 (access logging enabled).

        Uses:
        - user_inputs[0]: scoped access_log spec, ex: "global:/var/log/nginx/access.log combined,per_server:/var/log/nginx/srv.log combined"
        - user_inputs[1]: log_not_found control (on/off), optional
        """
        self.child_ast_modified = {}
        
        # Validate user inputs first
        is_valid, error_msg = self._validate_user_inputs()
        if not is_valid:
            print(f"  Validation error: {error_msg}")
            return
        
        if not isinstance(self.child_ast_config, dict) or not self.child_ast_config:
            return

        scoped_spec = self.user_inputs[0] if len(self.user_inputs) > 0 else ""
        log_not_found_value = self.user_inputs[1].strip() if len(self.user_inputs) > 1 else ""
        scope_map = self._parse_scope_map(scoped_spec)

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
                if remediation.get("directive") != "access_log":
                    continue

                context = remediation.get("context", [])
                rel_ctx = self._relative_context(context)
                if not rel_ctx:
                    continue

                target = ASTEditor.get_child_ast_config(parsed_copy, rel_ctx)
                if not isinstance(target, (list, dict)):
                    continue

                scope = self._infer_scope(rel_ctx)
                user_args = self._access_log_args_for_scope(scope_map, scope)
                args = user_args if user_args else remediation.get("args", [])
                if not isinstance(args, list) or not args:
                    continue

                action = remediation.get("action")

                # delete/modify/replace: update the offending access_log directive in place.
                if action in {"delete", "modify_directive", "replace"}:
                    if isinstance(target, dict) and target.get("directive") == "access_log":
                        target["args"] = copy.deepcopy(args)

                        # Optional log_not_found control at same block level.
                        if log_not_found_value in {"on", "off"}:
                            self._upsert_sibling_directive(
                                parsed_copy,
                                rel_ctx,
                                "log_not_found",
                                [log_not_found_value],
                            )

                    elif isinstance(target, list):
                        self._upsert_in_block(target, "access_log", args)
                        if log_not_found_value in {"on", "off"}:
                            self._upsert_in_block(target, "log_not_found", [log_not_found_value])

                # add/add_directive: add access_log into target directive list.
                elif action in {"add", "add_directive"}:
                    target_list = target if isinstance(target, list) else target.get("block") if isinstance(target, dict) else None
                    if isinstance(target_list, list):
                        self._upsert_in_block(target_list, "access_log", args)
                        if log_not_found_value in {"on", "off"}:
                            self._upsert_in_block(target_list, "log_not_found", [log_not_found_value])

            self.child_ast_modified[file_path] = {"parsed": parsed_copy}

    @staticmethod
    def _infer_scope(relative_context) -> str:
        if not isinstance(relative_context, list):
            return "global"
        block_count = relative_context.count("block")
        if block_count <= 1:
            return "global"
        if block_count == 2:
            return "per_server"
        return "location"

    @staticmethod
    def _parse_scope_map(raw_input: str):
        """Parse 'scope:value,scope:value' to {'scope': ['args', ...]} for access_log."""
        result = {}
        if not isinstance(raw_input, str):
            return result
        items = [item.strip() for item in raw_input.split(",") if item.strip()]
        for item in items:
            if ":" in item:
                scope, value = item.split(":", 1)
                scope_key = scope.strip().lower()
                value_tokens = value.strip().split()
                if scope_key and value_tokens:
                    result[scope_key] = value_tokens
            else:
                fallback_tokens = item.split()
                if fallback_tokens:
                    result["default"] = fallback_tokens
        return result

    @staticmethod
    def _access_log_args_for_scope(scope_map, scope: str):
        if not isinstance(scope_map, dict):
            return []
        for key in (scope, "global", "default"):
            if key in scope_map and isinstance(scope_map[key], list):
                return copy.deepcopy(scope_map[key])
        return []

    @staticmethod
    def _upsert_in_block(block_list, directive, args):
        if not isinstance(block_list, list):
            return
        for item in block_list:
            if isinstance(item, dict) and item.get("directive") == directive:
                item["args"] = copy.deepcopy(args)
                return
        block_list.append({"directive": directive, "args": copy.deepcopy(args)})

    @staticmethod
    def _upsert_sibling_directive(parsed_data, target_context, directive, args):
        """Upsert sibling directive inside the parent list of target_context."""
        if not isinstance(target_context, list) or not target_context:
            return
        parent_context = target_context[:-1]
        sibling_list = ASTEditor.get_child_ast_config(parsed_data, parent_context)
        if isinstance(sibling_list, list):
            Remediate32._upsert_in_block(sibling_list, directive, args)
    
    def get_user_guidance(self) -> str:
        """
        Provide step-by-step guidance for Rule 3.2 user input.
        
        Explains how to configure access logging at different nginx scopes
        and optimize log output format.
        """
        guidance = """
╔══════════════════════════════════════════════════════════════════════════════╗
║                        Rule 3.2: Enable Access Logging                       ║
╚══════════════════════════════════════════════════════════════════════════════╝

WHY THIS MATTERS:
  Access logs record every HTTP request processed by nginx: client IP, request
  method, status code, response size, referer, user agent, etc. These are
  CRITICAL for:
    • Security: Detect unusual request patterns, DoS attacks, malicious paths
    • Debugging: Understand why users see errors or slow responses
    • Compliance: Many regulations (PCI-DSS, HIPAA) require request logging
    • Analytics: Understand traffic patterns, popular endpoints

WHAT THIS RULE DOES:
  Enables access_log with appropriate format (preferably structured JSON from
  Rule 3.1) at three nginx scopes:
    • Global (http block)     → Logs ALL requests by default
    • Per-Server (server block) → Logs only requests to that domain
    • Per-Location (location)   → Logs specific API endpoints separately

STEP-BY-STEP INSTRUCTIONS:

  [STEP 1] Choose Your Logging Strategy
    
    OPTION A: Simple (Global only - Recommended for most)
      Single log file captures all requests:
      → Enter: global:/var/log/nginx/access.log combined
    
    OPTION B: Detailed (Per-server + Global)
      Different log file per domain + global fallback:
      → Enter: global:/var/log/nginx/access.log combined,per_server:/var/log/nginx/domains.log combined
    
    OPTION C: Advanced (Per-location + Per-server + Global)
      Separate logs for API vs webserver vs static assets:
      → Enter: global:/var/log/nginx/access.log combined,per_server:/var/log/nginx/domains.log combined,location:/var/log/nginx/api.log combined

  [STEP 2] Specify Log File Path
    The log file must:
      • Be ABSOLUTE PATH (start with /)
      • Be WRITABLE by nginx (typically /var/log/nginx/)
      • Have sufficient disk space
    
    Common locations:
      ✓ /var/log/nginx/access.log              (Standard, global log)
      ✓ /var/log/nginx/api.access.log          (Per-API endpoint)
      ✓ /var/log/nginx/example.com.access.log  (Per-domain)
      ✗ access.log                             (Invalid - relative path)
      ✗ /tmp/access.log                        (Risky - /tmp is cleaned up on reboot)

  [STEP 3] Choose Log Format
    Format options (AFTER you enable detailed JSON logging via Rule 3.1):
      • combined      → Standard Apache format (backward compatible)
      • main          → Nginx default format
      • main_access_json → Structured JSON (Rule 3.1)
    
    BEST PRACTICE: Use Rule 3.1 to create main_access_json format first,
                   then reference it here: /var/log/nginx/access.log main_access_json
    
    Examples:
      ✓ /var/log/nginx/access.log combined              (Simple, Apache format)
      ✓ /var/log/nginx/access.json main_access_json     (Structured JSON - preferred)
      ✗ /var/log/nginx/access.log                       (Missing format specifier)

  [STEP 4] Optional: Control log_not_found Behavior (STEP 2 Input)
    By default, nginx logs 404 errors for missing files.
    To reduce noise, you can disable logging for 404s:
      • Leave blank or "off"   → Default behavior (log 404 and missing files)
      • Enter "on"             → Explicitly enable 404 logging
      • Enter "off"            → Disable log_not_found (reduces noise for typos)

FORMATTING EXAMPLES:

  Single global log (SIMPLEST):
    global:/var/log/nginx/access.log combined

  Default server logging + global fallback:
    global:/var/log/nginx/access.log combined,per_server:/var/log/nginx/default.log combined

  Production setup with JSON + per-domain logs:
    global:/var/log/nginx/access.json main_access_json,per_server:/var/log/nginx/domains.log combined

  Separate API logs from general traffic:
    global:/var/log/nginx/access.log combined,location:/var/log/nginx/api.access.log main_access_json

VERIFICATION & TESTING:

  After remediation, check nginx config:
    grep -n "access_log" nginx.conf
  
    Expected output:
    ────────────────────────────────────────────────────────────────
    http {
        access_log /var/log/nginx/access.log combined buffer=32k;
        
        server {
            server_name example.com;
            access_log /var/log/nginx/example.com.log combined;
        }
    }
    ────────────────────────────────────────────────────────────────
  
    Syntax-oriented checks in remediation flow:
        - run nginx -t in the built-in validation loop
        - review generated diff includes access_log and optional log_not_found directives

DISK SPACE & LOG ROTATION:

  Access logs grow quickly (10-100MB per day on busy servers).
  Set up logrotate to prevent disk exhaustion:
  
    # Create /etc/logrotate.d/nginx
    /var/log/nginx/*.log {
        daily
        rotate 14
        compress
        delaycompress
        notifempty
        create 0640 www-data adm
        sharedscripts
        postrotate
            if [ -f /var/run/nginx.pid ]; then
                kill -USR1 `cat /var/run/nginx.pid`
            fi
        endscript
    }

COMMON MISTAKES:
  ✗ Relative paths:        access.log          (should be /var/log/nginx/access.log)
  ✗ Missing format spec:   /var/log/nginx/access.log (should include 'combined' or format name)
  ✗ Wrong scope:           server:/var/log/... (should be per_server, not server)
  ✗ Typos in scope names:  scope:path,scoope:path (typo: "scoope" instead of "scope")

JSON FORMAT RECOMMENDATION:
  For compliance and security analysis, use JSON format from Rule 3.1:
    Enables: Machine parsing → Easier log aggregation/analysis
    Tools: ELK Stack, Splunk, Datadog can directly ingest JSON
    Example: Parse timestamp, detect failed auth attempts, identify slow requests

────────────────────────────────────────────────────────────────────────────────
PROMPT: Enter scoped access_log paths (format: scope:/path format,scope:/path format)
        Leave BLANK to auto-detect from existing access_log directives.
        """
        return guidance.strip()