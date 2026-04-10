from core.remedyEng.base_remedy import BaseRemedy
from core.recom_registry import RECOMMENDATION_REGISTRY, RecomID
from core.remedyEng.ast_editor import ASTEditor
import copy
import json

REMEDY_FIX_EXAMPLE = 'Rule 3.1 Example (JSON Logging Format):\n├─ Input 1: Log file path (e.g., /var/log/nginx/access.json)\n├─ Input 2: Log format name (e.g., main_access_json)\n├─ Input 3: JSON format definition\n│\n├─ Example JSON input:\n{\"timestamp\": \"$time_iso8601\", \"remote_addr\": \"$remote_addr\", \"status\": \"$status\", \"request\": \"$request\", \"bytes_sent\": \"$body_bytes_sent\"}\n│\n├─ Important:\n│  └─ Must be valid JSON\n│  └─ Use nginx variables (start with $)\n│  └─ String values wrapped in quotes: \"$var\"\n│  └─ Numeric values without quotes: $status, $body_bytes_sent\n│\n├─ Result in nginx.conf:\nlog_format main_access_json escape=json \'{\"timestamp\": \"$time_iso8601\", \"remote_addr\": \"$remote_addr\", \"status\": $status, \"request\": \"$request\", \"bytes_sent\": $body_bytes_sent}\';\naccess_log /var/log/nginx/access.json main_access_json;\n│\n├─ Use --json-schema-strict for stricter validation\n└─ Verify: nginx -t validation loop and generated diff output\n'
REMEDY_INPUT_REQUIRE = [
    "Log file path (e.g., /var/log/nginx/access.json):",
    "Log format name (e.g., main_access_json):",
    "Log format definition as JSON (copy-paste ready):",
]


class Remediate31(BaseRemedy):
    def __init__(self) -> None:
        super().__init__(RECOMMENDATION_REGISTRY[RecomID.CIS_3_1])
        self.has_input = True
        self.has_guide_detail = True
        self.remedy_guide_detail = REMEDY_FIX_EXAMPLE
        self.remedy_input_require = REMEDY_INPUT_REQUIRE
        self.strict_json_validation = False  # Set via CLI --json-schema-strict

    def _validate_user_inputs(self) -> tuple[bool, str]:
        """
        Validate user inputs for JSON logging configuration.
        
        Returns:
            (is_valid: bool, error_message: str)
        """
        if len(self.user_inputs) < 3:
            return (False, "Missing required inputs: log_file_path, log_format_name, log_format_definition")
        
        log_file_path = self.user_inputs[0].strip()
        log_format_name = self.user_inputs[1].strip()
        log_format_def = self.user_inputs[2].strip()
        
        # Validate log file path
        if not log_file_path:
            return (False, "Log file path cannot be empty")
        if not log_file_path.startswith("/"):
            return (False, "Log file path must be absolute (start with /)")
        
        # Validate format name
        if not log_format_name:
            return (False, "Log format name cannot be empty")
        if not log_format_name.replace("_", "").isalnum():
            return (False, "Log format name must be alphanumeric with underscores only")
        
        # Validate JSON format definition
        if not log_format_def:
            return (False, "Log format definition cannot be empty")
        
        # Try to parse as JSON
        try:
            format_dict = json.loads(log_format_def)
            if not isinstance(format_dict, dict):
                return (False, "Log format definition must be a JSON object (dict)")
            if not format_dict:
                return (False, "Log format definition cannot be an empty object")
        except json.JSONDecodeError as e:
            return (False, f"Log format is not valid JSON: {str(e)}")
        
        # If strict validation enabled, check for nginx conventions
        if self.strict_json_validation:
            for key, value in format_dict.items():
                # Check that keys are reasonable field names
                if not key.replace("_", "").isalnum():
                    return (False, f"Key '{key}' in JSON is not a valid field name (alphanumeric + _ only)")
                # Warn if value doesn't look like nginx variable (print warning, not error)
                value_str = str(value)
                if not ("$" in value_str or value_str.isdigit()):
                    print(f"  Warning: Value for key '{key}' doesn't appear to be a nginx variable: {value_str}")
        
        return (True, "")

    def _build_log_format_string(self, log_format_name: str, log_format_dict: dict) -> str:
        """
        Build a single JSON string for nginx log_format directive.
        
        Converts dict {'timestamp': '$time_iso8601', 'status': '$status'} 
        to string: '{\"timestamp\": \"$time_iso8601\", \"status\": $status}'
        
        Note: String values get quotes, numeric/variable values don't.
        
        Args:
            log_format_name: Name of the format (unused here, for reference)
            log_format_dict: Dictionary of key-value pairs for log format
            
        Returns:
            Properly formatted JSON string for use as single nginx arg
        """
        json_parts = []
        for key, value in log_format_dict.items():
            value_str = str(value).strip()
            # If value starts with $ (nginx variable) or is a number, don't quote it
            if value_str.startswith("$") or value_str.isdigit():
                json_parts.append(f'"{key}": {value_str}')
            else:
                # Otherwise treat as string and quote it
                json_parts.append(f'"{key}": "{value_str}"')
        
        formatted_json = "{" + ", ".join(json_parts) + "}"
        return formatted_json

    def remediate(self) -> None:
        """
        Apply remediation for Rule 3.1: Ensure HTTP access logging with JSON format.
        
        Actions: 
        - ADD_BLOCK (log_format directive with escape=json and JSON string)
        - ADD (access_log directive pointing to log file and format)
        
        User inputs: [log_file_path, log_format_name, log_format_definition_json]
        """
        self.child_ast_modified = {}
        
        # Validate user inputs first
        is_valid, error_msg = self._validate_user_inputs()
        if not is_valid:
            print(f"  Validation error: {error_msg}")
            return
        
        log_file_path = self.user_inputs[0].strip()
        log_format_name = self.user_inputs[1].strip()
        log_format_def = self.user_inputs[2].strip()
        
        # Parse JSON format definition
        try:
            format_dict = json.loads(log_format_def)
        except json.JSONDecodeError:
            print("  Error: Could not parse JSON format definition")
            return
        
        # Build the JSON format string
        json_format_string = self._build_log_format_string(log_format_name, format_dict)
        
        # Process each file that has violations
        for file_path, remediations in self.child_ast_config.items():
            if file_path not in self.child_scan_result:
                continue
            
            if not isinstance(remediations, dict) or "parsed" not in remediations:
                continue
            
            # Deep copy the parsed section for modification
            parsed_copy = copy.deepcopy(remediations["parsed"])
            
            # Get violations for this file
            file_violations = self.child_scan_result[file_path]
            if not isinstance(file_violations, list):
                continue
            
            # Apply each violation fix
            for violation in file_violations:
                if not isinstance(violation, dict):
                    continue
                
                action = violation.get("action", "")
                context = violation.get("context", [])
                directive = violation.get("directive", "")
                
                # Convert context to relative path
                relative_context = self._relative_context(context)
                if not relative_context:
                    continue
                
                # Add log_format directive with JSON escape parameter
                if action == "add_block" and directive == "log_format":
                    # FIXED: Build args as exactly 2 elements:
                    # [format_name, "escape=json '<JSON_STRING>'"]
                    log_format_directive = {
                        "directive": "log_format",
                        "args": [
                            log_format_name,
                            f"escape=json '{json_format_string}'"
                        ]
                    }
                    
                    # Add to the target location
                    ASTEditor.append_to_context(parsed_copy, relative_context, log_format_directive)
                
                # Add access_log directive that uses the defined format
                elif action == "add" and directive == "access_log":
                    access_log_directive = {
                        "directive": "access_log",
                        "args": [log_file_path, log_format_name]
                    }
                    
                    # Add to the target location
                    ASTEditor.append_to_context(parsed_copy, relative_context, access_log_directive)
            
            # Store modified config
            self.child_ast_modified[file_path] = {
                "parsed": parsed_copy
            }

    def get_user_guidance(self) -> str:
        """Return step-by-step guidance for JSON logging input."""
        return 'Rule 3.1 Example (JSON Logging Configuration):\n├─ Input 1: Log file path\n│          Example: /var/log/nginx/access.json\n│          Must be absolute path (start with /)\n│\n├─ Input 2: Log format name\n│          Example: main_access_json\n│          Name to reference in access_log directive\n│\n├─ Input 3: JSON format definition (copy-paste ready)\n│          Example: {"timestamp": "$time_iso8601", "status": "$status", "request": "$request"}\n│\n├─ Important Points:\n│  - Must be valid JSON (copy from example)\n│  - String variables: wrap in quotes: "$time_iso8601"\n│  - Numeric fields: no quotes: $status, $body_bytes_sent\n│\n├─ Result will be: log_format main_access_json escape=json \'{"timestamp": "$time_iso8601", "status": $status, "request": "$request"}\';\n│\n└─ Verify: nginx -t validation output and generated diff (no runtime log tail check)\n   Use --json-schema-strict flag for stricter validation before applying\n'
