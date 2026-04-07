from core.remedyEng.base_remedy import BaseRemedy
from core.recom_registry import RECOMMENDATION_REGISTRY, RecomID
from core.remedyEng.ast_editor import ASTEditor
import copy
import json

REMEDY_FIX_EXAMPLE = "http {\n    log_format main_access_json escape=json '{'\n        '\"timestamp\":           \"$time_iso8601\",'\n        '\"remote_addr\":         \"$remote_addr\",'\n        '\"remote_user\":         \"$remote_user\",'\n        '\"server_name\":         \"$server_name\",'\n        '\"request_method\":       \"$request_method\",'\n        '\"request_uri\":          \"$request_uri\",'\n        '\"status\":               $status,'\n        '\"body_bytes_sent\":      $body_bytes_sent,'\n        '\"http_referer\":         \"$http_referer\",'\n        '\"http_user_agent\":      \"$http_user_agent\",'\n        '\"x_forwarded_for\":      \"$http_x_forwarded_for\",'\n        '\"request_id\":           \"$request_id\"'\n    '}';\n\n    # Apply the format globally or per server\n    access_log /var/log/nginx/access.json main_access_json;\n}"
REMEDY_INPUT_REQUIRE = [
    "Log file path (e.g., /var/log/nginx/access.json):",
    "Log format name (e.g., main_access_json):",
    "Log format definition (JSON string):",
]


class Remediate31(BaseRemedy):
    def __init__(self) -> None:
        super().__init__(RECOMMENDATION_REGISTRY[RecomID.CIS_3_1])
        self.has_input = True
        self.has_guide_detail = True
        self.remedy_guide_detail = REMEDY_FIX_EXAMPLE
        self.remedy_input_require = REMEDY_INPUT_REQUIRE

    def remediate(self) -> None:
        """
        Apply remediation for Rule 3.1: Ensure HTTP access logging is configured.
        
        Actions: ADD_BLOCK (log_format) + ADD (access_log)
        Uses user inputs: [log_file_path, log_format_name, define_log_format]
        """
        self.child_ast_modified = {}
        
        # Validate user inputs
        if len(self.user_inputs) < 3:
            return
        
        log_file_path = self.user_inputs[0].strip()
        log_format_name = self.user_inputs[1].strip()
        log_format_def = self.user_inputs[2].strip()
        
        if not log_file_path or not log_format_name: #Future implement the default for those value
            return
        
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
                relative_context = self._get_relative_context(context)
                if not relative_context:
                    continue
                
                # Add log_format directive (with block containing format definition)
                if action == "add_block" and directive == "log_format":
                    # Parse log format definition if it's a JSON string
                    try:
                        format_dict = json.loads(log_format_def) if log_format_def.startswith("{") else {"__raw__": log_format_def}
                    except:
                        format_dict = {"__raw__": log_format_def}
                    
                    log_format_directive = {
                        "directive": "log_format",
                        "args": [log_format_name, "escape=json"],
                        "block": []
                    }
                    
                    # If format_dict is a dict, add its key-value pairs as args
                    if isinstance(format_dict, dict) and "__raw__" not in format_dict:
                        # Build args from dict
                        log_format_directive["args"] = [log_format_name, "escape=json", "{"]
                        for key, value in format_dict.items():
                            log_format_directive["args"].append(f'"{key}":{value},')
                        log_format_directive["args"][-1] = log_format_directive["args"][-1][:-1]  # Remove trailing comma
                        log_format_directive["args"].append("}")
                    else:
                        # Use raw string
                        log_format_directive["args"] = [log_format_name, "escape=json", "{"]
                        log_format_directive["args"].extend(log_format_def.split(","))
                        log_format_directive["args"].append("}")
                    
                    # Add to the target location
                    ASTEditor.append_to_context(parsed_copy, relative_context, log_format_directive)
                
                # Add access_log directive
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
    
    @staticmethod
    def _get_relative_context(full_context):
        """
        Convert full context path to relative context within parsed section.
        
        Full context: ["config", 0, "parsed", 5, "block", 14]
        Relative context: [5, "block", 14]
        """
        if not isinstance(full_context, list):
            return []
        
        # Find "parsed" key in context
        try:
            parsed_index = full_context.index("parsed")
            # Return everything after "parsed"
            return full_context[parsed_index + 1:]
        except (ValueError, IndexError):
            return []
