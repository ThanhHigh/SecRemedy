from typing import Dict, List, Any, Optional
from core.scannerEng.base_recom import BaseRecom


class Detector33(BaseRecom):
    def __init__(self):
        super().__init__()
        self.id = "3.3"
        self.title = "Ensure error logging is enabled and set to the info logging level (Manual)"
        self.description = "The error_log directive configures logging for server errors and operational messages. The log level determines the verbosity of these messages and should be set to capture sufficient detail (typically notice or info)."
        self.audit_procedure = "Check the fully loaded configuration for error log settings and verify that error_log is defined globally in the main context. Confirm it points to a valid local file and the level is set according to internal policy."
        self.impact = "Setting the log level to info can generate a significant volume of log data, increasing disk I/O and storage requirements. Ensure that log rotation is configured and storage usage is monitored."
        self.remediation = "Configure the error_log directive in the main context to capture operational events, setting the specific logging level to align with organizational policy (typically info or notice)."

    def scan(self, parser_output: Dict[str, Any]) -> List[Dict[str, Any]]:
        uncompliances = []

        # Find if error_log is defined globally across any loaded file
        global_error_log_found = False
        nginx_conf_file = None
        nginx_conf_exact_path = None

        for config_idx, config_file in enumerate(parser_output.get("config", [])):
            filepath = config_file.get("file", "")
            if not filepath.endswith(".conf"):
                continue

            parsed_ast = config_file.get("parsed", [])
            base_exact_path = ["config", config_idx, "parsed"]

            if filepath.endswith("nginx.conf"):
                nginx_conf_file = filepath
                nginx_conf_exact_path = base_exact_path

            for idx, directive in enumerate(parsed_ast):
                if directive.get("directive") == "error_log":
                    global_error_log_found = True
                    args = directive.get("args", [])
                    level = args[1] if len(args) > 1 else "error"

                    if level not in ["info", "notice"]:
                        new_args = [args[0]] if args else [
                            "/var/log/nginx/error.log"]
                        new_args.append("info")
                        uncompliances.append({
                            "file": filepath,
                            "remediations": [
                                {
                                    "action": "modify_directive",
                                    "context": base_exact_path + [idx],
                                    "directive": "error_log",
                                    "args": new_args
                                }
                            ]
                        })

            # We also call traverse ast to process any nested error_log if needed
            # But the requirement says "globally in the main context".
            # If there are error_logs inside http/server blocks, we might not flag them here,
            # or maybe we should? The cis benchmark specifies main context.

        # If no global error_log is found, add one to main nginx.conf
        if not global_error_log_found and nginx_conf_file and nginx_conf_exact_path:
            uncompliances.append({
                "file": nginx_conf_file,
                "remediations": [
                    {
                        "action": "add_directive",
                        "context": nginx_conf_exact_path,
                        "directive": "error_log",
                        "args": ["/var/log/nginx/error.log", "info"]
                    }
                ]
            })

        return self._group_by_file(uncompliances)

    def evaluate(self, directive: Dict, filepath: str, logical_context: List[str], exact_path: List[Any]) -> Optional[Dict]:
        # Not used since scan is overridden, but implemented to avoid NotImplementedError
        return None
