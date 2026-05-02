from core.recom_registry import RECOMMENDATION_REGISTRY, RecomID
from core.remedyEng.base_remedy import BaseRemedy
from core.remedyEng.ast_editor import ASTEditor
import copy

REMEDY_FIX_EXAMPLE = "server {\n\n    # Standard HTTPS (TCP)\n    listen 443 ssl;\n\n    # HTTP/3 (UDP)\n    listen 443 quic reuseport;\n\n    # ... SSL/TLS configuration ...\n}"
REMEDY_INPUT_REQUIRE = []

class Remediate241(BaseRemedy):
    def __init__(self) -> None:
        super().__init__(RECOMMENDATION_REGISTRY[RecomID.CIS_2_4_1])
        self.has_input = False
        self.has_guide_detail = True
        self.remedy_guide_detail = REMEDY_FIX_EXAMPLE
        self.remedy_input_require = REMEDY_INPUT_REQUIRE

    def remediate(self) -> None:
        """
        Apply remediation for Rule 2.4.1: Ensure NGINX only listens on authorized ports.
        
        Action: DELETE - Removes unauthorized listen directives.
        Note: May have multiple violations per file.
        """
        self.child_ast_modified = {}

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
            
            patches = []
            for violation in file_violations:
                if not isinstance(violation, dict):
                    continue
                
                action = violation.get("action", "")
                context = violation.get("context", [])
                directive = violation.get("directive", "")
                
                # For rule 2.4.1, we expect action="delete"
                if action != "delete" or directive != "listen":
                    continue
                
                # Convert context to relative path within this file
                relative_context = self._relative_context(context)
                if not relative_context:
                    continue

                patches.append(
                    {
                        "action": "delete",
                        "exact_path": relative_context,
                        "directive": "listen",
                        "priority": 0,
                    }
                )

            parsed_copy = ASTEditor.apply_reverse_path_patches(parsed_copy, patches)
            
            # Store modified config only if changes were made
            self.child_ast_modified[file_path] = {
                "parsed": parsed_copy
            }
    
    def get_user_guidance(self) -> str:
        """
        Provide guidance for Rule 2.4.1 (auto-remediation, no user input).
        
        Explains what happens when unauthorized listen ports are removed.
        """
        guidance = """
╔══════════════════════════════════════════════════════════════════════════════╗
║              Rule 2.4.1: Remove Non-Standard Listen Ports                    ║
╚══════════════════════════════════════════════════════════════════════════════╝

WHY THIS MATTERS:
  Listen directives specify which TCP/UDP ports nginx accepts HTTP/HTTPS traffic on.
  CIS benchmark restricts nginx to standard ports:
    • HTTP:  port 80 (unencrypted)
    • HTTPS: port 443 (encrypted)
  
  Non-standard ports (e.g., 8080, 3000, 8443) may:
    • Bypass security policies or firewalls
    • Cause unexpected traffic routes
    • Expose backend services meant to be internal-only

WHAT THIS RULE DOES:
  Auto-detects any listen directives NOT listening on 80 or 443, then REMOVES them.
  
  This is AUTOMATIC - no user input needed.
  The remediation will:
    1. Scan for violations (non-standard ports)
    2. Delete the offending listen directives
    3. Keep only port 80 and 443 directives

EXAMPLES:

  BEFORE remediation:
    ───────────────────────────────────────────────────────────────────
    server {
        listen 80;         ✓ Standard - KEPT
        listen 8080;       ✗ Non-standard - REMOVED
        listen 443 ssl;    ✓ Standard - KEPT
        listen 3000;       ✗ Non-standard - REMOVED
        server_name example.com;
        ...
    }
    ───────────────────────────────────────────────────────────────────
  
  AFTER remediation:
    ───────────────────────────────────────────────────────────────────
    server {
        listen 80;         ✓ Kept
        listen 443 ssl;    ✓ Kept
        server_name example.com;
        ...
    }
    ───────────────────────────────────────────────────────────────────

VERIFICATION & TESTING:

  After remediation, verify only standard ports remain:
    grep "^\\s*listen" nginx.conf
    
    Expected: Only 80 and 443 (with optional ssl, http2, quic)
    ✓ listen 80;
    ✓ listen 443 ssl;
    ✓ listen [::]:80;         (IPv6)
    ✓ listen [::]:443 ssl;    (IPv6)
    ✗ NO listen 8080;
    ✗ NO listen 3000;
    ✗ NO listen 8443;
  
  Test connectivity on standard ports:
    # HTTP
    curl -v http://localhost
    # HTTPS (if cert configured)
    curl -kv https://localhost
  
  Non-standard ports should no longer work:
    curl http://localhost:8080
    # Should FAIL - connection refused

IMPACT:

  BREAKING CHANGES:
    Any services relying on non-standard ports will stop working.
    Example: If your app backend was accessible at :3000, it will be removed.
  
  RECOVERY:
    If you need to keep non-standard ports:
      1. Edit nginx.conf manually to restore them
      2. Re-submit for remediation (add them back before scanning)
      3. Document exception in your CIS exception policy

COMMON SCENARIOS:

  1. Development servers using :3000, :8000, :9000
     → Remove this rule or restore those ports afterward
  
  2. Multiple nginx instances on same server
     → Each should use :80 and :443; use split configs if needed
  
  3. Health check ports (:8080)
     → Use separate health check server block, or remove if not needed
  
  4. Reverse proxy to backends on non-standard ports
     → OK! This rule only affects incoming listen ports, not proxy_pass targets
     Example: OK to have listen 80; proxy_pass http://backend:8080;

────────────────────────────────────────────────────────────────────────────────
STATUS: This rule has NO user input. Remediation is automatic and cannot be customized.
        Only standard ports (80, 443) are allowed per CIS benchmark.
        """
        return guidance.strip()
