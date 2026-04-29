from core.recom_registry import RECOMMENDATION_REGISTRY, RecomID
from core.remedyEng.base_remedy import BaseRemedy
from core.remedyEng.ast_editor import ASTEditor
import copy
import re

REMEDY_FIX_EXAMPLE = """Rule 5.1.1 Example (IP-based Access Control):

Restricts access to specific IP addresses or CIDR ranges.
Uses NGINX allow and deny directives for defense-in-depth.

Example for /admin_login location:
  location /admin_login/ {
    # Allow specific monitoring server
    allow 192.168.1.100;
    # Allow internal office network
    allow 10.20.30.0/24;
    # Deny all other access
    deny all;
    # ... proxy_pass or other directives ...
  }

Verify:
✓ nginx -T 2>/dev/null | grep -E 'allow|deny'
✓ Try accessing from unauthorized IP (should be blocked)
✓ Try accessing from allowed IP (should work)

Impact: Medium. Misconfiguration can block legitimate users.
Requires maintenance as IPs change in dynamic environments.
"""
REMEDY_INPUT_REQUIRE = [
    "Enter location path to protect (e.g., /admin_login):",
    "Enter trusted IP addresses/CIDR ranges (comma-separated, e.g., 192.168.1.100, 10.0.0.0/8):"
]


class Remediate511(BaseRemedy):
    def __init__(self) -> None:
        super().__init__(RECOMMENDATION_REGISTRY[RecomID.CIS_5_1_1])
        self.has_input = True
        self.has_guide_detail = True
        self.remedy_guide_detail = REMEDY_FIX_EXAMPLE
        self.remedy_input_require = REMEDY_INPUT_REQUIRE

    def _parse_ips(self, ip_string: str) -> list:
        """
        Parse comma-separated IPs/CIDRs from user input.
        
        Args:
            ip_string: Comma-separated list of IPs/CIDRs
            
        Returns:
            List of validated IP addresses/CIDR ranges
        """
        if not ip_string:
            return []
        
        ips = [ip.strip() for ip in ip_string.split(",") if ip.strip()]
        validated_ips = []
        
        for ip in ips:
            # Basic validation: check if it looks like an IP or CIDR
            # Format: digits.digits.digits.digits or digits.digits.digits.digits/bits
            if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(/\d{1,2})?$", ip):
                validated_ips.append(ip)
        
        return validated_ips

    def _validate_user_inputs(self) -> tuple:
        """
        Validate user inputs for IP access control configuration.
        
        Returns:
            (is_valid: bool, error_message: str)
        """
        if not self.user_inputs or len(self.user_inputs) < 2:
            return (False, "Missing required inputs: location_path, ip_list")
        
        location_path = self.user_inputs[0].strip()
        ip_string = self.user_inputs[1].strip()
        
        # Validate location path
        if not location_path:
            return (False, "Location path cannot be empty")
        if not location_path.startswith("/"):
            return (False, "Location path must start with / (e.g., /admin_login)")
        
        # Validate IP list
        if not ip_string:
            return (False, "IP address list cannot be empty")
        
        ips = self._parse_ips(ip_string)
        if not ips:
            return (False, "No valid IP addresses/CIDR ranges found. Format: 192.168.1.100 or 10.0.0.0/8")
        
        return (True, "")

    def remediate(self) -> None:
        """
        Apply remediation for Rule 5.1.1: Ensure allow and deny filters limit access to IPs.
        
        Action: ADD/MODIFY - Adds allow and deny directives to location blocks
        User specifies location path and trusted IPs.
        """
        self.child_ast_modified = {}
        
        # Validate user inputs
        is_valid, error_msg = self._validate_user_inputs()
        if not is_valid:
            print(f"Warning: {error_msg}")
            return
        
        location_path = self.user_inputs[0].strip()
        ip_string = self.user_inputs[1].strip()
        ips = self._parse_ips(ip_string)
        
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
                directive = violation.get("directive", "")
                logical_context = violation.get("logical_context", [])
                exact_path = violation.get("exact_path", [])
                
                # For rule 5.1.1, we add allow and deny directives
                if action != "add" or not exact_path:
                    continue
                
                # Find or create the location block at the specified path
                target_block = ASTEditor.get_child_ast_config(parsed_copy, exact_path)
                
                if target_block and isinstance(target_block, list):
                    # Add allow directives for each IP
                    for ip in ips:
                        allow_directive = {
                            "directive": "allow",
                            "args": [ip]
                        }
                        target_block.append(allow_directive)
                    
                    # Add final deny all directive
                    deny_directive = {
                        "directive": "deny",
                        "args": ["all"]
                    }
                    target_block.append(deny_directive)
            
            # Store modified config
            self.child_ast_modified[file_path] = {
                "parsed": parsed_copy
            }

    def get_user_guidance(self) -> str:
        """Return guidance for IP access control rule."""
        return """Rule 5.1.1 (IP-Based Access Control):

This rule requires your input to configure IP restrictions.

What it does:
├─ Adds allow directives for each trusted IP/CIDR
├─ Adds deny all; to block all other access
└─ Applied to location blocks (e.g., /admin_login)

Principle of Least Privilege:
├─ Explicitly allow only known, trusted sources
├─ Implicitly deny everything else
└─ Applied at network layer before application layer

Protected Location Example:
├─ /admin_login      → Admin interface
├─ /api/internal    → Internal APIs
├─ /stats           → Monitoring endpoints
└─ /health-check    → System health endpoints

Input Format:
├─ Location: /admin_login (must start with /)
├─ IPs: 192.168.1.100 (single IP)
│       10.20.30.0/24 (CIDR range)
│       Separate multiple with commas

Result - nginx.conf will contain:
location /admin_login/ {
  allow 192.168.1.100;
  allow 10.20.30.0/24;
  deny all;
  # ... other directives ...
}

Use Cases:
├─ Admin interfaces     → Allow office IPs only
├─ Internal APIs        → Allow within company network
├─ Monitoring endpoints → Allow specific monitoring servers
└─ VPN-protected       → Allow VPN subnet range

Common CIDR Ranges:
├─ 10.0.0.0/8              - Class A private
├─ 172.16.0.0/12           - Class B private
├─ 192.168.0.0/16          - Class C private
└─ 0.0.0.0/0              - All IPs (same as "all")

Verify:
✓ nginx -t              (Syntax check)
✓ nginx -T 2>/dev/null | grep -E 'allow|deny'
✓ Test from allowed IP  (Should access normally)
✓ Test from other IP    (Should get 403 Forbidden)

Impact: Medium-High. Misconfiguration blocks legitimate traffic.
Maintenance: Update IPs when infrastructure changes (cloud instances).

Dynamic Environments:
├─ In cloud/Kubernetes, consider:
│  └─ DNS resolution via upstream variable
│  └─ geo mapping module for country-based access
│  └─ Re-evaluate strategy for dynamic IPs
└─ Document all allowed sources for audit trail
"""
