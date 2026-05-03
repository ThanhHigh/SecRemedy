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
        # self.child_ast_modified = {}
        
        # # Validate user inputs
        # is_valid, error_msg = self._validate_user_inputs()
        # if not is_valid:
        #     print(f"Warning: {error_msg}")
        #     return
        
        # location_path = self.user_inputs[0].strip()
        # ip_string = self.user_inputs[1].strip()
        # ips = self._parse_ips(ip_string)
        
        # # Process each file that has violations
        # for file_path, remediations in self.child_ast_config.items():
        #     if file_path not in self.child_scan_result:
        #         continue
            
        #     if not isinstance(remediations, dict) or "parsed" not in remediations:
        #         continue
            
        #     # Deep copy the parsed section for modification
        #     parsed_copy = copy.deepcopy(remediations["parsed"])
            
        #     # Get violations for this file
        #     file_violations = self.child_scan_result[file_path]
        #     if not isinstance(file_violations, list):
        #         continue
            
        #     # Apply each violation fix
        #     for violation in file_violations:
        #         if not isinstance(violation, dict):
        #             continue
                
        #         action = violation.get("action", "")
        #         directive = violation.get("directive", "")
        #         exact_path = violation.get("exact_path", [])

        #         rel_ctx = self._relative_context(exact_path)
        #         if not rel_ctx:
        #             continue

        #         target = ASTEditor.get_child_ast_config(parsed_copy, rel_ctx)

        #         if action == "delete":
        #             if isinstance(target, dict) and target.get("directive") == "allow":
        #                 ASTEditor.remove_by_context(parsed_copy, rel_ctx)
        #             continue

        #         if action != "add":
        #             continue

        #         target_block = target if isinstance(target, list) else target.get("block") if isinstance(target, dict) else None

        #         if isinstance(target_block, list):
        #             # Add allow directives for each IP
        #             for ip in ips:
        #                 allow_directive = {
        #                     "directive": "allow",
        #                     "args": [ip]
        #                 }
        #                 target_block.append(allow_directive)
                    
        #             # Add final deny all directive
        #             deny_directive = {
        #                 "directive": "deny",
        #                 "args": ["all"]
        #             }
        #             target_block.append(deny_directive)
            
        #     # Store modified config
        #     self.child_ast_modified[file_path] = {
        #         "parsed": parsed_copy
        #    }
        self.child_ast_modified = {}

        self.resolve_user_inputs()

        is_valid, error_msg = self._validate_user_inputs()
        if not is_valid:
            print(f"Warning: {error_msg}")
            return

        for file_path, patches in self._build_patches_511().items():
            parsed_copy = copy.deepcopy(self.child_ast_config[file_path]["parsed"])
            parsed_copy = ASTEditor.apply_reverse_path_patches(parsed_copy, patches)
            self.child_ast_modified[file_path] = {"parsed": parsed_copy}

    def _build_patches_511(self, all_ast_config=None):
        result = {}
        ip_string = self.user_inputs[1].strip()
        ips = self._parse_ips(ip_string)

        for file_path, remediations in self.child_ast_config.items():
            if file_path not in self.child_scan_result:
                continue

            if not isinstance(remediations, dict) or "parsed" not in remediations:
                continue

            parsed_copy = copy.deepcopy(remediations["parsed"])
            file_violations = self.child_scan_result[file_path]
            if not isinstance(file_violations, list):
                continue

            patches = []
            for violation in file_violations:
                if not isinstance(violation, dict):
                    continue

                action = violation.get("action", "")
                directive = violation.get("directive", "")
                raw_path = ASTEditor._extract_context_path(violation)
                if not raw_path:
                    raw_path = violation.get("context") or []
                rel_ctx = self._relative_context(raw_path)
                if not rel_ctx:
                    continue

                if action == "delete" and directive == "allow":
                    patches.append({
                        "action": "delete",
                        "exact_path": rel_ctx,
                        "directive": "allow",
                        "priority": 2,
                    })

                elif action == "add":
                    for ip in ips:
                        patches.append({
                            "action": "add",
                            "exact_path": rel_ctx,
                            "directive": "allow",
                            "args": [ip],
                            "priority": 1,
                        })

                    patches.append({
                        "action": "add",
                        "exact_path": rel_ctx,
                        "directive": "deny",
                        "args": ["all"],
                        "priority": 0,
                    })

            if patches:
                result[file_path] = patches

        # Global sweep: delete standalone `allow all` in ACME-style locations
        # across ALL config files. Rule 2.5.3 creates these, but 5.1.1 considers
        # them violations (allow without paired deny for IP restriction).
        def _find_allow_all_patches(nodes, prefix):
            """Find `allow all` directives in location blocks that lack deny."""
            sweep_patches = []
            if not isinstance(nodes, list):
                return sweep_patches
            for idx, node in enumerate(nodes):
                if not isinstance(node, dict):
                    continue
                block = node.get("block")
                if isinstance(block, list):
                    if node.get("directive") == "location":
                        for bidx, bnode in enumerate(block):
                            if (isinstance(bnode, dict)
                                    and bnode.get("directive") == "allow"
                                    and bnode.get("args") == ["all"]):
                                # Check if this location has a matching deny
                                has_deny_all = any(
                                    isinstance(b, dict)
                                    and b.get("directive") == "deny"
                                    and b.get("args") == ["all"]
                                    for b in block
                                )
                                if not has_deny_all:
                                    sweep_patches.append({
                                        "action": "delete",
                                        "exact_path": prefix + [idx, "block", bidx],
                                        "directive": "allow",
                                        "priority": 2,
                                    })
                    sweep_patches.extend(
                        _find_allow_all_patches(block, prefix + [idx, "block"])
                    )
            return sweep_patches

        sweep_source = all_ast_config if isinstance(all_ast_config, dict) else None
        config_list = sweep_source.get("config", []) if sweep_source else []
        if not isinstance(config_list, list):
            config_list = []

        for cfg_entry in config_list:
            if not isinstance(cfg_entry, dict):
                continue
            fp = cfg_entry.get("file", "")
            parsed = cfg_entry.get("parsed")
            if not isinstance(parsed, list):
                continue

            sweep_patches = _find_allow_all_patches(parsed, [])
            if sweep_patches:
                if fp not in result:
                    result[fp] = []
                result[fp].extend(sweep_patches)

        return result

    def collect_patches(self):
        self.resolve_user_inputs()
        is_valid, _ = self._validate_user_inputs()
        if not is_valid:
            return {}
        return self._build_patches_511(all_ast_config=self._full_ast_config)

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
