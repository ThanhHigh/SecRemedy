from enum import Enum
from dataclasses import dataclass
from typing import List, Dict, Optional


class RecomID(str, Enum):
    """
    Unique identifier for each CIS Recommendation.
    Using Enum (str) for fast O(1) dictionary retrieval and IDE autocompletion.
    """
    CIS_2_4_1 = "2.4.1"
    CIS_2_4_2 = "2.4.2"
    CIS_2_5_1 = "2.5.1"
    CIS_2_5_2 = "2.5.2"
    CIS_2_5_3 = "2.5.3"
    CIS_3_1 = "3.1"
    CIS_3_2 = "3.2"
    CIS_3_3 = "3.3"
    CIS_3_4 = "3.4"
    CIS_4_1_1 = "4.1.1"


@dataclass(frozen=True)
class Recommendation:
    """
    In-memory data structure for storing recommendation metadata.
    'frozen=True' ensures data integrity at run-time.
    """
    id: RecomID
    title: str
    level: int
    profiles: List[str]
    description: str
    rationale: str
    impact: str
    audit_procedure: str
    remediation_procedure: str
    default_value: str


# Fast-to-retrieve In-Memory Registry (RAM)
# Both Scanner Engine (Detectors) and Remediation Engine (Injectors) can import this.
RECOMMENDATION_REGISTRY: Dict[RecomID, Recommendation] = {
    RecomID.CIS_2_4_1: Recommendation(
        id=RecomID.CIS_2_4_1,
        title="Ensure NGINX only listens for network connections on authorized ports",
        level=1,
        profiles=["Webserver", "Proxy", "Loadbalancer"],
        description="NGINX should be configured to listen only on authorized ports and protocols (TCP 80/443, UDP 443).",
        rationale="Limiting listening ports ensures that no hidden or unintended services are exposed via NGINX.",
        impact="Disabling unused ports reduces attack surface but might break HTTP/3 if UDP 443 is blocked.",
        audit_procedure="nginx -T | grep 'listen'",
        remediation_procedure="Remove or comment out any listen directives that bind to unauthorized ports.",
        default_value="TCP port 80 (standard), TCP/UDP 443 (secure)."
    ),
    RecomID.CIS_2_4_2: Recommendation(
        id=RecomID.CIS_2_4_2,
        title="Ensure requests for unknown host names are rejected",
        level=1,
        profiles=["Webserver", "Proxy", "Loadbalancer"],
        description="Catch-all default server blocks should reject unknown hostnames to prevent Host Header attacks.",
        rationale="Prevents NGINX from serving applications to arbitrary domains pointing to the server's IP.",
        impact="Direct access via IP or unconfigured CNAMEs will be rejected. This is intended behavior but requires that all valid domains are explicitly defined in their own server blocks.",
        audit_procedure="Check for 'listen ... default_server' with 'return 444;' or 'ssl_reject_handshake on;'.",
        remediation_procedure="Configure a 'Catch-All' default server block as the first block in your configuration (or explicitly marked with default_server). After adding this block, ensure all your valid applications have their own server blocks with explicit server_name directives.",
        default_value="NGINX uses the first server block if no default_server is defined."
    ),
    RecomID.CIS_2_5_1: Recommendation(
        id=RecomID.CIS_2_5_1,
        title="Ensure server_tokens directive is set to off",
        level=1,
        profiles=["Webserver", "Proxy", "Loadbalancer"],
        description="Disables the display of NGINX version number on error pages and response headers.",
        rationale="Attackers can use version information to target known vulnerabilities.",
        impact="None.",
        audit_procedure="Check nginx.conf for 'server_tokens off;'.",
        remediation_procedure="Add 'server_tokens off;' to the http block in nginx.conf.",
        default_value="on"
    ),
    RecomID.CIS_2_5_2: Recommendation(
        id=RecomID.CIS_2_5_2,
        title="Ensure default error and index.html pages do not reference NGINX",
        level=1,
        profiles=["Webserver", "Proxy", "Loadbalancer"],
        description="Replaces standard NGINX branding on 404, 500 error pages with generic content.",
        rationale="Visual identification of server software aids reconnaissance.",
        impact="Requires administrative effort to create/maintain custom pages.",
        audit_procedure="Trigger an error and check for 'nginx' signature in the body.",
        remediation_procedure="Configure custom error_page directives pointing to generic HTML files.",
        default_value="Default pages identify the server as NGINX."
    ),
    RecomID.CIS_2_5_3: Recommendation(
        id=RecomID.CIS_2_5_3,
        title="Ensure hidden file serving is disabled",
        level=1,
        profiles=["Webserver", "Proxy", "Loadbalancer"],
        description="Blocks access to hidden files/directories (starting with a dot, e.g., .git, .env).",
        rationale="Hidden files often contain sensitive metadata or environment configurations.",
        impact="May break Let's Encrypt validation unless exceptions are made.",
        audit_procedure="Try accessing a dummy hidden file or check for 'location ~ /\\. { deny all; }'.",
        remediation_procedure="Add a location block denying access to all hidden files.",
        default_value="Disabled by default (NGINX serves everything in web root)."
    ),
    RecomID.CIS_3_1: Recommendation(
        id=RecomID.CIS_3_1,
        title="Ensure detailed logging is enabled",
        level=1,
        profiles=["Webserver", "Proxy", "Loadbalancer"],
        description="Configure structured logging (JSON) to facilitate incident response and SIEM integration.",
        rationale="Structured logs provide searchable context without complex parsing.",
        impact="Increases log volume/disk usage.",
        audit_procedure="Inspect log_format and access_log directives.",
        remediation_procedure="Define a JSON log_format and apply it to access_log.",
        default_value="Combined text format."
    ),
    RecomID.CIS_3_2: Recommendation(
        id=RecomID.CIS_3_2,
        title="Ensure access logging is enabled",
        level=1,
        profiles=["Webserver", "Proxy", "Loadbalancer"],
        description="Guarantees that all client requests are recorded for audit and security analysis.",
        rationale="Essential for tracking system usage and detecting attacks.",
        impact="High disk space usage if not rotated properly.",
        audit_procedure="Verify access_log points to a valid file path.",
        remediation_procedure="Enable access_log in the http block.",
        default_value="Enabled (combined format)."
    ),
    RecomID.CIS_3_3: Recommendation(
        id=RecomID.CIS_3_3,
        title="Ensure error logging is enabled and set to the info logging level",
        level=1,
        profiles=["Webserver", "Proxy", "Loadbalancer"],
        description="Captures operational failures and server errors at the 'info' verbosity level.",
        rationale="Required for diagnosing internal failures and anomalies.",
        impact="Increases disk I/O and storage needs.",
        audit_procedure="Verify error_log level is set to 'info' or 'notice'.",
        remediation_procedure="Configure 'error_log ... info;' in the main context.",
        default_value="error level."
    ),
    RecomID.CIS_3_4: Recommendation(
        id=RecomID.CIS_3_4,
        title="Ensure proxies pass source IP information",
        level=1,
        profiles=["Proxy", "Loadbalancer"],
        description="Forwards the original client IP to upstream servers via X-Forwarded-For or X-Real-IP headers.",
        rationale="Backend applications need client IPs for auditing and access control.",
        impact="Allows visibility of true IPs; requires careful header handling to prevent spoofing.",
        audit_procedure="Check for proxy_set_header directives.",
        remediation_procedure="Add 'proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;' in proxied locations.",
        default_value="Headers are not added by default."
    ),
    RecomID.CIS_4_1_1: Recommendation(
        id=RecomID.CIS_4_1_1,
        title="Ensure HTTP is redirected to HTTPS",
        level=1,
        profiles=["Webserver", "Proxy", "Loadbalancer"],
        description="Redirects all unencrypted HTTP traffic to secure HTTPS connections.",
        rationale="Enforces encryption for all user communications.",
        impact="Slight performance overhead for TLS handshake.",
        audit_procedure="Verify a 'return 301 https://$host$request_uri;' exists for port 80 blocks.",
        remediation_procedure="Add a return directive in the HTTP server block for redirection.",
        default_value="Not redirected by default."
    ),
}
