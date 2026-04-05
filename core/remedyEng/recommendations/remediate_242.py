from core.recom_registry import RECOMMENDATION_REGISTRY, RecomID
from core.remedyEng.base_remedy import BaseRemedy

REMEDY_FIX_EXAMPLE = "server {\n\n    # Listen on standard ports for IPv4 and IPv6\n    listen 80 default_server;\n    listen [::]:80 default_server;\n\n    # Listen for HTTPS (TCP) and QUIC (UDP)\n    listen 443 ssl default_server;\n    listen [::]:443 ssl default_server;\n    listen 443 quic default_server;\n    listen [::]:443 quic default_server;\n\n    # Reject SSL Handshake for unknown domains (Prevents cert leakage)\n    ssl_reject_handshake on;\n\n    # Catch-all name\n    server_name _;\n\n    # Close connection without response (Non-standard code 444)\n    return 444;\n}"

class Remediate242(BaseRemedy):
    def __init__(self) -> None:
        super().__init__(RECOMMENDATION_REGISTRY[RecomID.CIS_2_4_2])
        self.has_input = True
        self.has_guide_detail = True
        self.remedy_guide_detail = REMEDY_FIX_EXAMPLE