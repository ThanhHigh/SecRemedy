from core.recom_registry import RECOMMENDATION_REGISTRY, RecomID
from core.remedyEng.base_remedy import BaseRemedy

REMEDY_FIX_EXAMPLE = "location / {\n\n    # Use 'https' for Zero Trust environments (requires proxy_ssl_verify configuration)\n    # Use 'http' for standard TLS offloading (upstream traffic is unencrypted)\n    proxy_pass <protocol>://example_backend_application;\n\n    # Standard header: Appends the client IP to the list of proxies\n    proxy_set_header X-Forwarded-For    $proxy_add_x_forwarded_for;\n\n    # NGINX-specific header: Sets the direct client IP (useful for apps expecting a single value)\n    proxy_set_header X-Real-IP          $remote_addr;\n\n    # Recommended: Forward the protocol (http vs https)\n    proxy_set_header X-Forwarded-Proto $scheme;\n}"
REMEDY_INPUT_REQUIRE = [
    "proxy_pass",
]


class Remediate34(BaseRemedy):
    def __init__(self) -> None:
        super().__init__(RECOMMENDATION_REGISTRY[RecomID.CIS_3_4])
        self.has_input = True
        self.has_guide_detail = True
        self.remedy_guide_detail = REMEDY_FIX_EXAMPLE
        self.remedy_input_require = REMEDY_INPUT_REQUIRE