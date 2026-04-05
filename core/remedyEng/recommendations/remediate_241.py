from core.recom_registry import RECOMMENDATION_REGISTRY, RecomID
from core.remedyEng.base_remedy import BaseRemedy

REMEDY_FIX_EXAMPLE = "server {\n\n    # Standard HTTPS (TCP)\n    listen 443 ssl;\n\n    # HTTP/3 (UDP)\n    listen 443 quic reuseport;\n\n    # ... SSL/TLS configuration ...\n}"
REMEDY_INPUT_REQUIRE = []

class Remediate241(BaseRemedy):
    def __init__(self) -> None:
        super().__init__(RECOMMENDATION_REGISTRY[RecomID.CIS_2_4_1])
        self.has_input = False
        self.has_guide_detail = True
        self.remedy_guide_detail = REMEDY_FIX_EXAMPLE
        self.remedy_input_require = REMEDY_INPUT_REQUIRE
