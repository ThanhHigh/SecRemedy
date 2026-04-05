from core.recom_registry import RECOMMENDATION_REGISTRY, RecomID
from core.remedyEng.base_remedy import BaseRemedy

REMEDY_FIX_EXAMPLE = "http {\n\n    # Enable global logging using the detailed JSON format from Rec 3.1\n    access_log /var/log/nginx/access.json main_access_json;\n\n    server {\n\n        # Inherits the global log setting, or can be overridden:\n        access_log /var/log/nginx/example.com.access.json main_access_json;\n\n        location / {\n            # ...\n        }\n\n        # Exception: Disable logging for favicon to reduce noise (Optional)\n        location = /favicon.ico {\n            access_log      off;\n            log_not_found   off;\n        }\n    }\n}"


class Remediate32(BaseRemedy):
    def __init__(self) -> None:
        super().__init__(RECOMMENDATION_REGISTRY[RecomID.CIS_3_2])
        self.has_input = True
        self.has_guide_detail = True
        self.remedy_guide_detail = REMEDY_FIX_EXAMPLE