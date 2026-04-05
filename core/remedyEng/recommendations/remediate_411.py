from core.recom_registry import RECOMMENDATION_REGISTRY, RecomID
from core.remedyEng.base_remedy import BaseRemedy

REMEDY_FIX_EXAMPLE = "server {\n    listen 80;\n\n    server_name cisecurity.org;\n\n    return 301 https://$host$request_uri;\n}"
REMEDY_INPUT_REQUIRE = [
    "server_name",
    "redirect_code",
    "redirect_target"
]


class Remediate411(BaseRemedy):
    def __init__(self) -> None:
        super().__init__(RECOMMENDATION_REGISTRY[RecomID.CIS_4_1_1])
        self.has_input = True
        self.has_guide_detail = True
        self.remedy_guide_detail = REMEDY_FIX_EXAMPLE
        self.remedy_input_require = REMEDY_INPUT_REQUIRE
        