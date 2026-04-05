from core.recom_registry import RECOMMENDATION_REGISTRY, RecomID
from core.remedyEng.base_remedy import BaseRemedy

REMEDY_FIX_EXAMPLE = ""
REMEDY_INPUT_REQUIRE = []


class Remediate251(BaseRemedy):
    def __init__(self) -> None:
        super().__init__(RECOMMENDATION_REGISTRY[RecomID.CIS_2_5_1])
        self.has_input = False
        self.has_guide_detail = False
        self.remedy_guide_detail = REMEDY_FIX_EXAMPLE
        self.remedy_input_require = REMEDY_INPUT_REQUIRE
