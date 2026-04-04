from core.remedyEng.base_remedy import BaseRemedy
from core.recom_registry import RECOMMENDATION_REGISTRY, RecomID

class Remediate31(BaseRemedy):
    def __init__(self) -> None:
        super().__init__(RECOMMENDATION_REGISTRY[RecomID.CIS_3_1])