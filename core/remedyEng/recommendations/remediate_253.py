from core.recom_registry import RECOMMENDATION_REGISTRY, RecomID
from core.remedyEng.base_remedy import BaseRemedy

REMEDY_FIX_EXAMPLE = "# Allow Let's Encrypt validation (must be before the deny rule)\nlocation ^~ /.well-known/acme-challenge/ {\n    allow all;\n    default_type \"text/plain\";\n}\n\n# Deny access to all other hidden files\nlocation ~ /\\. {\n    deny all;\n    return 404;\n}"


class Remediate253(BaseRemedy):
    def __init__(self) -> None:
        super().__init__(RECOMMENDATION_REGISTRY[RecomID.CIS_2_5_3])
        self.has_input = False
        self.has_guide_detail = True
        self.remedy_guide_detail = REMEDY_FIX_EXAMPLE