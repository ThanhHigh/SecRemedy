from core.recom_registry import RECOMMENDATION_REGISTRY, RecomID
from core.remedyEng.base_remedy import BaseRemedy

REMEDY_FIX_EXAMPLE = "# Log errors to a specific file with the 'notice' level\nerror_log /var/log/nginx/error.log notice;\n\nhttp {\n    # ...\n}"
REMEDY_INPUT_REQUIRE = [
    "Scope (global/per_server/location)\nLog level (debug/info/notice/warn/error/crit/alert/emerg)\nLog file path\nFORMAT <scope>:<log_file_path>:<log_level>",
]


class Remediate33(BaseRemedy):
    def __init__(self) -> None:
        super().__init__(RECOMMENDATION_REGISTRY[RecomID.CIS_3_3])
        self.has_input = True
        self.has_guide_detail = True
        self.remedy_guide_detail = REMEDY_FIX_EXAMPLE
        self.remedy_input_require = REMEDY_INPUT_REQUIRE