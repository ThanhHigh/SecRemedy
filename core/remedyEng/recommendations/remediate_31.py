from core.remedyEng.base_remedy import BaseRemedy
from core.recom_registry import RECOMMENDATION_REGISTRY, RecomID

REMEDY_FIX_EXAMPLE = "http {\n    log_format main_access_json escape=json '{'\n        '\"timestamp\":           \"$time_iso8601\",'\n        '\"remote_addr\":         \"$remote_addr\",'\n        '\"remote_user\":         \"$remote_user\",'\n        '\"server_name\":         \"$server_name\",'\n        '\"request_method\":       \"$request_method\",'\n        '\"request_uri\":          \"$request_uri\",'\n        '\"status\":               $status,'\n        '\"body_bytes_sent\":      $body_bytes_sent,'\n        '\"http_referer\":         \"$http_referer\",'\n        '\"http_user_agent\":      \"$http_user_agent\",'\n        '\"x_forwarded_for\":      \"$http_x_forwarded_for\",'\n        '\"request_id\":           \"$request_id\"'\n    '}';\n\n    # Apply the format globally or per server\n    access_log /var/log/nginx/access.json main_access_json;\n}"
REMEDY_INPUT_REQUIRE = [
    "log_file_path",
    "log_format_name",
    "define_log_format",
]


class Remediate31(BaseRemedy):
    def __init__(self) -> None:
        super().__init__(RECOMMENDATION_REGISTRY[RecomID.CIS_3_1])
        self.has_input = True
        self.has_guide_detail = True
        self.remedy_guide_detail = REMEDY_FIX_EXAMPLE
        self.remedy_input_require = REMEDY_INPUT_REQUIRE
