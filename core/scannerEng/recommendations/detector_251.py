from typing import Dict, List, Any, Optional
from core.scannerEng.base_recom import BaseRecom, RecomID


class Detector251(BaseRecom):
    def __init__(self):
        super().__init__(RecomID.CIS_2_5_1)

    def scan(self, parser_output: Dict[str, Any]) -> List[Dict[str, Any]]:
        return []
