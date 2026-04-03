from core.scannerEng.recommendations.detector_253 import Detector253
import json
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(
    os.path.dirname(os.path.abspath(__file__)))))

with open('contracts/config_ast_2222.json') as f:
    data = json.load(f)
    ast = data.get("config", [])

det = Detector253()
for file_obj in ast:
    filepath = file_obj['file']
    for directive in file_obj['parsed']:
        res = det.evaluate(directive, filepath, [], [])
        if res:
            print(f"FAILED on {filepath}")
        elif directive.get("directive") == "server":
            print(f"PASSED on {filepath}")
