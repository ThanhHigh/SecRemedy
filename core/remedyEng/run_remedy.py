import json
from pathlib import Path

from core.remedyEng.remediator import Remediator
from core.remedyEng.terminal_ui import TerminalUI

if __name__ == "__main__":
    # Tạo instance của Remediator
    remediator = Remediator()

    remediator.display_header()
    remediator.get_input_ast()
    remediator.ast_config = remediator.apply_remediations()

    output_path = Path("contracts/remediated_output.json").resolve()
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(remediator.ast_config, f, indent=2)

    TerminalUI.get_instance().display_output_saved(str(output_path))
    TerminalUI.get_instance().display_remedy_closer()