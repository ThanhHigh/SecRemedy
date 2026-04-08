import json
import re
import subprocess
from copy import deepcopy
from pathlib import Path
from typing import Any, Dict, List, Set

from core.remedyEng.ast_editor import ASTEditor
from core.remedyEng.remediator import Remediator
from core.remedyEng.terminal_ui import TerminalUI


def _normalize_path(path: str) -> str:
    value = path.strip().replace("\\", "/")
    if value.startswith("./"):
        value = value[2:]
    return value.lower()


def _extract_error_paths(raw_output: str) -> List[str]:
    if not raw_output:
        return []

    # Typical nginx format: /path/to/file:line
    pattern = re.compile(r"(/[^:\s]+|[A-Za-z0-9_./-]+\.(?:conf|types|cfg|inc)):(\d+)")
    found = []
    seen = set()
    for match in pattern.finditer(raw_output):
        path = match.group(1)
        if path not in seen:
            seen.add(path)
            found.append(path)
    return found


def _expand_include_nodes(nodes: Any, config_list: List[dict], visiting: Set[int]) -> Any:
    if not isinstance(nodes, list):
        return nodes

    expanded_nodes = []
    for node in nodes:
        if not isinstance(node, dict):
            expanded_nodes.append(deepcopy(node))
            continue

        includes = node.get("includes")
        if isinstance(includes, list) and includes:
            for include_index in includes:
                if not isinstance(include_index, int):
                    continue
                if include_index in visiting:
                    continue
                if include_index < 0 or include_index >= len(config_list):
                    continue

                include_entry = config_list[include_index]
                parsed = include_entry.get("parsed", []) if isinstance(include_entry, dict) else []
                visiting.add(include_index)
                include_nodes = _expand_include_nodes(parsed, config_list, visiting)
                visiting.remove(include_index)
                if isinstance(include_nodes, list):
                    expanded_nodes.extend(include_nodes)
            continue

        node_copy = deepcopy(node)
        block = node_copy.get("block")
        if isinstance(block, list):
            node_copy["block"] = _expand_include_nodes(block, config_list, visiting)
        expanded_nodes.append(node_copy)

    return expanded_nodes


def _build_combined_entry_ast(ast_config: Dict[str, Any]) -> List[dict]:
    config_list = ast_config.get("config", [])
    if not isinstance(config_list, list) or not config_list:
        return []

    main_index = 0
    for idx, config_entry in enumerate(config_list):
        file_path = config_entry.get("file", "") if isinstance(config_entry, dict) else ""
        if Path(file_path).name == "nginx.conf":
            main_index = idx
            break

    main_entry = config_list[main_index]
    main_parsed = main_entry.get("parsed", []) if isinstance(main_entry, dict) else []
    if not isinstance(main_parsed, list):
        return []

    visiting = {main_index}
    return _expand_include_nodes(main_parsed, config_list, visiting)


def _write_combined_config(ast_config: Dict[str, Any], output_path: Path) -> None:
    combined_ast = _build_combined_entry_ast(ast_config)
    combined_text = ASTEditor.ast_to_config_text(combined_ast)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(combined_text, encoding="utf-8")


def _run_nginx_dry_test(generated_config: Path) -> tuple[bool, List[str], str]:
    cmd = ["nginx", "-t", "-c", str(generated_config)]
    process = subprocess.run(cmd, capture_output=True, text=True, check=False)
    raw_output = "\n".join([process.stdout or "", process.stderr or ""]).strip()
    error_paths = _extract_error_paths(raw_output)
    is_ok = process.returncode == 0
    return is_ok, error_paths, raw_output


def _find_candidate_remedies(applied_history: List[dict], error_paths: List[str]) -> List[str]:
    if not applied_history:
        return []

    if not error_paths:
        return [record.get("remedy_id", "") for record in applied_history if record.get("remedy_id")]

    normalized_error_paths = {_normalize_path(path) for path in error_paths}
    candidates = []
    for record in applied_history:
        touched = record.get("touched_files", [])
        touched_norm = {_normalize_path(path) for path in touched if isinstance(path, str)}
        if touched_norm.intersection(normalized_error_paths):
            remedy_id = record.get("remedy_id", "")
            if remedy_id and remedy_id not in candidates:
                candidates.append(remedy_id)

    if candidates:
        return candidates

    return [record.get("remedy_id", "") for record in applied_history if record.get("remedy_id")]


def _persist_ast_output(ast_config: Dict[str, Any], output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as f:
        json.dump(ast_config, f, indent=2)


if __name__ == "__main__":
    remediator = Remediator()
    ui = TerminalUI.get_instance()

    remediator.display_header()
    remediator.get_input_ast()
    remediator.ast_config = remediator.apply_remediations()

    output_path = Path("contracts/remediated_output.json").resolve()
    generated_path = Path("tmp/generated/nginx.generated.conf").resolve()

    should_continue = True
    iteration = 1

    while should_continue:
        ui.display_validation_header(iteration)
        _persist_ast_output(remediator.ast_config, output_path)
        _write_combined_config(remediator.ast_config, generated_path)

        is_ok, error_paths, raw_error = _run_nginx_dry_test(generated_path)
        if is_ok:
            ui.display_validation_ok(str(generated_path))
            break

        ui.display_validation_errors(error_paths=error_paths, raw_error=raw_error)
        candidate_ids = _find_candidate_remedies(remediator.applied_history, error_paths)

        action = ui.ask_post_error_action()
        if action == "stop":
            should_continue = False
            break

        if action == "rollback":
            remedy_id = ui.ask_remedy_id(candidate_ids)
            prev_len = len(remediator.applied_history)
            remediator.applied_history = [
                record
                for record in remediator.applied_history
                if record.get("remedy_id") != remedy_id
            ]
            if len(remediator.applied_history) == prev_len:
                ui.display_validation_warning(f"No applied remedy found for id {remedy_id}.")
            remediator.ast_config = remediator.replay_history()

        if action == "reapply":
            remedy_id = ui.ask_remedy_id(candidate_ids)

            # Remove existing rule record first, then rebuild a clean base for this rule.
            remediator.applied_history = [
                record
                for record in remediator.applied_history
                if record.get("remedy_id") != remedy_id
            ]
            remediator.ast_config = remediator.replay_history()

            updated_ast, new_record = remediator.apply_single_remedy_interactive(
                remedy_id=remedy_id,
                ast_input=remediator.ast_config,
            )
            remediator.ast_config = updated_ast
            if new_record is not None:
                remediator.applied_history.append(new_record)
            else:
                ui.display_validation_warning(
                    f"Remedy {remedy_id} was not reapplied."
                )

        iteration += 1

    _persist_ast_output(remediator.ast_config, output_path)
    ui.display_output_saved(str(output_path))
    ui.display_remedy_closer()