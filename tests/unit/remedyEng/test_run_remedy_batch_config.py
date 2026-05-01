from __future__ import annotations

import json
from pathlib import Path

from core.remedyEng.run_remedy import _load_batch_jobs, _run_batch_job


def test_load_batch_jobs_resolves_server_entries(tmp_path):
    config_file = tmp_path / "remedy_config_input.json"
    config_file.write_text(
        json.dumps(
            {
                "servers": [
                    {
                        "ip": "0.0.0.0",
                        "port": 2224,
                        "ast_config": "tmp/contrast/parser_output_2224.json",
                        "scan_result": "tmp/contrast/scan_result_2224.json",
                        "remediate_ast": "tmp/output/remediated_output.json",
                        "remediate_config": "tmp/output/remediated_output.conf",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    project_root = Path(__file__).resolve().parents[3]
    jobs = _load_batch_jobs(config_file, project_root)

    assert len(jobs) == 1
    job = jobs[0]
    assert job["ast_config"] == (project_root / "tmp/contrast/parser_output_2224.json").resolve()
    assert job["scan_result"] == (project_root / "tmp/contrast/scan_result_2224.json").resolve()
    assert job["remediate_ast"] == (project_root / "tmp/output/remediated_output.json").resolve()
    assert job["remediate_config"] == (project_root / "tmp/output/remediated_output.conf").resolve()


def test_run_batch_job_writes_ast_and_config_outputs(tmp_path):
    project_root = Path(__file__).resolve().parents[3]
    job = {
        "ast_config": (project_root / "tmp/contrast/parser_output_2224.json").resolve(),
        "scan_result": (project_root / "tmp/contrast/scan_result_2224.json").resolve(),
        "remediate_ast": (tmp_path / "remediated_output.json").resolve(),
        "remediate_config": (tmp_path / "config").resolve(),
    }

    _run_batch_job(job, project_root, 1, 1)

    assert job["remediate_ast"].exists()
    assert job["remediate_config"].exists()
    assert job["remediate_config"].is_dir()

    ast_payload = json.loads(job["remediate_ast"].read_text(encoding="utf-8"))
    assert "config" in ast_payload
    assert isinstance(ast_payload["config"], list)
    assert ast_payload["config"]

    config_files = list(job["remediate_config"].rglob("*.conf"))
    assert config_files, f"No .conf files found in {job['remediate_config']}"
    
    for conf_file in config_files:
        content = conf_file.read_text(encoding="utf-8")
        assert content.strip(), f"Config file {conf_file} is empty"
