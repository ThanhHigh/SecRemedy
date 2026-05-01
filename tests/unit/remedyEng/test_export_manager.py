from pathlib import Path

from core.remedyEng.export_manager import ExportManager


def make_sample_ast():
    return {
        "status": "ok",
        "errors": [],
        "config": [
            {
                "file": "/etc/nginx/nginx.conf",
                "parsed": [
                    {"directive": "user", "args": ["www-data"]},
                    {"directive": "events", "block": [{"directive": "worker_connections", "args": ["1024"]}]},
                ],
            },
            {
                "file": "/etc/nginx/conf.d/site.conf",
                "parsed": [
                    {"directive": "server", "block": [{"directive": "listen", "args": ["80"]}]}
                ],
            },
        ],
    }


def test_export_and_tar(tmp_path):
    ast = make_sample_ast()
    scan = {"server_ip": "127.0.0.1"}
    exporter = ExportManager(ast, scan, base_tmp=tmp_path)

    out_dir, tar_path = exporter.export_config_folder()
    assert out_dir.exists()
    # check files written
    f1 = out_dir / "etc/nginx/nginx.conf"
    f2 = out_dir / "etc/nginx/conf.d/site.conf"
    assert f1.exists()
    assert f2.exists()

    created = exporter.create_tarball(out_dir, tar_path)
    assert created.exists()

    # persist parser output
    contract = tmp_path / "parser_output_test.json"
    persisted = exporter.persist_parser_output(contract)
    assert persisted.exists()