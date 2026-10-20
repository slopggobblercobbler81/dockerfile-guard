"""Tests for CLI subcommands."""

from pathlib import Path
import tempfile
from dockerfile_guard.cli import main


def test_cli_version(capsys):
    try:
        main(["--version"])
    except SystemExit as e:
        assert e.code == 0
    captured = capsys.readouterr()
    assert "dockerfile-guard" in captured.out


def test_cli_rules(capsys):
    code = main(["rules"])
    assert code == 0
    captured = capsys.readouterr()
    assert "SEC001" in captured.out
    assert "OPT001" in captured.out
    assert "Total Rules:" in captured.out


def test_cli_init():
    with tempfile.TemporaryDirectory() as tmpdir:
        target = Path(tmpdir) / ".dockerfile-guard.json"
        code = main(["init", "-o", str(target)])
        assert code == 0
        assert target.exists()


def test_cli_scan_good_and_fail_on(capsys):
    with tempfile.TemporaryDirectory() as tmpdir:
        df_path = Path(tmpdir) / "Dockerfile"
        df_path.write_text("FROM alpine:3.19\nUSER app\nCMD [\"sh\"]", encoding="utf-8")
        (Path(tmpdir) / ".dockerignore").write_text("node_modules\n", encoding="utf-8")

        # Clean scan passes
        code = main(["scan", str(df_path)])
        assert code == 0

        # Scan bad Dockerfile with --fail-on
        bad_df = Path(tmpdir) / "Dockerfile.bad"
        bad_df.write_text("FROM alpine:latest\nRUN sudo rm -rf /", encoding="utf-8")

        fail_code = main(["scan", str(bad_df), "--fail-on", "error"])
        assert fail_code == 1
