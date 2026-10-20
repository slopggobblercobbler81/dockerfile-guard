"""Tests for linter and grading calculations."""

from pathlib import Path
import tempfile
from dockerfile_guard.linter import Linter


def test_linter_clean_dockerfile():
    clean_content = """
    FROM python:3.11-slim
    WORKDIR /app
    RUN useradd -m appuser
    USER appuser
    COPY --chown=appuser:appuser . .
    CMD ["python", "app.py"]
    """
    linter = Linter()
    result = linter.lint_text(clean_content)
    assert result.error_count == 0
    assert result.warning_count == 0
    assert result.score == 100
    assert result.grade == "A+"


def test_linter_scoring_and_penalties():
    bad_content = """
    FROM python:latest
    ENV AWS_SECRET_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE
    RUN sudo apt-get update
    COPY . .
    RUN pip install flask
    CMD python main.py
    """
    linter = Linter()
    result = linter.lint_text(bad_content)
    assert result.error_count >= 2  # SEC002 (sudo), SEC004 (secret)
    assert result.warning_count >= 2  # OPT001 (:latest), SEC001 (user), REL001 (shell form)
    assert result.score < 60
    assert result.grade == "F"


def test_linter_ignore_rules():
    content = "FROM python:latest\nCMD ['python']"
    linter_normal = Linter()
    res1 = linter_normal.lint_text(content)
    assert any(i.rule_id == "OPT001" for i in res1.issues)

    linter_ignored = Linter(ignored_rules=["OPT001"])
    res2 = linter_ignored.lint_text(content)
    assert not any(i.rule_id == "OPT001" for i in res2.issues)


def test_linter_file_and_dockerignore_detection():
    with tempfile.TemporaryDirectory() as tmpdir:
        dockerfile_path = Path(tmpdir) / "Dockerfile"
        dockerfile_path.write_text("FROM alpine:3.19\nUSER app\nCMD ['sh']", encoding="utf-8")

        linter = Linter()
        result = linter.lint_file(str(dockerfile_path))
        # Missing .dockerignore should be reported
        assert any(i.rule_id == "OPT006" for i in result.issues)

        # Create .dockerignore and rerun
        (Path(tmpdir) / ".dockerignore").write_text(".git\n", encoding="utf-8")
        result2 = linter.lint_file(str(dockerfile_path))
        assert not any(i.rule_id == "OPT006" for i in result2.issues)
