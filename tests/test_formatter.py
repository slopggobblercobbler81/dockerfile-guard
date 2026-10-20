"""Tests for output formatters."""

import json
from dockerfile_guard.formatter import Formatter
from dockerfile_guard.linter import Linter


def test_formatter_terminal_and_json():
    content = "FROM python:latest\nCMD python app.py"
    result = Linter().lint_text(content)

    term = Formatter.format_terminal(result)
    assert "Scanning: Dockerfile" in term
    assert "Health Score:" in term

    json_out = Formatter.format_json(result)
    data = json.loads(json_out)
    assert "score" in data
    assert "grade" in data
    assert "issues" in data
    assert len(data["issues"]) > 0


def test_formatter_markdown():
    content = "FROM alpine:3.19\nUSER app\nCMD ['sh']"
    result = Linter().lint_text(content)
    md = Formatter.format_markdown(result)
    assert "# Dockerfile Guard Report" in md
    assert "**Overall Health Grade:** `A+`" in md
