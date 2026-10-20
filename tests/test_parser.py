"""Tests for Dockerfile parser."""

from dockerfile_guard.parser import DockerfileParser


def test_parser_basic_instructions():
    content = """
    FROM python:3.11-slim
    WORKDIR /app
    COPY requirements.txt .
    RUN pip install --no-cache-dir -r requirements.txt
    CMD ["python", "main.py"]
    """
    df = DockerfileParser.parse(content)
    assert len(df.instructions) == 5
    assert len(df.stages) == 1
    assert df.stages[0].base_image == "python"
    assert df.stages[0].base_tag == "3.11-slim"
    assert df.instructions[0].name == "FROM"
    assert df.instructions[4].name == "CMD"


def test_parser_multistage():
    content = """
    FROM node:20-alpine AS builder
    WORKDIR /build
    RUN npm ci

    FROM nginx:1.25-alpine
    COPY --from=builder /build/dist /usr/share/nginx/html
    """
    df = DockerfileParser.parse(content)
    assert len(df.stages) == 2
    assert df.stages[0].name == "builder"
    assert df.stages[1].name is None
    assert df.stages[1].base_image == "nginx"


def test_parser_line_continuations():
    content = """
    FROM ubuntu:22.04
    RUN apt-get update && \\
        apt-get install -y --no-install-recommends curl && \\
        rm -rf /var/lib/apt/lists/*
    """
    df = DockerfileParser.parse(content)
    assert len(df.instructions) == 2
    run_inst = df.instructions[1]
    assert run_inst.name == "RUN"
    assert "apt-get update" in run_inst.arguments
    assert "rm -rf /var/lib/apt/lists/*" in run_inst.arguments
    assert run_inst.start_line == 3
    assert run_inst.end_line == 5
