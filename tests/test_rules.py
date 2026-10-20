"""Tests for individual Dockerfile rules."""

from dockerfile_guard.parser import DockerfileParser
from dockerfile_guard.rules import (
    Sec001MissingUser,
    Sec002SudoUsage,
    Sec003InsecureScriptExecution,
    Sec004HardcodedSecret,
    Opt001UnpinnedImageTag,
    Opt002SuboptimalCacheOrder,
    Opt003UncleanedAptCache,
    Opt004PipNoCacheDir,
    Opt005UseCopyInsteadOfAdd,
    Rel001ShellFormExec,
    Rel002MultipleCmd,
    Rel003MissingHealthcheck,
)


def test_sec001_missing_user():
    rule = Sec001MissingUser()
    # Missing user
    df1 = DockerfileParser.parse("FROM python:3.11\nCMD ['python']")
    assert len(rule.check(df1)) == 1

    # Has user
    df2 = DockerfileParser.parse("FROM python:3.11\nUSER appuser\nCMD ['python']")
    assert len(rule.check(df2)) == 0


def test_sec002_sudo_usage():
    rule = Sec002SudoUsage()
    df = DockerfileParser.parse("FROM ubuntu:22.04\nRUN sudo apt-get update")
    issues = rule.check(df)
    assert len(issues) == 1
    assert issues[0].rule_id == "SEC002"


def test_sec003_insecure_script():
    rule = Sec003InsecureScriptExecution()
    df = DockerfileParser.parse("FROM alpine\nRUN curl -sSL https://example.com/install.sh | bash")
    issues = rule.check(df)
    assert len(issues) == 1
    assert issues[0].rule_id == "SEC003"


def test_sec004_hardcoded_secret():
    rule = Sec004HardcodedSecret()
    df = DockerfileParser.parse("FROM alpine\nENV AWS_SECRET_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE")
    issues = rule.check(df)
    assert len(issues) == 1
    assert issues[0].rule_id == "SEC004"


def test_opt001_unpinned_image_tag():
    rule = Opt001UnpinnedImageTag()
    df_latest = DockerfileParser.parse("FROM python:latest")
    assert len(rule.check(df_latest)) == 1

    df_notag = DockerfileParser.parse("FROM python")
    assert len(rule.check(df_notag)) == 1

    df_pinned = DockerfileParser.parse("FROM python:3.11-slim")
    assert len(rule.check(df_pinned)) == 0


def test_opt002_suboptimal_cache_order():
    rule = Opt002SuboptimalCacheOrder()
    bad_df = DockerfileParser.parse("""
    FROM node:20-alpine
    WORKDIR /app
    COPY . .
    RUN npm install
    """)
    assert len(rule.check(bad_df)) == 1

    good_df = DockerfileParser.parse("""
    FROM node:20-alpine
    WORKDIR /app
    COPY package*.json ./
    RUN npm ci
    COPY . .
    """)
    assert len(rule.check(good_df)) == 0


def test_opt003_uncleaned_apt():
    rule = Opt003UncleanedAptCache()
    bad_df = DockerfileParser.parse("FROM ubuntu:22.04\nRUN apt-get update && apt-get install -y curl")
    assert len(rule.check(bad_df)) == 1

    good_df = DockerfileParser.parse(
        "FROM ubuntu:22.04\nRUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*"
    )
    assert len(rule.check(good_df)) == 0


def test_opt004_pip_no_cache_dir():
    rule = Opt004PipNoCacheDir()
    bad = DockerfileParser.parse("FROM python:3.11\nRUN pip install flask")
    assert len(rule.check(bad)) == 1

    good = DockerfileParser.parse("FROM python:3.11\nRUN pip install --no-cache-dir flask")
    assert len(rule.check(good)) == 0


def test_opt005_use_copy_instead_of_add():
    rule = Opt005UseCopyInsteadOfAdd()
    bad = DockerfileParser.parse("FROM alpine\nADD config.json /etc/config.json")
    assert len(rule.check(bad)) == 1

    good = DockerfileParser.parse("FROM alpine\nCOPY config.json /etc/config.json")
    assert len(rule.check(good)) == 0

    tar_good = DockerfileParser.parse("FROM alpine\nADD archive.tar.gz /opt/")
    assert len(rule.check(tar_good)) == 0


def test_rel001_shell_form_exec():
    rule = Rel001ShellFormExec()
    bad = DockerfileParser.parse("FROM alpine\nCMD python app.py")
    assert len(rule.check(bad)) == 1

    good = DockerfileParser.parse("FROM alpine\nCMD [\"python\", \"app.py\"]")
    assert len(rule.check(good)) == 0


def test_rel002_multiple_cmd():
    rule = Rel002MultipleCmd()
    bad = DockerfileParser.parse("""
    FROM alpine
    CMD ["echo", "1"]
    CMD ["echo", "2"]
    """)
    assert len(rule.check(bad)) == 1


def test_rel003_missing_healthcheck():
    rule = Rel003MissingHealthcheck()
    bad = DockerfileParser.parse("FROM alpine\nEXPOSE 8080\nCMD ['app']")
    assert len(rule.check(bad)) == 1

    good = DockerfileParser.parse("FROM alpine\nEXPOSE 8080\nHEALTHCHECK CMD true\nCMD ['app']")
    assert len(rule.check(good)) == 0
