# dockerfile-guard 🛡️🐳

[![CI](https://github.com/slopggobblercobbler81/dockerfile-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/slopggobblercobbler81/dockerfile-guard/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://python.org)

**dockerfile-guard** is a fast, lightweight static analyzer and optimization advisor for Dockerfiles. It detects security vulnerabilities, build cache invalidation bugs, image bloat, and container reliability pitfalls before they reach production.

---

## 🚀 Features

- **Security Auditing**:
  - `SEC001`: Detects missing non-root `USER` instructions.
  - `SEC002`: Flags dangerous `sudo` commands in `RUN`.
  - `SEC003`: Identifies unsafe remote script piping (`curl ... | sh` or `wget ... | bash`).
  - `SEC004`: Prevents baked-in API keys, secrets, or tokens in `ENV` and `ARG`.
- **Build Cache & Size Optimization**:
  - `OPT001`: Flags unpinned base image tags (`FROM ubuntu:latest`).
  - `OPT002`: Detects premature `COPY . .` commands that invalidate package manager layer caches.
  - `OPT003`: Catches uncleaned package caches (`apt-get install` without removing `/var/lib/apt/lists/*`).
  - `OPT004`: Warns on `pip install` without `--no-cache-dir`.
  - `OPT005`: Recommends `COPY` over `ADD` for standard files.
  - `OPT006`: Verifies the presence of `.dockerignore`.
- **Reliability & Orchestration**:
  - `REL001`: Warns about shell form in `CMD` / `ENTRYPOINT` preventing proper signal propagation (`SIGTERM`).
  - `REL002`: Flags duplicate `CMD` or `ENTRYPOINT` definitions.
  - `REL003`: Recommends `HEALTHCHECK` for exposed services.
- **Grading Engine**: Computes health scores (`0-100`) and letter grades (`A+` to `F`).
- **Flexible Output Formats**: Text table, JSON, and Markdown.
- **CI/CD Friendly**: Enforce thresholds using `--fail-on` or `--min-score`.

---

## 📦 Installation

```bash
pip install dockerfile-guard
```

Or install locally in editable mode:

```bash
git clone https://github.com/slopggobblercobbler81/dockerfile-guard.git
cd dockerfile-guard
pip install -e .
```

---

## ⚡ Quick Start

### 1. Scan a Dockerfile

```bash
dockerfile-guard scan Dockerfile
```

Example Output:
```
Scanning: Dockerfile
============================================================
[ERROR] Line 4: SEC003 - Insecure Remote Script Piping
  -> Insecure piping of untrusted web content to shell detected.
  -> Suggestion: Download script to a temporary file and verify its hash/checksum before execution.
     | RUN curl -fsSL https://get.docker.com | sh

[WARNING] Line 1: OPT001 - Unpinned Base Image Tag
  -> Base image 'python' uses missing or ':latest' tag.
  -> Suggestion: Pin to an exact semantic version or digest (e.g. 'python:3.11-slim' or 'node:20.11-alpine').
     | FROM python:latest

------------------------------------------------------------
Summary: 1 Error(s), 1 Warning(s), 0 Info(s)
Health Score: 72/100 (Grade: C)
============================================================
```

### 2. CI/CD Gate Enforcement

Fail the build if any errors or warnings exist, or if the score drops below 85:

```bash
dockerfile-guard scan Dockerfile --fail-on warning --min-score 85
```

### 3. Generate JSON or Markdown Reports

```bash
# JSON report for CI pipelines
dockerfile-guard scan Dockerfile --format json -o report.json

# Markdown report for pull request comments
dockerfile-guard scan Dockerfile --format markdown -o report.md
```

### 4. List All Rules

```bash
dockerfile-guard rules
```

### 5. Initialize Configuration File

```bash
dockerfile-guard init
```

Generates `.dockerfile-guard.json`:

```json
{
  "ignored_rules": [],
  "min_score": 80,
  "fail_on": "warning"
}
```

---

## 🤖 GitHub Actions CI Workflow

Add automated Dockerfile checks to your GitHub Actions:

```yaml
name: Dockerfile Lint

on: [push, pull_request]

jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - name: Install dockerfile-guard
        run: pip install dockerfile-guard
      - name: Run Guard Scan
        run: dockerfile-guard scan Dockerfile --fail-on error --min-score 80
```

---

## 🧪 Testing

Run tests with `pytest`:

```bash
python -m pytest -v
```

---

## 📄 License

MIT License. See [LICENSE](LICENSE) for details.
