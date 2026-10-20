"""dockerfile-guard: Fast static analyzer and optimization advisor for Dockerfiles."""

from dockerfile_guard.formatter import Formatter
from dockerfile_guard.linter import Linter, LintResult
from dockerfile_guard.parser import Dockerfile, DockerfileParser, Instruction, Stage
from dockerfile_guard.rules import ALL_RULES, Issue, Rule, Severity

__version__ = "0.1.0"

__all__ = [
    "__version__",
    "ALL_RULES",
    "Dockerfile",
    "DockerfileParser",
    "Formatter",
    "Instruction",
    "Issue",
    "Linter",
    "LintResult",
    "Rule",
    "Severity",
    "Stage",
]
