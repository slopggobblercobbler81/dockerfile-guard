"""Linter runner and health score grading."""

from dataclasses import dataclass, field
import os
from pathlib import Path
from typing import List, Optional

from dockerfile_guard.parser import Dockerfile, DockerfileParser
from dockerfile_guard.rules import ALL_RULES, Issue, Rule, Severity


@dataclass
class LintResult:
    target_path: str
    dockerfile: Dockerfile
    issues: List[Issue] = field(default_factory=list)
    score: int = 100
    grade: str = "A+"

    @property
    def error_count(self) -> int:
        return sum(1 for i in self.issues if i.severity == Severity.ERROR)

    @property
    def warning_count(self) -> int:
        return sum(1 for i in self.issues if i.severity == Severity.WARNING)

    @property
    def info_count(self) -> int:
        return sum(1 for i in self.issues if i.severity == Severity.INFO)


class Linter:
    """Runs rules on Dockerfiles and computes grade scores."""

    def __init__(self, rules: Optional[List[Rule]] = None, ignored_rules: Optional[List[str]] = None):
        self.rules = rules or list(ALL_RULES)
        self.ignored_rules = set(r.upper() for r in (ignored_rules or []))

    def lint_text(self, content: str, target_path: str = "Dockerfile", context_dir: Optional[str] = None) -> LintResult:
        dockerfile = DockerfileParser.parse(content)
        issues: List[Issue] = []

        for rule in self.rules:
            if rule.rule_id.upper() in self.ignored_rules:
                continue
            rule_issues = rule.check(dockerfile)
            issues.extend(rule_issues)

        # Context check: .dockerignore
        if context_dir:
            ctx_path = Path(context_dir)
            if ctx_path.is_dir():
                dockerignore_file = ctx_path / ".dockerignore"
                if not dockerignore_file.exists():
                    issues.append(
                        Issue(
                            rule_id="OPT006",
                            severity=Severity.INFO,
                            title="Missing .dockerignore File",
                            message="No .dockerignore found in build context directory.",
                            line=1,
                            end_line=1,
                            suggestion="Create a .dockerignore file to exclude unnecessary files from build context.",
                            code_snippet="",
                        )
                    )

        # Sort issues by line number then severity
        severity_order = {Severity.ERROR: 0, Severity.WARNING: 1, Severity.INFO: 2}
        issues.sort(key=lambda x: (x.line, severity_order.get(x.severity, 9)))

        # Score calculation
        score = 100
        for issue in issues:
            score -= issue.severity.penalty
        score = max(0, min(100, score))

        # Grade calculation
        if score >= 95:
            grade = "A+"
        elif score >= 90:
            grade = "A"
        elif score >= 80:
            grade = "B"
        elif score >= 70:
            grade = "C"
        elif score >= 60:
            grade = "D"
        else:
            grade = "F"

        return LintResult(
            target_path=target_path,
            dockerfile=dockerfile,
            issues=issues,
            score=score,
            grade=grade,
        )

    def lint_file(self, filepath: str) -> LintResult:
        p = Path(filepath)
        if not p.is_file():
            raise FileNotFoundError(f"Dockerfile not found: '{filepath}'")
        content = p.read_text(encoding="utf-8", errors="replace")
        context_dir = str(p.parent)
        return self.lint_text(content, target_path=filepath, context_dir=context_dir)
