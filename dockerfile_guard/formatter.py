"""Formatters for terminal output, Markdown, and JSON."""

import json
from typing import Dict, Any
from dockerfile_guard.linter import LintResult
from dockerfile_guard.rules import Severity


class Formatter:
    """Renders LintResult into text, JSON, or Markdown formats."""

    @staticmethod
    def format_terminal(result: LintResult, show_snippets: bool = True) -> str:
        lines = []
        lines.append(f"\nScanning: {result.target_path}")
        lines.append("=" * 60)

        if not result.issues:
            lines.append("  [OK] No issues found! Dockerfile adheres to best practices.")
        else:
            for issue in result.issues:
                prefix = f"[{issue.severity.value}]"
                lines.append(f"{prefix} Line {issue.line}: {issue.rule_id} - {issue.title}")
                lines.append(f"  -> {issue.message}")
                if issue.suggestion:
                    lines.append(f"  -> Suggestion: {issue.suggestion}")
                if show_snippets and issue.code_snippet:
                    lines.append(f"     | {issue.code_snippet}")
                lines.append("")

        lines.append("-" * 60)
        lines.append(
            f"Summary: {result.error_count} Error(s), {result.warning_count} Warning(s), {result.info_count} Info(s)"
        )
        lines.append(f"Health Score: {result.score}/100 (Grade: {result.grade})")
        lines.append("=" * 60 + "\n")
        return "\n".join(lines)

    @staticmethod
    def format_json(result: LintResult) -> str:
        data: Dict[str, Any] = {
            "target_path": result.target_path,
            "score": result.score,
            "grade": result.grade,
            "summary": {
                "errors": result.error_count,
                "warnings": result.warning_count,
                "info": result.info_count,
                "total_issues": len(result.issues),
            },
            "issues": [i.to_dict() for i in result.issues],
        }
        return json.dumps(data, indent=2)

    @staticmethod
    def format_markdown(result: LintResult) -> str:
        lines = [
            f"# Dockerfile Guard Report for `{result.target_path}`",
            "",
            f"**Overall Health Grade:** `{result.grade}` (Score: {result.score}/100)",
            "",
            f"- **Errors:** {result.error_count}",
            f"- **Warnings:** {result.warning_count}",
            f"- **Info:** {result.info_count}",
            "",
        ]

        if not result.issues:
            lines.append("No security or optimization issues detected.")
            return "\n".join(lines)

        lines.append("| Severity | Rule | Line | Title | Recommendation |")
        lines.append("|:---:|:---:|:---:|:---|:---|")
        for i in result.issues:
            lines.append(
                f"| `{i.severity.value}` | `{i.rule_id}` | {i.line} | {i.title} | {i.suggestion} |"
            )

        return "\n".join(lines)
