"""Security, optimization, and reliability rules for Dockerfiles."""

from dataclasses import dataclass
from enum import Enum
import re
from typing import List, Optional

from dockerfile_guard.parser import Dockerfile, Instruction


class Severity(str, Enum):
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"

    @property
    def penalty(self) -> int:
        penalties = {
            Severity.INFO: 2,
            Severity.WARNING: 8,
            Severity.ERROR: 20,
        }
        return penalties[self]


@dataclass
class Issue:
    rule_id: str
    severity: Severity
    title: str
    message: str
    line: int
    end_line: int
    suggestion: str
    code_snippet: str = ""

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity.value,
            "title": self.title,
            "message": self.message,
            "line": self.line,
            "end_line": self.end_line,
            "suggestion": self.suggestion,
            "code_snippet": self.code_snippet,
        }


class Rule:
    rule_id: str = ""
    title: str = ""
    description: str = ""
    severity: Severity = Severity.WARNING

    def check(self, dockerfile: Dockerfile) -> List[Issue]:
        raise NotImplementedError


class Sec001MissingUser(Rule):
    """Checks if final stage runs as root (no USER directive)."""

    rule_id = "SEC001"
    title = "Missing Non-Root USER Instruction"
    description = "Running containers as root poses security risks if container isolation is compromised."
    severity = Severity.WARNING

    def check(self, dockerfile: Dockerfile) -> List[Issue]:
        if not dockerfile.stages:
            return []
        final_stage = dockerfile.stages[-1]
        has_user = any(inst.name == "USER" for inst in final_stage.instructions)
        if not has_user and final_stage.instructions:
            first_inst = final_stage.instructions[0]
            return [
                Issue(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    title=self.title,
                    message="Final stage does not declare a non-root USER directive.",
                    line=first_inst.start_line,
                    end_line=first_inst.end_line,
                    suggestion="Add 'USER nonroot' or create a dedicated application user.",
                    code_snippet=first_inst.raw,
                )
            ]
        return []


class Sec002SudoUsage(Rule):
    """Detects sudo commands inside RUN instructions."""

    rule_id = "SEC002"
    title = "Sudo Usage in RUN Command"
    description = "Sudo should not be used in Docker build steps; build runs as root by default."
    severity = Severity.ERROR

    REGEX = re.compile(r"\bsudo\b", re.IGNORECASE)

    def check(self, dockerfile: Dockerfile) -> List[Issue]:
        issues = []
        for inst in dockerfile.instructions:
            if inst.name == "RUN" and self.REGEX.search(inst.arguments):
                issues.append(
                    Issue(
                        rule_id=self.rule_id,
                        severity=self.severity,
                        title=self.title,
                        message="Avoid using 'sudo' inside RUN instructions.",
                        line=inst.start_line,
                        end_line=inst.end_line,
                        suggestion="Remove 'sudo' from RUN commands or configure appropriate permissions directly.",
                        code_snippet=inst.raw,
                    )
                )
        return issues


class Sec003InsecureScriptExecution(Rule):
    """Detects curl or wget piped directly to bash or sh."""

    rule_id = "SEC003"
    title = "Insecure Remote Script Piping"
    description = "Piping remote scripts directly to shell (curl | sh) can execute malicious or compromised code."
    severity = Severity.ERROR

    REGEX = re.compile(
        r"(?:curl[^\n|]+|wget[^\n|]+)\|\s*(?:ba)?sh\b", re.IGNORECASE
    )

    def check(self, dockerfile: Dockerfile) -> List[Issue]:
        issues = []
        for inst in dockerfile.instructions:
            if inst.name == "RUN" and self.REGEX.search(inst.arguments):
                issues.append(
                    Issue(
                        rule_id=self.rule_id,
                        severity=self.severity,
                        title=self.title,
                        message="Insecure piping of untrusted web content to shell detected.",
                        line=inst.start_line,
                        end_line=inst.end_line,
                        suggestion="Download script to a temporary file and verify its hash/checksum before execution.",
                        code_snippet=inst.raw,
                    )
                )
        return issues


class Sec004HardcodedSecret(Rule):
    """Detects potential credentials, tokens, or private keys in ENV / ARG instructions."""

    rule_id = "SEC004"
    title = "Hardcoded Secret in Build Instruction"
    description = "Secrets baked into ENV or ARG instructions persist in container image metadata."
    severity = Severity.ERROR

    PATTERN = re.compile(
        r"(?:api[_-]?key|secret|password|passwd|token|private[_-]?key|access[_-]?key|auth[_-]?token)"
        r"[a-zA-Z0-9_]*"
        r"(?:\s*=\s*|\s+)['\"]?[a-zA-Z0-9_\-\.\/+=]{6,}['\"]?",
        re.IGNORECASE,
    )

    def check(self, dockerfile: Dockerfile) -> List[Issue]:
        issues = []
        for inst in dockerfile.instructions:
            if inst.name in ("ENV", "ARG"):
                match = self.PATTERN.search(inst.arguments)
                if match:
                    issues.append(
                        Issue(
                            rule_id=self.rule_id,
                            severity=self.severity,
                            title=self.title,
                            message=f"Possible secret or credential hardcoded in {inst.name} instruction.",
                            line=inst.start_line,
                            end_line=inst.end_line,
                            suggestion="Pass sensitive credentials at runtime via environment variables or Docker secrets (--secret).",
                            code_snippet=inst.raw,
                        )
                    )
        return issues


class Opt001UnpinnedImageTag(Rule):
    """Detects base images using :latest or missing explicit version tags."""

    rule_id = "OPT001"
    title = "Unpinned Base Image Tag"
    description = "Using ':latest' or no tag leads to non-reproducible builds and sudden breakage."
    severity = Severity.WARNING

    def check(self, dockerfile: Dockerfile) -> List[Issue]:
        issues = []
        for stage in dockerfile.stages:
            if stage.base_image and stage.base_image != "scratch":
                if not stage.base_tag or stage.base_tag.lower() == "latest":
                    from_inst = stage.instructions[0] if stage.instructions else None
                    if from_inst:
                        issues.append(
                            Issue(
                                rule_id=self.rule_id,
                                severity=self.severity,
                                title=self.title,
                                message=f"Base image '{stage.base_image}' uses missing or ':latest' tag.",
                                line=from_inst.start_line,
                                end_line=from_inst.end_line,
                                suggestion="Pin to an exact semantic version or digest (e.g. 'python:3.11-slim' or 'node:20.11-alpine').",
                                code_snippet=from_inst.raw,
                            )
                        )
        return issues


class Opt002SuboptimalCacheOrder(Rule):
    """Detects 'COPY . .' executed before dependency installation commands."""

    rule_id = "OPT002"
    title = "Suboptimal Layer Caching Order"
    description = "Copying the entire source before installing dependencies busts the build cache on every code change."
    severity = Severity.WARNING

    DEP_INSTALL_REGEX = re.compile(
        r"\b(?:npm\s+(?:ci|install)|yarn\s+install|pip\s+install|cargo\s+build|go\s+mod\s+download)\b",
        re.IGNORECASE,
    )
    BROAD_COPY_REGEX = re.compile(r"^COPY\s+(?:\.\s+\.|\.\s+\/|\.\s+[a-zA-Z0-9_\-\/\.]+)\s*$", re.IGNORECASE)

    def check(self, dockerfile: Dockerfile) -> List[Issue]:
        issues = []
        for stage in dockerfile.stages:
            broad_copy_inst: Optional[Instruction] = None
            for inst in stage.instructions:
                if inst.name == "COPY":
                    clean = re.sub(r"--[a-z0-9_\-]+=[^\s]+\s+", "", inst.raw).strip()
                    if self.BROAD_COPY_REGEX.match(clean) and not broad_copy_inst:
                        broad_copy_inst = inst
                elif inst.name == "RUN" and broad_copy_inst:
                    if self.DEP_INSTALL_REGEX.search(inst.arguments):
                        issues.append(
                            Issue(
                                rule_id=self.rule_id,
                                severity=self.severity,
                                title=self.title,
                                message=f"Dependency installation occurs after broad 'COPY' on line {broad_copy_inst.start_line}.",
                                line=broad_copy_inst.start_line,
                                end_line=broad_copy_inst.end_line,
                                suggestion="Copy package manifests (package.json, requirements.txt, Cargo.toml) first, install dependencies, then copy remaining source.",
                                code_snippet=broad_copy_inst.raw,
                            )
                        )
                        break
        return issues


class Opt003UncleanedAptCache(Rule):
    """Detects apt-get install without cleaning lists cache or missing -y flag."""

    rule_id = "OPT003"
    title = "Uncleaned APT Package Cache"
    description = "Failing to clean /var/lib/apt/lists/ bloats docker image layers."
    severity = Severity.WARNING

    def check(self, dockerfile: Dockerfile) -> List[Issue]:
        issues = []
        for inst in dockerfile.instructions:
            if inst.name == "RUN" and "apt-get install" in inst.arguments:
                if "rm -rf /var/lib/apt/lists" not in inst.arguments:
                    issues.append(
                        Issue(
                            rule_id=self.rule_id,
                            severity=self.severity,
                            title=self.title,
                            message="apt-get install without removing /var/lib/apt/lists/* in the same RUN layer.",
                            line=inst.start_line,
                            end_line=inst.end_line,
                            suggestion="Append '&& rm -rf /var/lib/apt/lists/*' and use '--no-install-recommends' flag.",
                            code_snippet=inst.raw,
                        )
                    )
        return issues


class Opt004PipNoCacheDir(Rule):
    """Detects pip install without --no-cache-dir."""

    rule_id = "OPT004"
    title = "Pip Cache Not Disabled"
    description = "pip caches wheels and tarballs by default, needlessly increasing image size."
    severity = Severity.INFO

    def check(self, dockerfile: Dockerfile) -> List[Issue]:
        issues = []
        for inst in dockerfile.instructions:
            if inst.name == "RUN" and re.search(r"\bpip\s+install\b", inst.arguments):
                if "--no-cache-dir" not in inst.arguments:
                    issues.append(
                        Issue(
                            rule_id=self.rule_id,
                            severity=self.severity,
                            title=self.title,
                            message="pip install without '--no-cache-dir' increases image size.",
                            line=inst.start_line,
                            end_line=inst.end_line,
                            suggestion="Add '--no-cache-dir' to pip install command.",
                            code_snippet=inst.raw,
                        )
                    )
        return issues


class Opt005UseCopyInsteadOfAdd(Rule):
    """Detects ADD when COPY should be used for simple file copying."""

    rule_id = "OPT005"
    title = "Use COPY Instead of ADD"
    description = "COPY is more transparent and predictable than ADD unless auto-extracting archives."
    severity = Severity.INFO

    def check(self, dockerfile: Dockerfile) -> List[Issue]:
        issues = []
        for inst in dockerfile.instructions:
            if inst.name == "ADD":
                args = inst.arguments.lower()
                is_url = "http://" in args or "https://" in args
                is_tar = any(ext in args for ext in (".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tar.xz"))
                if not is_url and not is_tar:
                    issues.append(
                        Issue(
                            rule_id=self.rule_id,
                            severity=self.severity,
                            title=self.title,
                            message="ADD instruction used for local file without archive extraction.",
                            line=inst.start_line,
                            end_line=inst.end_line,
                            suggestion="Replace 'ADD' with 'COPY'.",
                            code_snippet=inst.raw,
                        )
                    )
        return issues


class Rel001ShellFormExec(Rule):
    """Detects CMD or ENTRYPOINT in shell form instead of JSON exec array form."""

    rule_id = "REL001"
    title = "Shell Form in CMD or ENTRYPOINT"
    description = "Shell form runs through /bin/sh -c and fails to receive Unix process signals (SIGTERM/SIGINT)."
    severity = Severity.WARNING

    def check(self, dockerfile: Dockerfile) -> List[Issue]:
        issues = []
        for inst in dockerfile.instructions:
            if inst.name in ("CMD", "ENTRYPOINT"):
                arg = inst.arguments.strip()
                if not (arg.startswith("[") and arg.endswith("]")):
                    issues.append(
                        Issue(
                            rule_id=self.rule_id,
                            severity=self.severity,
                            title=self.title,
                            message=f"{inst.name} is using shell form instead of JSON exec array.",
                            line=inst.start_line,
                            end_line=inst.end_line,
                            suggestion=f"Convert to JSON array format: {inst.name} [\"binary\", \"arg1\", \"arg2\"]",
                            code_snippet=inst.raw,
                        )
                    )
        return issues


class Rel002MultipleCmd(Rule):
    """Detects multiple CMD or ENTRYPOINT instructions in the same build stage."""

    rule_id = "REL002"
    title = "Duplicate CMD or ENTRYPOINT Instructions"
    description = "Only the last CMD or ENTRYPOINT takes effect in Docker; earlier ones are overridden."
    severity = Severity.WARNING

    def check(self, dockerfile: Dockerfile) -> List[Issue]:
        issues = []
        for stage in dockerfile.stages:
            cmds = [inst for inst in stage.instructions if inst.name == "CMD"]
            if len(cmds) > 1:
                for duplicate in cmds[:-1]:
                    issues.append(
                        Issue(
                            rule_id=self.rule_id,
                            severity=self.severity,
                            title=self.title,
                            message="Multiple CMD instructions detected in the same stage. Only the last will execute.",
                            line=duplicate.start_line,
                            end_line=duplicate.end_line,
                            suggestion="Remove redundant CMD instruction.",
                            code_snippet=duplicate.raw,
                        )
                    )
        return issues


class Rel003MissingHealthcheck(Rule):
    """Detects exposed service without HEALTHCHECK instruction."""

    rule_id = "REL003"
    title = "Missing HEALTHCHECK Directive"
    description = "Containers exposing ports should define HEALTHCHECK to allow orchestrators to monitor health."
    severity = Severity.INFO

    def check(self, dockerfile: Dockerfile) -> List[Issue]:
        if not dockerfile.stages:
            return []
        final_stage = dockerfile.stages[-1]
        has_expose = any(inst.name == "EXPOSE" for inst in final_stage.instructions)
        has_healthcheck = any(inst.name == "HEALTHCHECK" for inst in dockerfile.instructions)
        if has_expose and not has_healthcheck:
            first_inst = final_stage.instructions[0] if final_stage.instructions else None
            line = first_inst.start_line if first_inst else 1
            return [
                Issue(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    title=self.title,
                    message="Container exposes network ports but defines no HEALTHCHECK instruction.",
                    line=line,
                    end_line=line,
                    suggestion="Add 'HEALTHCHECK --interval=30s --timeout=3s CMD curl -f http://localhost:8080/health || exit 1'",
                    code_snippet=first_inst.raw if first_inst else "",
                )
            ]
        return []


ALL_RULES: List[Rule] = [
    Sec001MissingUser(),
    Sec002SudoUsage(),
    Sec003InsecureScriptExecution(),
    Sec004HardcodedSecret(),
    Opt001UnpinnedImageTag(),
    Opt002SuboptimalCacheOrder(),
    Opt003UncleanedAptCache(),
    Opt004PipNoCacheDir(),
    Opt005UseCopyInsteadOfAdd(),
    Rel001ShellFormExec(),
    Rel002MultipleCmd(),
    Rel003MissingHealthcheck(),
]
