"""Dockerfile parser for instructions, stages, and arguments."""

from dataclasses import dataclass, field
import re
from typing import List, Optional


@dataclass
class Instruction:
    name: str
    arguments: str
    raw: str
    start_line: int
    end_line: int
    stage_index: int = 0
    stage_name: Optional[str] = None


@dataclass
class Stage:
    index: int
    name: Optional[str]
    base_image: str
    base_tag: Optional[str]
    instructions: List[Instruction] = field(default_factory=list)


@dataclass
class Dockerfile:
    instructions: List[Instruction] = field(default_factory=list)
    stages: List[Stage] = field(default_factory=list)
    raw_content: str = ""
    lines: List[str] = field(default_factory=list)


class DockerfileParser:
    """Parses Dockerfile text into structured Instructions and Stages."""

    INSTRUCTION_REGEX = re.compile(
        r"^\s*(?P<name>[a-zA-Z]+)(?:\s+(?P<args>[\s\S]*))?$"
    )
    STAGE_REGEX = re.compile(
        r"^(?:--platform=[^\s]+\s+)?(?P<image>[^\s:]+)(?::(?P<tag>[^\s]+))?(?:\s+[aA][sS]\s+(?P<stage>[^\s]+))?"
    )

    @classmethod
    def parse(cls, content: str) -> Dockerfile:
        lines = content.splitlines()
        instructions: List[Instruction] = []
        stages: List[Stage] = []

        current_raw_parts: List[str] = []
        start_line = 0
        current_stage_idx = -1
        current_stage_name: Optional[str] = None
        current_stage: Optional[Stage] = None

        i = 0
        while i < len(lines):
            line_num = i + 1
            raw_line = lines[i]
            stripped = raw_line.strip()

            # Ignore empty lines and comments (when not in continuation)
            if not current_raw_parts:
                if not stripped or stripped.startswith("#"):
                    i += 1
                    continue
                start_line = line_num

            # Check for line continuation '\'
            if stripped.endswith("\\"):
                # Remove trailing backslash and accumulate
                current_raw_parts.append(stripped[:-1].rstrip())
                i += 1
                continue
            else:
                current_raw_parts.append(stripped)

            # Finished accumulating complete instruction
            full_raw = " ".join(current_raw_parts).strip()
            current_raw_parts = []

            match = cls.INSTRUCTION_REGEX.match(full_raw)
            if match:
                inst_name = match.group("name").upper()
                inst_args = (match.group("args") or "").strip()

                if inst_name == "FROM":
                    current_stage_idx += 1
                    stage_match = cls.STAGE_REGEX.match(inst_args)
                    base_img = ""
                    base_tag = None
                    stage_name = None
                    if stage_match:
                        base_img = stage_match.group("image") or ""
                        base_tag = stage_match.group("tag")
                        stage_name = stage_match.group("stage")
                    current_stage_name = stage_name
                    current_stage = Stage(
                        index=current_stage_idx,
                        name=stage_name,
                        base_image=base_img,
                        base_tag=base_tag,
                    )
                    stages.append(current_stage)

                inst = Instruction(
                    name=inst_name,
                    arguments=inst_args,
                    raw=full_raw,
                    start_line=start_line,
                    end_line=line_num,
                    stage_index=max(0, current_stage_idx),
                    stage_name=current_stage_name,
                )
                instructions.append(inst)
                if current_stage:
                    current_stage.instructions.append(inst)

            i += 1

        return Dockerfile(
            instructions=instructions,
            stages=stages,
            raw_content=content,
            lines=lines,
        )
