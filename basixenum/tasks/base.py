from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class TaskResult:
    name: str
    command: List[str]
    returncode: int
    stdout: str
    stderr: str
    findings: List[str] = field(default_factory=list)
    artifacts: List[str] = field(default_factory=list)


@dataclass
class ReconTask:
    name: str
    category: str
    command: List[str]
    enabled: bool = True
    timeout: int = 300
    description: str = ""

    def parse_output(self, stdout: str, stderr: str) -> List[str]:
        return []
