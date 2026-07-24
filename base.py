"""
Core data structures shared by every audit check module.

Every check module implements a function `run() -> CheckResult` (or, for
categories with multiple sub-checks, `run() -> List[CheckResult]`).
Keeping this contract simple makes it trivial to plug new checks into
the orchestrator in main.py without touching the report generator.
"""

from __future__ import annotations

import subprocess
import shutil
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional


class Severity(str, Enum):
    """Ordered severity levels, low -> high, used both for display and scoring."""
    INFO = "INFO"
    PASS = "PASS"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def weight(self) -> int:
        """Points deducted from the category's score for one finding at this level."""
        return {
            Severity.INFO: 0,
            Severity.PASS: 0,
            Severity.LOW: 2,
            Severity.MEDIUM: 5,
            Severity.HIGH: 10,
            Severity.CRITICAL: 20,
        }[self]

    @property
    def rank(self) -> int:
        order = [Severity.PASS, Severity.INFO, Severity.LOW,
                  Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        return order.index(self)


@dataclass
class Finding:
    """A single, atomic observation produced by a check (e.g. one bad file)."""
    title: str
    severity: Severity
    detail: str = ""
    remediation: str = ""


@dataclass
class CheckResult:
    """The full output of one check function: a group of related findings."""
    check_id: str
    name: str
    category: str
    findings: List[Finding] = field(default_factory=list)
    error: Optional[str] = None  # populated if the check could not run at all

    @property
    def worst_severity(self) -> Severity:
        if self.error:
            return Severity.MEDIUM
        if not self.findings:
            return Severity.PASS
        return max((f.severity for f in self.findings), key=lambda s: s.rank)


def run_cmd(cmd: List[str], timeout: int = 10) -> Optional[str]:
    """
    Run a shell command safely and return stdout, or None if the binary is
    missing, the command fails, or it times out. Centralizing this means
    every check module fails soft instead of crashing the whole audit.
    """
    if shutil.which(cmd[0]) is None:
        return None
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, check=False
        )
        return proc.stdout
    except (subprocess.TimeoutExpired, OSError):
        return None


def command_exists(name: str) -> bool:
    return shutil.which(name) is not None
