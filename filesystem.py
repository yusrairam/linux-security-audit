"""
Filesystem permission checks: SUID/SGID binaries, world-writable files,
world-writable directories missing the sticky bit, and unowned files.

Uses `find` for speed and to respect the running user's read permissions;
scans are scoped to reduce false positives from pseudo-filesystems.
"""

from __future__ import annotations

from typing import List

from .base import CheckResult, Finding, Severity, run_cmd

CATEGORY = "Filesystem & Permissions"

# Common, expected SUID binaries shipped by most distros. Anything else
# found is flagged for review rather than treated as inherently bad.
KNOWN_SUID_ALLOWLIST = {
    "/usr/bin/sudo", "/usr/bin/su", "/usr/bin/passwd", "/usr/bin/chsh",
    "/usr/bin/chfn", "/usr/bin/gpasswd", "/usr/bin/newgrp", "/usr/bin/mount",
    "/usr/bin/umount", "/usr/bin/fusermount", "/usr/bin/fusermount3",
    "/usr/bin/pkexec", "/usr/lib/openssh/ssh-keysign", "/usr/bin/at",
    "/usr/bin/crontab", "/usr/sbin/mount.nfs", "/usr/bin/ping", "/usr/bin/ping6",
}

SEARCH_ROOTS = ["/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/local/bin", "/opt"]


def _check_suid_sgid() -> CheckResult:
    findings: List[Finding] = []
    out = run_cmd(["find", *SEARCH_ROOTS, "-xdev", "-type", "f",
                    "(", "-perm", "-4000", "-o", "-perm", "-2000", ")"])
    if out is None:
        return CheckResult("fs.suid_sgid", "SUID/SGID binaries", CATEGORY,
                            error="'find' unavailable or scan failed")
    unexpected = [p for p in out.splitlines() if p and p not in KNOWN_SUID_ALLOWLIST]
    if unexpected:
        findings.append(Finding(
            title=f"{len(unexpected)} non-standard SUID/SGID binaries found",
            severity=Severity.MEDIUM,
            detail="Files: " + ", ".join(unexpected[:15]) +
                   (" ..." if len(unexpected) > 15 else ""),
            remediation="Review each binary; remove the SUID/SGID bit "
                        "(chmod -s <path>) if it isn't required.",
        ))
    else:
        findings.append(Finding("Only expected SUID/SGID binaries present", Severity.PASS))
    return CheckResult("fs.suid_sgid", "SUID/SGID binaries", CATEGORY, findings)


def _check_world_writable_files() -> CheckResult:
    findings: List[Finding] = []
    out = run_cmd(["find", "/etc", "/usr", "/opt", "/home", "-xdev", "-type", "f",
                    "-perm", "-0002"])
    if out is None:
        return CheckResult("fs.world_writable_files", "World-writable files",
                            CATEGORY, error="'find' unavailable or scan failed")
    files = [f for f in out.splitlines() if f]
    if files:
        findings.append(Finding(
            title=f"{len(files)} world-writable file(s) found",
            severity=Severity.HIGH,
            detail="Examples: " + ", ".join(files[:15]) +
                   (" ..." if len(files) > 15 else ""),
            remediation="Remove world-write with: chmod o-w <file>",
        ))
    else:
        findings.append(Finding("No world-writable files in scanned paths", Severity.PASS))
    return CheckResult("fs.world_writable_files", "World-writable files",
                        CATEGORY, findings)


def _check_world_writable_dirs_no_sticky() -> CheckResult:
    findings: List[Finding] = []
    out = run_cmd(["find", "/", "-xdev", "-type", "d", "-perm", "-0002", "!", "-perm", "-1000"])
    if out is None:
        return CheckResult("fs.sticky_bit", "World-writable dirs without sticky bit",
                            CATEGORY, error="'find' unavailable or scan failed")
    dirs = [d for d in out.splitlines() if d and not d.startswith(("/proc", "/sys"))]
    if dirs:
        findings.append(Finding(
            title=f"{len(dirs)} world-writable directories missing the sticky bit",
            severity=Severity.MEDIUM,
            detail="Directories: " + ", ".join(dirs[:15]) +
                   (" ..." if len(dirs) > 15 else ""),
            remediation="Set the sticky bit so only owners can delete their own "
                        "files: chmod +t <dir>",
        ))
    else:
        findings.append(Finding("All world-writable directories have the sticky bit", Severity.PASS))
    return CheckResult("fs.sticky_bit", "World-writable dirs without sticky bit",
                        CATEGORY, findings)


def _check_unowned_files() -> CheckResult:
    findings: List[Finding] = []
    out = run_cmd(["find", "/home", "/etc", "/opt", "-xdev",
                    "(", "-nouser", "-o", "-nogroup", ")"])
    if out is None:
        return CheckResult("fs.unowned", "Unowned files", CATEGORY,
                            error="'find' unavailable or scan failed")
    files = [f for f in out.splitlines() if f]
    if files:
        findings.append(Finding(
            title=f"{len(files)} file(s) with no valid owning user/group",
            severity=Severity.LOW,
            detail="Examples: " + ", ".join(files[:15]) +
                   (" ..." if len(files) > 15 else ""),
            remediation="Assign a valid owner or remove: chown user:group <file>",
        ))
    else:
        findings.append(Finding("No unowned files found", Severity.PASS))
    return CheckResult("fs.unowned", "Unowned files", CATEGORY, findings)


def run() -> List[CheckResult]:
    return [
        _check_suid_sgid(),
        _check_world_writable_files(),
        _check_world_writable_dirs_no_sticky(),
        _check_unowned_files(),
    ]
