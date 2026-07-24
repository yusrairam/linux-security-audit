"""
System-level checks: pending updates, mandatory access control (SELinux /
AppArmor), unnecessary running services, and scheduled task exposure.
"""

from __future__ import annotations

import os
from typing import List

from .base import CheckResult, Finding, Severity, run_cmd, command_exists

CATEGORY = "System Hardening"

# Services that are commonly enabled by default but rarely needed, and
# increase attack surface when running unused.
QUESTIONABLE_SERVICES = [
    "telnet.socket", "rsh.socket", "rlogin.socket", "tftp.socket",
    "avahi-daemon.service", "cups.service",
]


def _check_pending_updates() -> CheckResult:
    findings: List[Finding] = []
    if command_exists("apt"):
        out = run_cmd(["apt", "list", "--upgradable"], timeout=20)
        if out is not None:
            lines = [l for l in out.splitlines() if "/" in l and "Listing..." not in l]
            security = [l for l in lines if "-security" in l]
            if security:
                findings.append(Finding(
                    f"{len(security)} security update(s) pending", Severity.HIGH,
                    detail="Run 'apt list --upgradable' to see them.",
                    remediation="sudo apt update && sudo apt upgrade",
                ))
            elif lines:
                findings.append(Finding(
                    f"{len(lines)} non-security update(s) pending", Severity.LOW,
                    remediation="sudo apt update && sudo apt upgrade",
                ))
            else:
                findings.append(Finding("System packages are up to date", Severity.PASS))
            return CheckResult("sys.updates", "Pending package updates", CATEGORY, findings)

    if command_exists("dnf") or command_exists("yum"):
        pm = "dnf" if command_exists("dnf") else "yum"
        out = run_cmd([pm, "check-update"], timeout=30)
        # check-update exits 100 when updates are available; our run_cmd
        # doesn't raise on nonzero exit, so we inspect stdout instead.
        if out:
            pkg_lines = [l for l in out.splitlines() if l and not l.startswith(("Last", "Loaded"))]
            if pkg_lines:
                findings.append(Finding(
                    f"~{len(pkg_lines)} package update(s) may be pending", Severity.MEDIUM,
                    remediation=f"sudo {pm} update",
                ))
            else:
                findings.append(Finding("System packages appear up to date", Severity.PASS))
        else:
            findings.append(Finding("System packages appear up to date", Severity.PASS))
        return CheckResult("sys.updates", "Pending package updates", CATEGORY, findings)

    return CheckResult("sys.updates", "Pending package updates", CATEGORY,
                        error="No supported package manager found (apt/dnf/yum)")


def _check_mac() -> CheckResult:
    findings: List[Finding] = []
    if command_exists("getenforce"):
        out = (run_cmd(["getenforce"]) or "").strip()
        if out == "Enforcing":
            findings.append(Finding("SELinux is Enforcing", Severity.PASS))
        elif out == "Permissive":
            findings.append(Finding(
                "SELinux is Permissive (logging only, not blocking)", Severity.MEDIUM,
                remediation="Set to Enforcing in /etc/selinux/config once policy is validated.",
            ))
        else:
            findings.append(Finding(
                "SELinux is Disabled", Severity.MEDIUM,
                remediation="Consider enabling SELinux or an equivalent MAC system.",
            ))
        return CheckResult("sys.mac", "Mandatory Access Control", CATEGORY, findings)

    if command_exists("aa-status"):
        out = run_cmd(["aa-status", "--enabled"])
        enabled = out is not None  # aa-status --enabled exits 0 if enabled
        if enabled:
            findings.append(Finding("AppArmor is enabled", Severity.PASS))
        else:
            findings.append(Finding(
                "AppArmor is installed but not enabled", Severity.MEDIUM,
                remediation="sudo systemctl enable --now apparmor",
            ))
        return CheckResult("sys.mac", "Mandatory Access Control", CATEGORY, findings)

    findings.append(Finding(
        "No MAC system detected (SELinux/AppArmor)", Severity.LOW,
        detail="Not all distros ship one by default; consider adding one for defense in depth.",
    ))
    return CheckResult("sys.mac", "Mandatory Access Control", CATEGORY, findings)


def _check_questionable_services() -> CheckResult:
    findings: List[Finding] = []
    if not command_exists("systemctl"):
        return CheckResult("sys.services", "Unnecessary services", CATEGORY,
                            error="systemctl not available (non-systemd system?)")
    out = run_cmd(["systemctl", "list-units", "--type=service,socket",
                    "--state=running,listening", "--no-legend", "--no-pager"])
    if out is None:
        return CheckResult("sys.services", "Unnecessary services", CATEGORY,
                            error="Could not query systemctl")
    running = [line.split()[0] for line in out.splitlines() if line.strip()]
    flagged = [s for s in QUESTIONABLE_SERVICES if s in running]
    if flagged:
        findings.append(Finding(
            title=f"{len(flagged)} legacy/high-risk service(s) active",
            severity=Severity.MEDIUM,
            detail=", ".join(flagged),
            remediation="Disable if unused: sudo systemctl disable --now <service>",
        ))
    else:
        findings.append(Finding("No commonly-flagged legacy services detected", Severity.PASS))
    findings.append(Finding(
        title=f"{len(running)} service/socket unit(s) currently active",
        severity=Severity.INFO,
    ))
    return CheckResult("sys.services", "Unnecessary services", CATEGORY, findings)


def _check_cron_permissions() -> CheckResult:
    findings: List[Finding] = []
    paths_to_check = ["/etc/crontab", "/etc/cron.d", "/etc/cron.daily",
                       "/etc/cron.hourly", "/etc/cron.weekly", "/etc/cron.monthly"]
    writable_by_others = []
    for p in paths_to_check:
        if not os.path.exists(p):
            continue
        try:
            mode = os.stat(p).st_mode
            if mode & 0o022:  # group or other write bit
                writable_by_others.append(p)
        except OSError:
            continue
    if writable_by_others:
        findings.append(Finding(
            title=f"{len(writable_by_others)} cron path(s) writable by group/other",
            severity=Severity.HIGH,
            detail=", ".join(writable_by_others),
            remediation="chmod go-w on each path; cron jobs run as root and must not "
                        "be tamperable by unprivileged users.",
        ))
    else:
        findings.append(Finding("Cron directories have safe permissions", Severity.PASS))
    return CheckResult("sys.cron_perms", "Cron path permissions", CATEGORY, findings)


def run() -> List[CheckResult]:
    return [
        _check_pending_updates(),
        _check_mac(),
        _check_questionable_services(),
        _check_cron_permissions(),
    ]
