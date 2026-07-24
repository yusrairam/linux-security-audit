"""
User account, password, and privilege checks.

Reads /etc/passwd, /etc/shadow (if readable), and group membership to
find classic account misconfigurations: duplicate UID 0 accounts, empty
passwords, unlocked system accounts, and an oversized sudo/wheel group.
"""

from __future__ import annotations

import grp
import os
import pwd
from typing import List

from .base import CheckResult, Finding, Severity

CATEGORY = "Users & Authentication"

# Accounts below this UID are conventionally "system" accounts and should
# not normally have an interactive login shell.
SYSTEM_UID_THRESHOLD = 1000

LOGIN_SHELLS_OK_FOR_SYSTEM = {"/usr/sbin/nologin", "/bin/false", "/sbin/nologin"}


def _check_duplicate_root() -> CheckResult:
    findings: List[Finding] = []
    try:
        uid0 = [u.pw_name for u in pwd.getpwall() if u.pw_uid == 0]
        if len(uid0) > 1:
            findings.append(Finding(
                title="Multiple accounts share UID 0",
                severity=Severity.CRITICAL,
                detail=f"Accounts with UID 0: {', '.join(uid0)}. Any one of these "
                       f"has full root privileges.",
                remediation="Ensure only 'root' uses UID 0; reassign or remove others.",
            ))
        else:
            findings.append(Finding("Single UID 0 account", Severity.PASS))
    except Exception as e:
        return CheckResult("users.duplicate_root", "Duplicate UID 0 accounts",
                            CATEGORY, error=str(e))
    return CheckResult("users.duplicate_root", "Duplicate UID 0 accounts",
                        CATEGORY, findings)


def _check_system_accounts_shell() -> CheckResult:
    findings: List[Finding] = []
    try:
        for u in pwd.getpwall():
            if u.pw_uid < SYSTEM_UID_THRESHOLD and u.pw_name != "root":
                if u.pw_shell not in LOGIN_SHELLS_OK_FOR_SYSTEM and u.pw_shell != "":
                    findings.append(Finding(
                        title=f"System account '{u.pw_name}' has a login shell",
                        severity=Severity.MEDIUM,
                        detail=f"UID {u.pw_uid}, shell={u.pw_shell}. System/service "
                               f"accounts should not be able to log in interactively.",
                        remediation=f"chsh -s /usr/sbin/nologin {u.pw_name}",
                    ))
        if not findings:
            findings.append(Finding("System accounts correctly shell-locked", Severity.PASS))
    except Exception as e:
        return CheckResult("users.system_shells", "System account shells",
                            CATEGORY, error=str(e))
    return CheckResult("users.system_shells", "System account shells",
                        CATEGORY, findings)


def _check_empty_passwords() -> CheckResult:
    findings: List[Finding] = []
    shadow_path = "/etc/shadow"
    if not os.access(shadow_path, os.R_OK):
        return CheckResult("users.empty_passwords", "Empty password check",
                            CATEGORY, error="/etc/shadow not readable (run as root for this check)")
    try:
        with open(shadow_path) as f:
            for line in f:
                parts = line.strip().split(":")
                if len(parts) < 2:
                    continue
                user, pw_field = parts[0], parts[1]
                if pw_field == "":
                    findings.append(Finding(
                        title=f"Account '{user}' has no password set",
                        severity=Severity.CRITICAL,
                        detail="Empty password hash allows login with no credentials "
                               "on services that permit blank passwords.",
                        remediation=f"passwd -l {user}  # or set a strong password",
                    ))
        if not findings:
            findings.append(Finding("No empty password hashes found", Severity.PASS))
    except Exception as e:
        return CheckResult("users.empty_passwords", "Empty password check",
                            CATEGORY, error=str(e))
    return CheckResult("users.empty_passwords", "Empty password check",
                        CATEGORY, findings)


def _check_sudo_group() -> CheckResult:
    findings: List[Finding] = []
    try:
        sudo_members: List[str] = []
        for group_name in ("sudo", "wheel", "admin"):
            try:
                g = grp.getgrnam(group_name)
                sudo_members.extend(g.gr_mem)
            except KeyError:
                continue
        sudo_members = sorted(set(sudo_members))
        if len(sudo_members) > 5:
            findings.append(Finding(
                title="Large number of users with sudo/admin privileges",
                severity=Severity.LOW,
                detail=f"{len(sudo_members)} accounts can escalate to root: "
                       f"{', '.join(sudo_members)}.",
                remediation="Apply least privilege: remove accounts that don't need root.",
            ))
        elif sudo_members:
            findings.append(Finding(
                title="Sudo-capable accounts",
                severity=Severity.INFO,
                detail=f"{len(sudo_members)} account(s): {', '.join(sudo_members)}",
            ))
        else:
            findings.append(Finding("No sudo/wheel group members found", Severity.INFO))
    except Exception as e:
        return CheckResult("users.sudo_group", "Sudo group membership",
                            CATEGORY, error=str(e))
    return CheckResult("users.sudo_group", "Sudo group membership",
                        CATEGORY, findings)


def run() -> List[CheckResult]:
    return [
        _check_duplicate_root(),
        _check_system_accounts_shell(),
        _check_empty_passwords(),
        _check_sudo_group(),
    ]
