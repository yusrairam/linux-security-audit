"""
SSH daemon configuration audit.

Parses /etc/ssh/sshd_config (last-value-wins, as sshd itself applies it)
and flags settings that weaken remote access security.
"""

from __future__ import annotations

import os
import re
from typing import Dict, List

from .base import CheckResult, Finding, Severity

CATEGORY = "SSH Configuration"
SSHD_CONFIG_PATH = "/etc/ssh/sshd_config"


def _parse_sshd_config(path: str) -> Dict[str, str]:
    """Return a dict of directive -> last-set value (sshd uses first match,
    but many hardening scripts append overrides, so we surface the
    effective value most admins expect: the last non-comment occurrence)."""
    settings: Dict[str, str] = {}
    with open(path) as f:
        for raw_line in f:
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            match = re.match(r"^(\S+)\s+(.*)$", line)
            if match:
                key, value = match.group(1), match.group(2).strip()
                settings[key.lower()] = value
    return settings


def run() -> List[CheckResult]:
    if not os.path.exists(SSHD_CONFIG_PATH):
        return [CheckResult("ssh.config", "SSH daemon configuration", CATEGORY,
                             findings=[Finding("sshd not installed / no config found",
                                                Severity.INFO)])]
    try:
        settings = _parse_sshd_config(SSHD_CONFIG_PATH)
    except PermissionError:
        return [CheckResult("ssh.config", "SSH daemon configuration", CATEGORY,
                             error=f"{SSHD_CONFIG_PATH} not readable by current user")]
    except Exception as e:
        return [CheckResult("ssh.config", "SSH daemon configuration", CATEGORY, error=str(e))]

    findings: List[Finding] = []

    root_login = settings.get("permitrootlogin", "prohibit-password")
    if root_login.lower() in ("yes",):
        findings.append(Finding(
            "PermitRootLogin is set to 'yes'", Severity.CRITICAL,
            detail="Direct root login over SSH is fully permitted, including with a password.",
            remediation="Set 'PermitRootLogin no' or 'prohibit-password' in sshd_config.",
        ))
    elif root_login.lower() in ("no", "prohibit-password", "without-password"):
        findings.append(Finding("Root login restricted appropriately", Severity.PASS))
    else:
        findings.append(Finding(f"PermitRootLogin value '{root_login}' unrecognized",
                                 Severity.LOW))

    pw_auth = settings.get("passwordauthentication", "yes")
    if pw_auth.lower() == "yes":
        findings.append(Finding(
            "Password authentication is enabled", Severity.MEDIUM,
            detail="Allows brute-force attempts against user passwords over SSH.",
            remediation="Set 'PasswordAuthentication no' and use key-based auth instead.",
        ))
    else:
        findings.append(Finding("Password authentication disabled", Severity.PASS))

    empty_pw = settings.get("permitemptypasswords", "no")
    if empty_pw.lower() == "yes":
        findings.append(Finding(
            "PermitEmptyPasswords is enabled", Severity.CRITICAL,
            detail="Accounts with blank passwords could log in over SSH.",
            remediation="Set 'PermitEmptyPasswords no'.",
        ))
    else:
        findings.append(Finding("Empty password logins disallowed", Severity.PASS))

    protocol = settings.get("protocol", "2")
    if protocol.strip() == "1":
        findings.append(Finding(
            "Obsolete SSH protocol 1 is enabled", Severity.CRITICAL,
            detail="Protocol 1 has known cryptographic weaknesses.",
            remediation="Remove the 'Protocol 1' directive; only protocol 2 is supported "
                        "by modern OpenSSH anyway.",
        ))
    else:
        findings.append(Finding("SSH protocol version is 2 (or unset default)", Severity.PASS))

    x11 = settings.get("x11forwarding", "no")
    if x11.lower() == "yes":
        findings.append(Finding(
            "X11Forwarding is enabled", Severity.LOW,
            detail="Increases attack surface if a client's X server is compromised.",
            remediation="Disable unless remote GUI forwarding is genuinely needed.",
        ))

    max_auth = settings.get("maxauthtries")
    if max_auth and max_auth.isdigit() and int(max_auth) > 6:
        findings.append(Finding(
            f"MaxAuthTries is high ({max_auth})", Severity.LOW,
            detail="Allows many authentication attempts per connection.",
            remediation="Lower to 3-4 to slow down brute-force attempts.",
        ))

    port = settings.get("port", "22")
    findings.append(Finding(f"SSH listening port: {port}", Severity.INFO))

    banner = settings.get("banner")
    if not banner or banner.lower() == "none":
        findings.append(Finding(
            "No SSH login banner configured", Severity.INFO,
            detail="A legal warning banner can support unauthorized-access prosecution.",
            remediation="Set 'Banner /etc/issue.net' with an appropriate legal notice.",
        ))

    return [CheckResult("ssh.config", "SSH daemon configuration", CATEGORY, findings)]
