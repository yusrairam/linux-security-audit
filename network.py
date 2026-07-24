"""
Network exposure checks: listening TCP/UDP ports and firewall status.

Prefers `ss` (modern, fast) and falls back to `netstat`. Firewall status
is checked across the three common Linux stacks: ufw, firewalld, iptables.
"""

from __future__ import annotations

import re
from typing import List

from .base import CheckResult, Finding, Severity, run_cmd, command_exists

CATEGORY = "Network Exposure"

# Ports considered high-risk when exposed to all interfaces (0.0.0.0 / ::)
RISKY_PORTS = {
    21: "FTP (unencrypted)",
    23: "Telnet (unencrypted)",
    25: "SMTP",
    111: "rpcbind",
    135: "MS-RPC",
    139: "NetBIOS",
    445: "SMB",
    512: "rexec",
    513: "rlogin",
    514: "rsh",
    2049: "NFS",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis (often unauthenticated)",
    27017: "MongoDB",
}


def _check_listening_ports() -> CheckResult:
    findings: List[Finding] = []
    out = run_cmd(["ss", "-tulnH"])
    parser = "ss"
    if out is None:
        out = run_cmd(["netstat", "-tulnp"])
        parser = "netstat"
    if out is None:
        return CheckResult("net.listening_ports", "Listening ports", CATEGORY,
                            error="Neither 'ss' nor 'netstat' available")

    exposed_risky: List[str] = []
    all_listening: List[str] = []
    for line in out.splitlines():
        # Match address:port at the end of the local-address column
        m = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|\[?::\]?|\*):(\d+)\b", line)
        if not m:
            continue
        addr, port_s = m.group(1), m.group(2)
        try:
            port = int(port_s)
        except ValueError:
            continue
        all_listening.append(f"{addr}:{port}")
        bound_to_all = addr in ("0.0.0.0", "*", "::", "[::]")
        if bound_to_all and port in RISKY_PORTS:
            exposed_risky.append(f"{port} ({RISKY_PORTS[port]})")

    if exposed_risky:
        findings.append(Finding(
            title=f"{len(set(exposed_risky))} risky service(s) exposed on all interfaces",
            severity=Severity.HIGH,
            detail="Ports: " + ", ".join(sorted(set(exposed_risky))),
            remediation="Bind to localhost/private interface only, or restrict via "
                        "firewall rules if the service must remain.",
        ))
    else:
        findings.append(Finding("No high-risk ports exposed on all interfaces", Severity.PASS))

    findings.append(Finding(
        title=f"{len(all_listening)} listening socket(s) detected (via {parser})",
        severity=Severity.INFO,
        detail=", ".join(sorted(set(all_listening))[:25]) +
               (" ..." if len(all_listening) > 25 else ""),
    ))
    return CheckResult("net.listening_ports", "Listening ports", CATEGORY, findings)


def _check_firewall() -> CheckResult:
    findings: List[Finding] = []

    if command_exists("ufw"):
        out = run_cmd(["ufw", "status"]) or ""
        if "Status: active" in out:
            findings.append(Finding("UFW firewall is active", Severity.PASS))
            return CheckResult("net.firewall", "Firewall status", CATEGORY, findings)
        elif "Status: inactive" in out:
            findings.append(Finding(
                "UFW is installed but inactive", Severity.HIGH,
                detail="No firewall rules are being enforced by ufw.",
                remediation="Enable with: sudo ufw enable",
            ))
            return CheckResult("net.firewall", "Firewall status", CATEGORY, findings)

    if command_exists("firewall-cmd"):
        out = run_cmd(["firewall-cmd", "--state"]) or ""
        if "running" in out.lower():
            findings.append(Finding("firewalld is running", Severity.PASS))
            return CheckResult("net.firewall", "Firewall status", CATEGORY, findings)
        else:
            findings.append(Finding(
                "firewalld is installed but not running", Severity.HIGH,
                remediation="Start with: sudo systemctl enable --now firewalld",
            ))
            return CheckResult("net.firewall", "Firewall status", CATEGORY, findings)

    if command_exists("iptables"):
        out = run_cmd(["iptables", "-S"]) or ""
        rule_lines = [l for l in out.splitlines() if l.startswith("-A")]
        if rule_lines:
            findings.append(Finding(
                f"iptables has {len(rule_lines)} active rule(s)", Severity.PASS,
            ))
        else:
            findings.append(Finding(
                "iptables present but no filtering rules configured", Severity.HIGH,
                detail="Default policy alone (often ACCEPT) may leave the host exposed.",
                remediation="Configure a default-deny iptables policy or use ufw/firewalld.",
            ))
        return CheckResult("net.firewall", "Firewall status", CATEGORY, findings)

    return CheckResult("net.firewall", "Firewall status", CATEGORY,
                        findings=[Finding("No known firewall tool found (ufw/firewalld/iptables)",
                                           Severity.HIGH,
                                           remediation="Install and configure a firewall, e.g. 'ufw'.")])


def run() -> List[CheckResult]:
    return [_check_listening_ports(), _check_firewall()]
