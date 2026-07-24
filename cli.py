#!/usr/bin/env python3
"""
Linux Security Audit Tool
==========================
Runs a battery of read-only security checks against the local Linux host
and produces a scored report (text, JSON, or HTML).

Usage:
    python3 main.py                       # text report to stdout
    python3 main.py --format html -o report.html
    python3 main.py --format json -o report.json
    sudo python3 main.py                  # run as root for full coverage
                                           # (e.g. /etc/shadow checks)

Exit codes:
    0  audit completed, score >= --fail-under threshold (default: no threshold)
    1  audit completed, score < --fail-under threshold
    2  audit could not run (e.g. unsupported platform)
"""

from __future__ import annotations

import argparse
import platform
import socket
import sys
from typing import List

from securityaudit.checks import filesystem, network, ssh_config, system, users
from securityaudit.checks.base import CheckResult
from securityaudit import report

CHECK_MODULES = [users, filesystem, ssh_config, network, system]


def run_all_checks(only_categories: List[str] | None = None) -> List[CheckResult]:
    results: List[CheckResult] = []
    for module in CHECK_MODULES:
        module_results = module.run()
        for r in module_results:
            if only_categories and r.category not in only_categories:
                continue
            results.append(r)
    return results


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Audit this Linux host's security posture and produce a scored report."
    )
    parser.add_argument("--format", choices=["text", "json", "html"], default="text",
                         help="Output report format (default: text)")
    parser.add_argument("-o", "--output", metavar="FILE",
                         help="Write report to FILE instead of stdout")
    parser.add_argument("--fail-under", type=int, metavar="N",
                         help="Exit with code 1 if score falls below N (0-100)")
    parser.add_argument("--category", action="append", metavar="NAME",
                         help="Only run checks in this category (repeatable). "
                              "Categories: Users & Authentication, "
                              "Filesystem & Permissions, SSH Configuration, "
                              "Network Exposure, System Hardening")
    args = parser.parse_args()

    if platform.system() != "Linux":
        print(f"Warning: this tool targets Linux; detected platform is "
              f"'{platform.system()}'. Results may be incomplete.", file=sys.stderr)

    hostname = socket.gethostname()
    results = run_all_checks(only_categories=args.category)

    if not results:
        print("No checks were run (check your --category filter).", file=sys.stderr)
        return 2

    if args.format == "text":
        output = report.render_text(results, hostname)
    elif args.format == "json":
        output = report.render_json(results, hostname)
    else:
        output = report.render_html(results, hostname)

    if args.output:
        with open(args.output, "w") as f:
            f.write(output)
        print(f"Report written to {args.output}")
    else:
        print(output)

    scoring = report.compute_score(results)
    if args.fail_under is not None and scoring["score"] < args.fail_under:
        print(f"\nScore {scoring['score']} is below threshold {args.fail_under}",
              file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
