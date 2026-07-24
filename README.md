# Linux Security Audit Tool

A read-only, dependency-free security auditing tool for Linux hosts. It
inspects user accounts, filesystem permissions, SSH configuration,
network exposure, and system hardening, then produces a scored report
in text, JSON, or HTML.

No changes are ever made to the system — every check only reads state.

## Features

- **5 audit categories, 15 individual checks** covering the areas most
  commonly assessed in CIS Benchmark-style hardening reviews:
  - **Users & Authentication** — duplicate UID 0 accounts, system
    accounts with login shells, empty password hashes, sudo group size
  - **Filesystem & Permissions** — unexpected SUID/SGID binaries,
    world-writable files/directories, missing sticky bits, unowned files
  - **SSH Configuration** — root login, password auth, empty passwords,
    protocol version, X11 forwarding, MaxAuthTries, login banner
  - **Network Exposure** — listening ports bound to all interfaces,
    known-risky services (Telnet, SMB, Redis, etc.), firewall status
    (ufw / firewalld / iptables)
  - **System Hardening** — pending security updates, SELinux/AppArmor
    status, legacy services, cron path permissions
- **0–100 security score** with a letter grade (A–F), weighted by
  finding severity (INFO/LOW/MEDIUM/HIGH/CRITICAL)
- **Three report formats**: colorized HTML, structured JSON (for CI or
  dashboards), and plain text (for terminals/logs)
- **Fails soft**: a check that can't run (e.g. `/etc/shadow` unreadable
  as non-root) is reported as an error, not a crash — the rest of the
  audit still completes
- **CI-friendly**: `--fail-under N` exits non-zero when the score drops
  below a threshold, so it can gate a pipeline

## Requirements

- Python 3.8+
- Standard Linux userland tools where available: `find`, `ss` (or
  `netstat`), `ufw`/`firewall-cmd`/`iptables`, `apt`/`dnf`/`yum`,
  `getenforce`/`aa-status`, `systemctl`. Missing tools degrade a single
  check to an "error" entry rather than failing the whole run.
- No third-party Python packages required to run the audit itself.

## Quick Start — 3 ways to run this on any machine

Pick whichever fits your situation. All three run the exact same audit logic.

### Option A — Single file, zero install (easiest for sharing)

`security-audit.pyz` is a self-contained, ~100 KB executable Python archive.
Anyone with Python 3.8+ already on their machine can run it with **no pip
install, no virtualenv, no setup**:

```bash
python3 security-audit.pyz --format text
python3 security-audit.pyz --format html -o report.html

# or, since it's executable:
./security-audit.pyz --format text
```

Just copy this one file to any Linux machine (scp, USB, download link —
anything) and run it. This is the best option when you want someone else
to try the tool without asking them to install anything.

### Option B — pip install (adds a permanent `security-audit` command)

```bash
git clone <this-repo>            # or unzip the project folder
cd linux-security-audit
./install.sh
```

`install.sh` installs the package for your user only (no root needed) and
adds a `security-audit` command to your shell. After that:

```bash
security-audit --format html -o report.html
sudo security-audit                          # for full coverage (root-only checks)
```

Prefer to do it by hand instead of the script?

```bash
pip install --user .
python3 -m securityaudit --format text        # also works without the command on PATH
```

### Option C — Docker (no Python required on the host at all)

```bash
docker build -t security-audit .
docker run --rm -v /:/host:ro security-audit --format text
```

Useful when you want to ship the tool to a machine that doesn't have
Python installed, or want it fully isolated from the host's own Python
environment. Note: some checks (network sockets, PIDs) see the
*container's* view unless you add `--pid=host --network=host` — see the
comments at the top of the `Dockerfile` for details and trade-offs.

### CLI reference (same for all three methods)

| Flag | Description |
|---|---|
| `--format {text,json,html}` | Output format (default: `text`) |
| `-o, --output FILE` | Write the report to a file instead of stdout |
| `--fail-under N` | Exit code `1` if the score is below `N` (0–100) |
| `--category NAME` | Restrict the run to one category; repeatable |

## Project layout

```
linux-security-audit/
├── securityaudit/            # the installable Python package
│   ├── __init__.py           # package version
│   ├── __main__.py           # enables `python3 -m securityaudit`
│   ├── cli.py                # CLI entry point / orchestrator
│   ├── report.py             # Scoring engine + text/JSON/HTML renderers
│   └── checks/
│       ├── base.py           # Shared Finding / CheckResult / Severity types
│       ├── users.py          # Account & auth checks
│       ├── filesystem.py     # Permission checks
│       ├── ssh_config.py     # sshd_config parsing & rules
│       ├── network.py        # Listening ports & firewall status
│       └── system.py         # Updates, MAC, services, cron
├── tests/
│   └── test_report.py        # Unit tests for scoring & rendering
├── pyproject.toml            # makes the project pip-installable
├── install.sh                # one-command installer (Option B)
├── Dockerfile                 # container build (Option C)
├── security-audit.pyz        # single-file executable (Option A)
└── requirements.txt
```

## How scoring works

Every check returns one or more `Finding`s, each with a `Severity`.
Severities deduct points from a starting score of 100:

| Severity | Points deducted |
|---|---|
| CRITICAL | 20 |
| HIGH | 10 |
| MEDIUM | 5 |
| LOW | 2 |
| INFO / PASS | 0 |

A check that can't run at all (e.g. permission denied, missing binary)
counts as one MEDIUM deduction — an unauditable area is a visibility
gap, not automatically a pass. The final score floors at 0 and maps to
a letter grade:

| Score | Grade |
|---|---|
| 90–100 | A |
| 75–89 | B |
| 60–74 | C |
| 40–59 | D |
| 0–39 | F |

## Extending the tool

Each check module exposes a `run() -> List[CheckResult]` function. To
add a new category:

1. Create `securityaudit/checks/your_module.py` implementing `run()`,
   returning `CheckResult` objects built from `Finding`s (see
   `securityaudit/checks/base.py`).
2. Register the module in `CHECK_MODULES` in `securityaudit/cli.py`.
3. If you built `security-audit.pyz`, rebuild it (see "Rebuilding the
   .pyz" below) so the single-file version picks up the change.

Because every check fails soft (wrapped in `run_cmd`'s `None`-on-error
contract, or a try/except returning `CheckResult(..., error=...)`), a
broken or environment-specific check never crashes the whole audit.

### Rebuilding the .pyz

After changing anything under `securityaudit/`, regenerate the single-file
executable with Python's built-in `zipapp` module:

```bash
python3 -m zipapp securityaudit -o security-audit.pyz -p "/usr/bin/env python3"
```

## Limitations & honest caveats

- This is a **point-in-time snapshot**, not continuous monitoring —
  pair it with proper log monitoring / IDS for ongoing coverage.
- Some checks (e.g. `/etc/shadow` parsing, full SUID sweep of `/`) need
  root to be fully accurate; running as a normal user will surface
  those as "error" entries rather than false negatives.
- The risky-port and legacy-service lists are illustrative starting
  points, not an exhaustive CIS Benchmark implementation — treat this
  as a first-pass triage tool, not a compliance certification.
- Filesystem scans are scoped to common directories (`/etc`, `/usr`,
  `/home`, `/opt`) rather than the entire filesystem, to keep runtime
  reasonable on large systems.
- Auditing from inside Docker sees the container's own namespaces
  (PIDs, network) unless run with `--pid=host --network=host` — for a
  fully accurate host audit, Options A or B (running natively) are
  more reliable.
