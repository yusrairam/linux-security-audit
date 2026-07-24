"""
Scoring engine and report renderers.

Takes the flat list of CheckResult objects produced by every check
module and turns them into:
  - a 0-100 security score (100 = no deductions),
  - a grouped, human-readable text report,
  - a machine-readable JSON report,
  - a self-contained HTML report with color-coded severities.
"""

from __future__ import annotations

import html
import json
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Dict, List

from securityaudit.checks.base import CheckResult, Severity

MAX_SCORE = 100

SEVERITY_COLORS = {
    Severity.CRITICAL: "#dc2626",
    Severity.HIGH: "#ea580c",
    Severity.MEDIUM: "#d97706",
    Severity.LOW: "#65a30d",
    Severity.INFO: "#0891b2",
    Severity.PASS: "#16a34a",
}


def compute_score(results: List[CheckResult]) -> Dict:
    """
    Deduct points per finding severity, floor at 0. Errors (check couldn't
    run) count as a flat MEDIUM deduction since an un-auditable area is a
    visibility gap, not a pass.
    """
    score = MAX_SCORE
    counts = {s: 0 for s in Severity}
    for result in results:
        if result.error:
            counts[Severity.MEDIUM] += 1
            score -= Severity.MEDIUM.weight
            continue
        for finding in result.findings:
            counts[finding.severity] += 1
            score -= finding.severity.weight
    score = max(0, score)

    if score >= 90:
        grade = "A"
    elif score >= 75:
        grade = "B"
    elif score >= 60:
        grade = "C"
    elif score >= 40:
        grade = "D"
    else:
        grade = "F"

    return {"score": score, "grade": grade, "counts": {s.value: c for s, c in counts.items()}}


def _group_by_category(results: List[CheckResult]) -> Dict[str, List[CheckResult]]:
    grouped: Dict[str, List[CheckResult]] = {}
    for r in results:
        grouped.setdefault(r.category, []).append(r)
    return grouped


def render_text(results: List[CheckResult], hostname: str) -> str:
    scoring = compute_score(results)
    lines = []
    lines.append("=" * 70)
    lines.append("  LINUX SECURITY AUDIT REPORT")
    lines.append(f"  Host: {hostname}")
    lines.append(f"  Generated: {datetime.now(timezone.utc).isoformat(timespec='seconds')}")
    lines.append(f"  Score: {scoring['score']}/100  (Grade {scoring['grade']})")
    lines.append("=" * 70)

    for category, checks in _group_by_category(results).items():
        lines.append(f"\n## {category}")
        for check in checks:
            lines.append(f"\n  [{check.check_id}] {check.name}")
            if check.error:
                lines.append(f"    ! ERROR: {check.error}")
                continue
            for f in check.findings:
                lines.append(f"    [{f.severity.value:8}] {f.title}")
                if f.detail:
                    lines.append(f"               {f.detail}")
                if f.remediation:
                    lines.append(f"               -> Fix: {f.remediation}")

    lines.append("\n" + "=" * 70)
    lines.append("Finding counts: " + ", ".join(
        f"{k}={v}" for k, v in scoring["counts"].items() if v))
    lines.append("=" * 70)
    return "\n".join(lines)


def render_json(results: List[CheckResult], hostname: str) -> str:
    scoring = compute_score(results)
    payload = {
        "hostname": hostname,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "score": scoring["score"],
        "grade": scoring["grade"],
        "finding_counts": scoring["counts"],
        "checks": [
            {
                "check_id": r.check_id,
                "name": r.name,
                "category": r.category,
                "error": r.error,
                "findings": [asdict(f) for f in r.findings],
            }
            for r in results
        ],
    }

    def default(obj):
        if isinstance(obj, Severity):
            return obj.value
        raise TypeError

    return json.dumps(payload, indent=2, default=default)


def render_html(results: List[CheckResult], hostname: str) -> str:
    scoring = compute_score(results)
    grouped = _group_by_category(results)

    score_color = "#16a34a" if scoring["score"] >= 75 else (
        "#d97706" if scoring["score"] >= 50 else "#dc2626")

    category_html = []
    for category, checks in grouped.items():
        rows = []
        for check in checks:
            if check.error:
                rows.append(f"""
                <div class="check">
                  <div class="check-title">{html.escape(check.name)}
                    <span class="badge" style="background:#6b7280">ERROR</span>
                  </div>
                  <div class="detail">{html.escape(check.error)}</div>
                </div>""")
                continue
            finding_html = []
            for f in check.findings:
                color = SEVERITY_COLORS[f.severity]
                finding_html.append(f"""
                <div class="finding">
                  <span class="badge" style="background:{color}">{f.severity.value}</span>
                  <span class="finding-title">{html.escape(f.title)}</span>
                  {f'<div class="detail">{html.escape(f.detail)}</div>' if f.detail else ''}
                  {f'<div class="remediation">Fix: {html.escape(f.remediation)}</div>' if f.remediation else ''}
                </div>""")
            rows.append(f"""
                <div class="check">
                  <div class="check-title">{html.escape(check.name)}</div>
                  {''.join(finding_html)}
                </div>""")
        category_html.append(f"""
        <section class="category">
          <h2>{html.escape(category)}</h2>
          {''.join(rows)}
        </section>""")

    counts_html = "".join(
        f'<div class="count-pill" style="border-color:{SEVERITY_COLORS[Severity(k)]}">'
        f'{k}: {v}</div>'
        for k, v in scoring["counts"].items() if v
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Linux Security Audit — {html.escape(hostname)}</title>
<style>
  :root {{ color-scheme: light; }}
  * {{ box-sizing: border-box; }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    background: #f8fafc; color: #1e293b; margin: 0; padding: 2rem;
    line-height: 1.5;
  }}
  .container {{ max-width: 900px; margin: 0 auto; }}
  header {{
    background: #0f172a; color: white; border-radius: 12px;
    padding: 2rem; margin-bottom: 2rem; display: flex;
    justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 1rem;
  }}
  header h1 {{ margin: 0 0 .25rem; font-size: 1.4rem; }}
  header p {{ margin: 0; opacity: .75; font-size: .9rem; }}
  .score-box {{ text-align: center; }}
  .score-num {{ font-size: 3rem; font-weight: 700; color: {score_color}; line-height: 1; }}
  .score-grade {{ font-size: 1rem; opacity: .8; }}
  .counts {{ display: flex; gap: .5rem; flex-wrap: wrap; margin-bottom: 2rem; }}
  .count-pill {{
    border: 1.5px solid; border-radius: 999px; padding: .25rem .75rem;
    font-size: .8rem; font-weight: 600;
  }}
  .category {{
    background: white; border-radius: 12px; padding: 1.5rem;
    margin-bottom: 1.5rem; box-shadow: 0 1px 3px rgba(0,0,0,.06);
  }}
  .category h2 {{ margin-top: 0; font-size: 1.1rem; border-bottom: 2px solid #e2e8f0; padding-bottom: .5rem; }}
  .check {{ margin: 1rem 0; padding-left: .25rem; }}
  .check-title {{ font-weight: 600; margin-bottom: .4rem; }}
  .finding {{ margin: .5rem 0 .5rem 0; padding: .6rem .8rem; background: #f8fafc; border-radius: 8px; }}
  .badge {{
    display: inline-block; color: white; font-size: .7rem; font-weight: 700;
    padding: .15rem .5rem; border-radius: 4px; margin-right: .5rem; letter-spacing: .03em;
  }}
  .finding-title {{ font-weight: 500; }}
  .detail {{ font-size: .85rem; color: #475569; margin-top: .3rem; }}
  .remediation {{ font-size: .85rem; color: #0369a1; margin-top: .3rem; font-weight: 500; }}
  footer {{ text-align: center; color: #94a3b8; font-size: .8rem; margin-top: 2rem; }}
</style>
</head>
<body>
<div class="container">
  <header>
    <div>
      <h1>Linux Security Audit</h1>
      <p>Host: {html.escape(hostname)} &middot; Generated {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}</p>
    </div>
    <div class="score-box">
      <div class="score-num">{scoring['score']}</div>
      <div class="score-grade">Grade {scoring['grade']} / 100</div>
    </div>
  </header>
  <div class="counts">{counts_html}</div>
  {''.join(category_html)}
  <footer>Generated by Linux Security Audit Tool</footer>
</div>
</body>
</html>"""
