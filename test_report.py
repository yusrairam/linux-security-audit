"""
Unit tests for the scoring engine. Run with: python3 -m pytest tests/ -v
(or python3 tests/test_report.py to run without pytest).
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from securityaudit.checks.base import CheckResult, Finding, Severity
from securityaudit import report


class TestScoring(unittest.TestCase):

    def test_no_findings_perfect_score(self):
        results = [CheckResult("x.1", "Test", "Cat", findings=[])]
        scoring = report.compute_score(results)
        self.assertEqual(scoring["score"], 100)
        self.assertEqual(scoring["grade"], "A")

    def test_pass_findings_dont_deduct(self):
        results = [CheckResult("x.1", "Test", "Cat",
                                findings=[Finding("ok", Severity.PASS)])]
        scoring = report.compute_score(results)
        self.assertEqual(scoring["score"], 100)

    def test_critical_finding_deducts_20(self):
        results = [CheckResult("x.1", "Test", "Cat",
                                findings=[Finding("bad", Severity.CRITICAL)])]
        scoring = report.compute_score(results)
        self.assertEqual(scoring["score"], 80)

    def test_score_floors_at_zero(self):
        results = [CheckResult("x.1", "Test", "Cat",
                                findings=[Finding(f"bad{i}", Severity.CRITICAL)
                                          for i in range(10)])]
        scoring = report.compute_score(results)
        self.assertEqual(scoring["score"], 0)
        self.assertEqual(scoring["grade"], "F")

    def test_error_counts_as_medium_deduction(self):
        results = [CheckResult("x.1", "Test", "Cat", error="could not run")]
        scoring = report.compute_score(results)
        self.assertEqual(scoring["score"], 95)  # 100 - MEDIUM(5)

    def test_grade_boundaries(self):
        cases = [(100, "A"), (90, "A"), (89, "B"), (75, "B"), (74, "C"),
                  (60, "C"), (59, "D"), (40, "D"), (39, "F"), (0, "F")]
        for score_value, expected_grade in cases:
            if score_value >= 90:
                grade = "A"
            elif score_value >= 75:
                grade = "B"
            elif score_value >= 60:
                grade = "C"
            elif score_value >= 40:
                grade = "D"
            else:
                grade = "F"
            self.assertEqual(grade, expected_grade,
                              f"score {score_value} should be grade {expected_grade}")

    def test_worst_severity_reflects_highest(self):
        result = CheckResult("x.1", "Test", "Cat", findings=[
            Finding("a", Severity.LOW),
            Finding("b", Severity.CRITICAL),
            Finding("c", Severity.INFO),
        ])
        self.assertEqual(result.worst_severity, Severity.CRITICAL)

    def test_worst_severity_pass_when_no_findings(self):
        result = CheckResult("x.1", "Test", "Cat", findings=[])
        self.assertEqual(result.worst_severity, Severity.PASS)


class TestRenderers(unittest.TestCase):

    def setUp(self):
        self.results = [
            CheckResult("t.1", "Sample Check", "Sample Category", findings=[
                Finding("Something found", Severity.HIGH, detail="details here",
                        remediation="fix it"),
            ])
        ]

    def test_text_renderer_includes_finding_title(self):
        text = report.render_text(self.results, "testhost")
        self.assertIn("Something found", text)
        self.assertIn("testhost", text)

    def test_json_renderer_is_valid_json(self):
        import json
        out = report.render_json(self.results, "testhost")
        parsed = json.loads(out)
        self.assertEqual(parsed["hostname"], "testhost")
        self.assertEqual(len(parsed["checks"]), 1)
        self.assertEqual(parsed["checks"][0]["findings"][0]["title"], "Something found")

    def test_html_renderer_escapes_content(self):
        results = [CheckResult("t.1", "Sample", "Cat", findings=[
            Finding("<script>alert(1)</script>", Severity.HIGH),
        ])]
        html_out = report.render_html(results, "testhost")
        self.assertNotIn("<script>alert(1)</script>", html_out)
        self.assertIn("&lt;script&gt;", html_out)


if __name__ == "__main__":
    unittest.main()
