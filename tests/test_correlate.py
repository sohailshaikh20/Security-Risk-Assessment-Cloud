"""Tests for the correlation engine."""

import pytest

from risk_engine.correlate import (
    classify_issue,
    correlation_key,
    correlate_findings,
)


class TestClassifyIssue:

    def test_sql_injection(self):
        finding = {"issue_type": "SQL Injection", "evidence": "", "id": ""}
        assert classify_issue(finding) == "injection"

    def test_command_injection(self):
        finding = {"issue_type": "os.popen usage", "evidence": "", "id": ""}
        assert classify_issue(finding) == "injection"

    def test_secrets(self):
        finding = {"issue_type": "Hardcoded password", "evidence": "", "id": ""}
        assert classify_issue(finding) == "secrets"

    def test_container_security(self):
        finding = {"issue_type": "Container runs as root", "evidence": "", "id": ""}
        assert classify_issue(finding) == "container-security"

    def test_cve(self):
        finding = {"issue_type": "CVE", "evidence": "", "id": "CVE-2023-1234"}
        assert classify_issue(finding) == "dependency-vuln"

    def test_unknown(self):
        finding = {"issue_type": "something else", "evidence": "", "id": ""}
        assert classify_issue(finding) == "other"


class TestCorrelateFindings:

    def test_no_duplicates(self):
        findings = [
            {"id": "A", "tool": "semgrep", "asset": "app.py",
             "issue_type": "SQL Injection", "evidence": "",
             "severity": 7, "metadata": {}},
            {"id": "B", "tool": "checkov", "asset": "main.tf",
             "issue_type": "privileged container", "evidence": "",
             "severity": 5, "metadata": {}},
        ]
        result = correlate_findings(findings)
        assert len(result) == 2

    def test_cross_tool_correlation(self):
        findings = [
            {"id": "rule1", "tool": "semgrep", "asset": "app.py",
             "issue_type": "Hardcoded secret key", "evidence": "",
             "severity": 7, "metadata": {}},
            {"id": "CKV123", "tool": "checkov", "asset": "app.py",
             "issue_type": "Secret in code", "evidence": "",
             "severity": 5, "metadata": {}},
        ]
        result = correlate_findings(findings)
        # Both should be in 'secrets' category for app.py
        assert len(result) == 1
        assert result[0]["metadata"]["correlation_boost"] is True
        assert len(result[0]["metadata"]["correlated_tools"]) == 2

    def test_severity_boost(self):
        findings = [
            {"id": "A", "tool": "semgrep", "asset": "app.py",
             "issue_type": "SQL injection", "evidence": "",
             "severity": 7, "metadata": {}},
            {"id": "B", "tool": "trivy", "asset": "app.py",
             "issue_type": "command injection", "evidence": "",
             "severity": 5, "metadata": {}},
        ]
        result = correlate_findings(findings)
        # Should boost the highest severity by 1
        assert result[0]["severity"] == 8

    def test_same_tool_no_boost(self):
        findings = [
            {"id": "A", "tool": "checkov", "asset": "main.tf",
             "issue_type": "privileged container", "evidence": "",
             "severity": 7, "metadata": {}},
            {"id": "B", "tool": "checkov", "asset": "main.tf",
             "issue_type": "root user namespace", "evidence": "",
             "severity": 5, "metadata": {}},
        ]
        result = correlate_findings(findings)
        # Same tool — grouped but no cross-tool boost
        assert result[0]["metadata"]["correlation_boost"] is False
