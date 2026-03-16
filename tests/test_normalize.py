"""Tests for the normalization engine."""

import json
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from risk_engine.normalize import (
    severity_to_score,
    get_checkov_severity,
    normalize_semgrep,
    normalize_trivy,
    normalize_checkov,
)


# ==============================
# severity_to_score
# ==============================

class TestSeverityToScore:

    def test_critical(self):
        assert severity_to_score("CRITICAL") == 9

    def test_high(self):
        assert severity_to_score("HIGH") == 7

    def test_medium(self):
        assert severity_to_score("MEDIUM") == 5

    def test_low(self):
        assert severity_to_score("LOW") == 3

    def test_info(self):
        assert severity_to_score("INFO") == 1

    def test_case_insensitive(self):
        assert severity_to_score("critical") == 9
        assert severity_to_score("High") == 7

    def test_none_returns_1(self):
        assert severity_to_score(None) == 1

    def test_empty_string_returns_1(self):
        assert severity_to_score("") == 1

    def test_unknown_returns_1(self):
        assert severity_to_score("UNKNOWN") == 1


# ==============================
# get_checkov_severity
# ==============================

class TestCheckovSeverity:

    def test_privileged_container_is_critical(self):
        assert get_checkov_severity("CKV_K8S_1") == 9

    def test_root_user_is_critical(self):
        assert get_checkov_severity("CKV_K8S_6") == 9

    def test_latest_tag_is_high(self):
        assert get_checkov_severity("CKV_K8S_14") == 7

    def test_liveness_probe_is_medium(self):
        assert get_checkov_severity("CKV_K8S_8") == 5

    def test_unknown_check_defaults_to_medium(self):
        assert get_checkov_severity("CKV_UNKNOWN_999") == 5


# ==============================
# Semgrep normalization
# ==============================

class TestNormalizeSemgrep:

    def test_empty_results(self, tmp_path):
        findings = tmp_path / "semgrep.json"
        findings.write_text(json.dumps({"results": []}))

        with patch("risk_engine.normalize.FINDINGS_DIR", tmp_path):
            result = normalize_semgrep()
            assert result == []

    def test_missing_file(self, tmp_path):
        with patch("risk_engine.normalize.FINDINGS_DIR", tmp_path):
            result = normalize_semgrep()
            assert result == []

    def test_parses_finding(self, tmp_path):
        data = {
            "results": [{
                "path": "app.py",
                "check_id": "python.flask.sql-injection",
                "extra": {
                    "severity": "HIGH",
                    "message": "SQL injection detected",
                },
            }]
        }
        (tmp_path / "semgrep.json").write_text(json.dumps(data))

        with patch("risk_engine.normalize.FINDINGS_DIR", tmp_path):
            result = normalize_semgrep()

        assert len(result) == 1
        assert result[0]["tool"] == "semgrep"
        assert result[0]["stage"] == "SAST"
        assert result[0]["severity"] == 7
        assert result[0]["asset"] == "app.py"


# ==============================
# Trivy normalization
# ==============================

class TestNormalizeTrivy:

    def test_no_vulnerabilities(self, tmp_path):
        data = {"Results": [{"Target": "app", "Vulnerabilities": None}]}
        (tmp_path / "trivy.json").write_text(json.dumps(data))

        with patch("risk_engine.normalize.FINDINGS_DIR", tmp_path):
            result = normalize_trivy()
            assert result == []

    def test_parses_cve(self, tmp_path):
        data = {
            "Results": [{
                "Target": "requirements.txt",
                "Vulnerabilities": [{
                    "VulnerabilityID": "CVE-2023-1234",
                    "Severity": "CRITICAL",
                    "Title": "Remote code execution",
                    "PkgName": "flask",
                    "InstalledVersion": "2.2.0",
                    "FixedVersion": "2.3.0",
                }],
            }]
        }
        (tmp_path / "trivy.json").write_text(json.dumps(data))

        with patch("risk_engine.normalize.FINDINGS_DIR", tmp_path):
            result = normalize_trivy()

        assert len(result) == 1
        assert result[0]["tool"] == "trivy"
        assert result[0]["severity"] == 9
        assert result[0]["id"] == "CVE-2023-1234"


# ==============================
# Checkov normalization
# ==============================

class TestNormalizeCheckov:

    def test_dict_format(self, tmp_path):
        data = {
            "results": {
                "failed_checks": [{
                    "check_id": "CKV_K8S_14",
                    "check_name": "Image Tag should be fixed",
                    "file_path": "/main.tf",
                    "resource": "kubernetes_deployment.app",
                    "file_line_range": [1, 50],
                }]
            }
        }
        (tmp_path / "terraform_checkov.json").write_text(json.dumps(data))

        with patch("risk_engine.normalize.FINDINGS_DIR", tmp_path):
            result = normalize_checkov()

        assert len(result) == 1
        assert result[0]["tool"] == "checkov"
        assert result[0]["severity"] == 7  # HIGH, not 1

    def test_list_format(self, tmp_path):
        data = [{
            "results": {
                "failed_checks": [{
                    "check_id": "CKV_K8S_8",
                    "check_name": "Liveness Probe",
                    "file_path": "/main.tf",
                }]
            }
        }]
        (tmp_path / "checkov.json").write_text(json.dumps(data))

        with patch("risk_engine.normalize.FINDINGS_DIR", tmp_path):
            result = normalize_checkov()

        assert len(result) == 1
        assert result[0]["severity"] == 5  # MEDIUM
