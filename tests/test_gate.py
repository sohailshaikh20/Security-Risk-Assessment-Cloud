"""Tests for the security gate."""

import pytest

from risk_engine.gate import (
    check_findings,
    check_assets,
    check_critical_count,
    check_ml_predictions,
)


class TestCheckFindings:

    def test_passes_low_risk(self):
        findings = [
            {"risk_score": 0.3, "stage": "SAST", "risk_label": "MEDIUM"},
        ]
        assert check_findings(findings) == []

    def test_fails_high_risk(self):
        findings = [
            {"risk_score": 0.80, "stage": "SAST", "risk_label": "CRITICAL",
             "id": "test", "tool": "semgrep", "asset": "app.py"},
        ]
        result = check_findings(findings)
        assert len(result) == 1
        assert result[0]["type"] == "finding"

    def test_iac_lower_threshold(self):
        findings = [
            {"risk_score": 0.72, "stage": "IaC", "risk_label": "HIGH",
             "id": "CKV1", "tool": "checkov", "asset": "main.tf"},
        ]
        result = check_findings(findings)
        assert len(result) == 1  # 0.72 >= 0.70 IaC threshold


class TestCheckAssets:

    def test_passes_safe_assets(self):
        assets = [{"asset": "app.py", "max_risk": 0.5, "count": 3}]
        assert check_assets(assets) == []

    def test_fails_risky_asset(self):
        assets = [{"asset": "app.py", "max_risk": 0.85, "count": 5}]
        result = check_assets(assets)
        assert len(result) == 1


class TestCheckCriticalCount:

    def test_no_criticals_passes(self):
        findings = [
            {"risk_label": "HIGH"},
            {"risk_label": "MEDIUM"},
        ]
        assert check_critical_count(findings) == []

    def test_any_critical_fails(self):
        findings = [
            {"risk_label": "CRITICAL", "id": "X", "tool": "semgrep",
             "risk_score": 0.9},
        ]
        result = check_critical_count(findings)
        assert len(result) == 1
        assert result[0]["type"] == "critical_count"


class TestCheckMLPredictions:

    def test_low_probability_passes(self):
        preds = [{"ml_risk_probability": 0.3, "id": "A", "tool": "semgrep"}]
        assert check_ml_predictions(preds) == []

    def test_high_probability_fails(self):
        preds = [{"ml_risk_probability": 0.85, "id": "A", "tool": "semgrep"}]
        result = check_ml_predictions(preds)
        assert len(result) == 1
