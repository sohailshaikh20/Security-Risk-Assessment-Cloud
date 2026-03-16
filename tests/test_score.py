"""Tests for the risk scoring engine."""

import pytest

from risk_engine.score import (
    clamp01,
    severity_norm,
    guess_exposure,
    guess_criticality,
    freshness_norm,
    compute_risk,
    risk_label,
)


class TestClamp:

    def test_within_range(self):
        assert clamp01(0.5) == 0.5

    def test_below_zero(self):
        assert clamp01(-0.1) == 0.0

    def test_above_one(self):
        assert clamp01(1.5) == 1.0

    def test_boundaries(self):
        assert clamp01(0.0) == 0.0
        assert clamp01(1.0) == 1.0


class TestSeverityNorm:

    def test_critical_severity(self):
        finding = {"severity": 9}
        assert severity_norm(finding) == 0.9

    def test_low_severity(self):
        finding = {"severity": 3}
        assert severity_norm(finding) == 0.3

    def test_cvss_preferred(self):
        finding = {
            "severity": 3,
            "metadata": {"cvss_score": 9.8},
        }
        assert severity_norm(finding) == 0.98

    def test_missing_severity(self):
        finding = {}
        assert severity_norm(finding) == 0.1


class TestGuessExposure:

    def test_loadbalancer(self):
        assert guess_exposure("kubernetes_service.lb") == "internet"

    def test_public(self):
        assert guess_exposure("/public/api.py") == "internet"

    def test_internal(self):
        assert guess_exposure("internal-cluster-svc") == "internal"

    def test_unknown(self):
        assert guess_exposure("main.tf") == "unknown"

    def test_none(self):
        assert guess_exposure(None) == "unknown"


class TestGuessCriticality:

    def test_prod(self):
        assert guess_criticality("payment-service.py") == "prod"

    def test_auth(self):
        assert guess_criticality("auth/login.py") == "prod"

    def test_staging(self):
        assert guess_criticality("test_app.py") == "staging"

    def test_dev(self):
        assert guess_criticality("demo-app") == "dev"

    def test_unknown(self):
        assert guess_criticality("main.tf") == "unknown"


class TestRiskLabel:

    def test_critical(self):
        assert risk_label(0.80) == "CRITICAL"

    def test_high(self):
        assert risk_label(0.60) == "HIGH"

    def test_medium(self):
        assert risk_label(0.40) == "MEDIUM"

    def test_low(self):
        assert risk_label(0.20) == "LOW"

    def test_info(self):
        assert risk_label(0.05) == "INFO"


class TestComputeRisk:

    def test_returns_score_and_explanation(self):
        finding = {
            "tool": "semgrep",
            "stage": "SAST",
            "severity": 9,
            "asset": "app.py",
            "timestamp": "2026-01-01T00:00:00+00:00",
            "metadata": {},
        }
        score, explanation = compute_risk(finding)

        assert 0 <= score <= 1
        assert "score_breakdown" in explanation
        assert "feature_values" in explanation
        assert "weights" in explanation

    def test_high_severity_scores_higher(self):
        base = {
            "tool": "semgrep",
            "stage": "SAST",
            "asset": "app.py",
            "timestamp": "2026-01-01T00:00:00+00:00",
            "metadata": {},
        }

        low = dict(base, severity=1)
        high = dict(base, severity=9)

        low_score, _ = compute_risk(low)
        high_score, _ = compute_risk(high)

        assert high_score > low_score

    def test_iac_stage_multiplier(self):
        base = {
            "tool": "checkov",
            "severity": 7,
            "asset": "main.tf",
            "timestamp": "2026-01-01T00:00:00+00:00",
            "metadata": {},
        }

        sast = dict(base, stage="SAST")
        iac = dict(base, stage="IaC")

        sast_score, _ = compute_risk(sast)
        iac_score, _ = compute_risk(iac)

        assert iac_score > sast_score

    def test_correlation_boost(self):
        base = {
            "tool": "semgrep",
            "stage": "SAST",
            "severity": 7,
            "asset": "app.py",
            "timestamp": "2026-01-01T00:00:00+00:00",
        }

        normal = dict(base, metadata={})
        boosted = dict(base, metadata={"correlation_boost": True})

        normal_score, _ = compute_risk(normal)
        boosted_score, _ = compute_risk(boosted)

        assert boosted_score > normal_score
