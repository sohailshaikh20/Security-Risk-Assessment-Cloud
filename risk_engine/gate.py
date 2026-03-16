"""
Security Gate
==============
Enforces risk thresholds and blocks deployments when
security risk exceeds acceptable levels. Integrates
both rule-based scores and ML predictions.
"""

import json
import sys
from pathlib import Path

FINDINGS_DIR = Path("findings")

# =====================================================
# RISK THRESHOLDS
# =====================================================

THRESHOLD_FINDING = 0.75      # individual finding
THRESHOLD_ASSET = 0.80        # asset-level aggregate
THRESHOLD_IAC = 0.70          # infrastructure findings
THRESHOLD_ML = 0.80           # ML predicted probability
MAX_CRITICAL_ALLOWED = 0      # zero tolerance for critical


# =====================================================
# LOAD DATA
# =====================================================

def load_report():
    report_path = FINDINGS_DIR / "risk_report.json"

    if not report_path.exists():
        print("❌ risk_report.json not found")
        sys.exit(1)

    with open(report_path) as f:
        return json.load(f)


def load_ml_predictions():
    ml_path = FINDINGS_DIR / "ml_risk_predictions.json"

    if not ml_path.exists():
        return []

    with open(ml_path) as f:
        return json.load(f)


# =====================================================
# GATE CHECKS
# =====================================================

def check_findings(findings):
    """Check individual finding risk scores."""
    violations = []

    for f in findings:
        score = f.get("risk_score", 0)
        stage = f.get("stage")
        label = f.get("risk_label", "")

        threshold = THRESHOLD_IAC if stage == "IaC" else THRESHOLD_FINDING

        if score >= threshold:
            violations.append({
                "type": "finding",
                "id": f.get("id"),
                "tool": f.get("tool"),
                "score": score,
                "label": label,
                "asset": f.get("asset"),
                "stage": stage,
            })

    return violations


def check_assets(assets):
    """Check asset-level aggregate risk."""
    violations = []

    for a in assets:
        if a.get("max_risk", 0) >= THRESHOLD_ASSET:
            violations.append({
                "type": "asset",
                "asset": a.get("asset"),
                "max_risk": a.get("max_risk"),
                "count": a.get("count"),
            })

    return violations


def check_ml_predictions(predictions):
    """Check ML-predicted high-risk findings."""
    violations = []

    for p in predictions:
        prob = p.get("ml_risk_probability", 0)
        if prob >= THRESHOLD_ML:
            violations.append({
                "type": "ml_prediction",
                "id": p.get("id"),
                "tool": p.get("tool"),
                "probability": prob,
                "anomaly_score": p.get("anomaly_score"),
            })

    return violations


def check_critical_count(findings):
    """Zero tolerance for CRITICAL findings."""
    critical = [
        f for f in findings
        if f.get("risk_label") == "CRITICAL"
    ]

    if len(critical) > MAX_CRITICAL_ALLOWED:
        return [{
            "type": "critical_count",
            "count": len(critical),
            "limit": MAX_CRITICAL_ALLOWED,
            "findings": [
                {
                    "id": f.get("id"),
                    "tool": f.get("tool"),
                    "score": f.get("risk_score"),
                }
                for f in critical[:5]
            ],
        }]

    return []


# =====================================================
# MAIN SECURITY GATE
# =====================================================

def main():
    report = load_report()
    ml_predictions = load_ml_predictions()

    findings = report.get("all_findings", [])
    assets = report.get("assets", [])
    stats = report.get("statistics", {})

    print("\n" + "=" * 55)
    print("  🔒 DevSecOps Security Gate")
    print("=" * 55)

    # Print summary
    print(f"\n  Total findings:  {stats.get('total_findings', len(findings))}")
    print(f"  Average risk:    {stats.get('avg_risk', 'N/A')}")
    print(f"  Max risk:        {stats.get('max_risk', 'N/A')}")
    print(f"  Critical:        {stats.get('critical_count', 0)}")
    print(f"  High:            {stats.get('high_count', 0)}")
    print(f"  Medium:          {stats.get('medium_count', 0)}")
    print(f"  Low:             {stats.get('low_count', 0)}")

    print(f"\n  Thresholds:")
    print(f"    Finding:       {THRESHOLD_FINDING}")
    print(f"    IaC:           {THRESHOLD_IAC}")
    print(f"    Asset:         {THRESHOLD_ASSET}")
    print(f"    ML:            {THRESHOLD_ML}")
    print(f"    Max Critical:  {MAX_CRITICAL_ALLOWED}")

    # Run all checks
    all_violations = []

    critical_violations = check_critical_count(findings)
    all_violations.extend(critical_violations)

    finding_violations = check_findings(findings)
    all_violations.extend(finding_violations)

    asset_violations = check_assets(assets)
    all_violations.extend(asset_violations)

    ml_violations = check_ml_predictions(ml_predictions)
    all_violations.extend(ml_violations)

    # =====================================================
    # DECISION
    # =====================================================

    print(f"\n{'=' * 55}")

    if not all_violations:
        print("  ✅ PASSED — Risk within acceptable thresholds")
        print(f"{'=' * 55}\n")
        sys.exit(0)

    print("  ❌ FAILED — Security gate blocked deployment")
    print(f"{'=' * 55}\n")

    # Group and display violations
    if critical_violations:
        print("  🚨 CRITICAL FINDINGS (zero tolerance):\n")
        for v in critical_violations:
            print(f"     {v['count']} critical finding(s) found (max allowed: {v['limit']})")
            for f in v.get("findings", []):
                print(f"       → {f['id']} ({f['tool']}) score={f['score']}")
        print()

    if finding_violations:
        print(f"  ⛔ HIGH-RISK FINDINGS ({len(finding_violations)}):\n")
        for v in finding_violations[:5]:
            print(
                f"     [{v['label']}] {v['id']} "
                f"({v['tool']}) score={v['score']} "
                f"asset={v['asset']}"
            )
        if len(finding_violations) > 5:
            print(f"     ... and {len(finding_violations) - 5} more")
        print()

    if asset_violations:
        print(f"  ⛔ HIGH-RISK ASSETS ({len(asset_violations)}):\n")
        for v in asset_violations[:5]:
            print(
                f"     {v['asset']} "
                f"max_risk={v['max_risk']} "
                f"({v['count']} findings)"
            )
        print()

    if ml_violations:
        print(f"  ⛔ ML-PREDICTED HIGH RISK ({len(ml_violations)}):\n")
        for v in ml_violations[:5]:
            print(
                f"     {v['id']} ({v['tool']}) "
                f"probability={v['probability']}"
            )
        print()

    # Save gate result
    gate_result = {
        "status": "FAILED",
        "total_violations": len(all_violations),
        "violations": all_violations[:20],
    }

    gate_path = FINDINGS_DIR / "gate_result.json"
    with open(gate_path, "w") as f:
        json.dump(gate_result, f, indent=2)

    print(f"  📄 Gate result saved to {gate_path}\n")

    sys.exit(1)


if __name__ == "__main__":
    main()
