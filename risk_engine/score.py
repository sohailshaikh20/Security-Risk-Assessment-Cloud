"""
Explainable Risk Scoring Engine
================================
Computes a transparent, weighted risk score for each
finding using severity, exposure, criticality, tool
confidence, and freshness. Outputs JSON + Markdown reports.
"""

import json
from pathlib import Path
from collections import defaultdict
from datetime import datetime, timezone
from typing import Dict, Tuple

FINDINGS_DIR = Path("findings")
TOP_N = 10

# =====================================================
# EXPLAINABLE MODEL WEIGHTS
# =====================================================

WEIGHTS = {
    "severity": 0.40,
    "exposure": 0.20,
    "criticality": 0.15,
    "confidence": 0.15,
    "freshness": 0.10,
}

# Stage importance multiplier
STAGE_WEIGHT = {
    "SAST": 0.9,
    "SCA": 1.0,
    "IaC": 1.1,
}

# =====================================================
# FEATURE MAPS
# =====================================================

EXPOSURE_MAP = {
    "internet": 1.0,
    "internal": 0.5,
    "unknown": 0.3,
}

CRITICALITY_MAP = {
    "prod": 1.0,
    "staging": 0.6,
    "dev": 0.3,
    "unknown": 0.5,
}

TOOL_CONFIDENCE = {
    "trivy": 0.85,
    "checkov": 0.80,
    "semgrep": 0.75,
}


# =====================================================
# UTILITIES
# =====================================================

def clamp01(x: float) -> float:
    return max(0.0, min(1.0, x))


def severity_norm(finding: Dict) -> float:
    """Normalize severity to 0–1 range. Prefer CVSS if available."""
    metadata = finding.get("metadata") or {}
    cvss = metadata.get("cvss_score")

    if cvss is not None:
        try:
            return clamp01(float(cvss) / 10.0)
        except (ValueError, TypeError):
            pass

    try:
        return clamp01(float(finding.get("severity", 1)) / 10.0)
    except (ValueError, TypeError):
        return 0.1


def guess_exposure(asset: str) -> str:
    a = (asset or "").lower()

    if any(x in a for x in [
        "ingress", "loadbalancer", "public", "internet", "service"
    ]):
        return "internet"

    if any(x in a for x in ["cluster", "internal", "private"]):
        return "internal"

    return "unknown"


def guess_criticality(asset: str) -> str:
    a = (asset or "").lower()

    if any(x in a for x in [
        "prod", "payment", "auth", "user", "order", "login"
    ]):
        return "prod"

    if any(x in a for x in ["stage", "test"]):
        return "staging"

    if any(x in a for x in ["dev", "demo", "sample"]):
        return "dev"

    return "unknown"


def freshness_norm(timestamp: str) -> float:
    try:
        t = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        age_days = (datetime.now(timezone.utc) - t).days

        if age_days < 1:
            return 1.0
        if age_days < 7:
            return 0.8
        if age_days < 30:
            return 0.5
        return 0.2

    except Exception:
        return 1.0


# =====================================================
# FEATURE EXTRACTION
# =====================================================

def extract_features(finding: Dict) -> Dict:
    sev = severity_norm(finding)

    metadata = finding.get("metadata") or {}

    exposure_label = (
        metadata.get("exposure")
        or guess_exposure(finding.get("asset"))
    )
    exposure = EXPOSURE_MAP.get(exposure_label, EXPOSURE_MAP["unknown"])

    criticality_label = (
        metadata.get("criticality")
        or guess_criticality(finding.get("asset"))
    )
    criticality = CRITICALITY_MAP.get(
        criticality_label, CRITICALITY_MAP["unknown"]
    )

    confidence = TOOL_CONFIDENCE.get(finding.get("tool"), 0.6)

    # Boost confidence for correlated findings
    if metadata.get("correlation_boost"):
        confidence = min(confidence + 0.10, 1.0)

    freshness = freshness_norm(finding.get("timestamp"))

    stage = finding.get("stage", "unknown")
    stage_multiplier = STAGE_WEIGHT.get(stage, 1.0)

    return {
        "severity": sev,
        "exposure": exposure,
        "criticality": criticality,
        "confidence": confidence,
        "freshness": freshness,
        "stage_weight": stage_multiplier,
        "labels": {
            "exposure": exposure_label,
            "criticality": criticality_label,
            "stage": stage,
        },
    }


# =====================================================
# RISK MODEL
# =====================================================

def compute_risk(finding: Dict) -> Tuple[float, Dict]:
    features = extract_features(finding)

    contributions = {}
    score = 0.0

    for feature, weight in WEIGHTS.items():
        contribution = weight * features[feature]
        contributions[feature] = round(contribution, 4)
        score += contribution

    # Apply stage multiplier
    score = clamp01(score * features["stage_weight"])
    score = round(score, 4)

    explanation = {
        "model": "weighted-linear-risk-v2",
        "stage_multiplier": features["stage_weight"],
        "score_breakdown": contributions,
        "feature_values": {
            "severity_norm": round(features["severity"], 3),
            "exposure": features["labels"]["exposure"],
            "criticality": features["labels"]["criticality"],
            "confidence": round(features["confidence"], 3),
            "freshness_norm": round(features["freshness"], 3),
            "stage": features["labels"]["stage"],
        },
        "weights": WEIGHTS,
    }

    return score, explanation


# =====================================================
# RISK RATING LABEL
# =====================================================

def risk_label(score: float) -> str:
    if score >= 0.75:
        return "CRITICAL"
    if score >= 0.55:
        return "HIGH"
    if score >= 0.35:
        return "MEDIUM"
    if score >= 0.15:
        return "LOW"
    return "INFO"


# =====================================================
# MAIN PIPELINE
# =====================================================

def main():
    input_path = FINDINGS_DIR / "correlated_findings.json"

    if not input_path.exists():
        raise FileNotFoundError("correlated_findings.json not found")

    with open(input_path) as f:
        findings = json.load(f)

    scored = []
    asset_scores = defaultdict(list)

    for f in findings:
        score, explanation = compute_risk(f)

        f2 = dict(f)
        f2["risk_score"] = score
        f2["risk_label"] = risk_label(score)
        f2["explanation"] = explanation

        scored.append(f2)
        asset_scores[f2.get("asset", "unknown")].append(score)

    # =====================================================
    # ASSET LEVEL AGGREGATION
    # =====================================================

    asset_summary = []

    for asset, scores in asset_scores.items():
        asset_summary.append({
            "asset": asset,
            "avg_risk": round(sum(scores) / len(scores), 4),
            "max_risk": round(max(scores), 4),
            "count": len(scores),
            "risk_label": risk_label(max(scores)),
        })

    scored.sort(key=lambda x: x["risk_score"], reverse=True)
    asset_summary.sort(key=lambda x: x["max_risk"], reverse=True)

    # =====================================================
    # STATISTICS
    # =====================================================

    all_scores = [s["risk_score"] for s in scored]
    stats = {}
    if all_scores:
        stats = {
            "total_findings": len(scored),
            "avg_risk": round(sum(all_scores) / len(all_scores), 4),
            "max_risk": round(max(all_scores), 4),
            "min_risk": round(min(all_scores), 4),
            "critical_count": sum(
                1 for s in scored if s["risk_label"] == "CRITICAL"
            ),
            "high_count": sum(
                1 for s in scored if s["risk_label"] == "HIGH"
            ),
            "medium_count": sum(
                1 for s in scored if s["risk_label"] == "MEDIUM"
            ),
            "low_count": sum(
                1 for s in scored if s["risk_label"] == "LOW"
            ),
        }

    # =====================================================
    # SAVE JSON REPORT
    # =====================================================

    out_json = FINDINGS_DIR / "risk_report.json"

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "statistics": stats,
        "top_findings": scored[:TOP_N],
        "assets": asset_summary,
        "all_findings": scored,
    }

    with open(out_json, "w") as f:
        json.dump(report, f, indent=2)

    # =====================================================
    # SAVE MARKDOWN REPORT
    # =====================================================

    out_md = FINDINGS_DIR / "risk_report.md"

    with open(out_md, "w") as f:
        f.write("# DevSecOps Risk Assessment Report\n\n")
        f.write(f"**Generated:** {datetime.now(timezone.utc).isoformat()}\n\n")
        f.write(f"**Total findings:** {len(scored)}\n\n")

        if stats:
            f.write("## Risk Summary\n\n")
            f.write(f"| Metric | Value |\n")
            f.write(f"|--------|-------|\n")
            f.write(f"| Average Risk | {stats['avg_risk']} |\n")
            f.write(f"| Max Risk | {stats['max_risk']} |\n")
            f.write(f"| Critical | {stats['critical_count']} |\n")
            f.write(f"| High | {stats['high_count']} |\n")
            f.write(f"| Medium | {stats['medium_count']} |\n")
            f.write(f"| Low | {stats['low_count']} |\n\n")

        f.write(f"## Top {TOP_N} Highest Risk Findings\n\n")

        for i, item in enumerate(scored[:TOP_N], start=1):
            f.write(
                f"{i}. **[{item.get('risk_label')}]** "
                f"`{item.get('tool')}` | "
                f"score={item['risk_score']} | "
                f"id={item.get('id')} | "
                f"asset={item.get('asset')}\n"
            )
            f.write(f"   - type: {item.get('issue_type')}\n")
            f.write(f"   - stage: {item.get('stage')}\n")
            f.write(
                f"   - evidence: "
                f"{str(item.get('evidence'))[:180]}\n"
            )

            exp = item["explanation"]["score_breakdown"]
            f.write("   - contributions:\n")
            for k, v in exp.items():
                f.write(f"       {k}: {v}\n")
            f.write("\n")

        f.write("## Asset Risk Summary\n\n")

        f.write("| Asset | Max Risk | Avg Risk | Count | Label |\n")
        f.write("|-------|----------|----------|-------|-------|\n")
        for a in asset_summary[:TOP_N]:
            f.write(
                f"| {a['asset']} | {a['max_risk']} | "
                f"{a['avg_risk']} | {a['count']} | "
                f"{a['risk_label']} |\n"
            )

    print(f"\n✅ Scored {len(scored)} findings")
    if stats:
        print(f"   Critical: {stats['critical_count']}")
        print(f"   High:     {stats['high_count']}")
        print(f"   Medium:   {stats['medium_count']}")
        print(f"   Low:      {stats['low_count']}")
    print(f"\nSaved: {out_json}")
    print(f"Saved: {out_md}\n")


if __name__ == "__main__":
    main()
