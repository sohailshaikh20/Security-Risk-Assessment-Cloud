"""
SARIF Report Generator
=======================
Converts the risk report into SARIF (Static Analysis
Results Interchange Format) v2.1.0, enabling native
integration with GitHub's Security tab.

When uploaded via the `github/codeql-action/upload-sarif`
action, findings appear directly in the repository's
Security → Code scanning alerts.
"""

import json
from pathlib import Path
from datetime import datetime, timezone

FINDINGS_DIR = Path("findings")
REPORT_FILE = FINDINGS_DIR / "risk_report.json"
OUTPUT_FILE = FINDINGS_DIR / "devsecops-results.sarif"

SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"
SARIF_VERSION = "2.1.0"


# ==============================
# SEVERITY MAPPING
# ==============================

# SARIF uses: error, warning, note, none
RISK_TO_SARIF_LEVEL = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
    "INFO": "note",
}

# GitHub Security severity: must be numeric string (CVSS-style 0.0-10.0)
RISK_TO_GH_SEVERITY = {
    "CRITICAL": "9.5",
    "HIGH": "7.5",
    "MEDIUM": "5.0",
    "LOW": "2.5",
    "INFO": "1.0",
}


def build_tool_descriptor():
    """Build the SARIF tool component."""
    return {
        "driver": {
            "name": "DevSecOps-Risk-Engine",
            "version": "2.0.0",
            "semanticVersion": "2.0.0",
            "informationUri": "https://github.com/sohailshaikh20/Security-Risk-Assessment-for-Cloud-Native-Applications-in-DevSecOps-Pipelines",
            "rules": [],
        }
    }


def build_rule(finding):
    """Build a SARIF rule descriptor from a finding."""
    risk_label = finding.get("risk_label", "MEDIUM")
    explanation = finding.get("explanation", {})
    weights = explanation.get("weights", {})
    breakdown = explanation.get("score_breakdown", {})

    help_text = f"Risk Score: {finding.get('risk_score', 0)}\n"
    help_text += f"Risk Level: {risk_label}\n"
    help_text += f"Stage: {finding.get('stage', 'unknown')}\n"
    help_text += f"Tool: {finding.get('tool', 'unknown')}\n\n"
    help_text += "Score Breakdown:\n"
    for k, v in breakdown.items():
        w = weights.get(k, "?")
        help_text += f"  {k}: {v} (weight: {w})\n"

    return {
        "id": finding.get("id", "unknown"),
        "name": finding.get("issue_type", "Security Finding"),
        "shortDescription": {
            "text": finding.get("issue_type", "Security vulnerability detected"),
        },
        "fullDescription": {
            "text": (
                finding.get("evidence", "")
                or finding.get("issue_type", "Security finding detected by DevSecOps pipeline")
            ),
        },
        "help": {
            "text": help_text,
            "markdown": help_text,
        },
        "defaultConfiguration": {
            "level": RISK_TO_SARIF_LEVEL.get(risk_label, "warning"),
        },
        "properties": {
            "security-severity": str(round(finding.get("risk_score", 0) * 10, 1)),
            "tags": [
                "security",
                finding.get("stage", "unknown").lower(),
                finding.get("tool", "unknown"),
            ],
        },
    }


def build_result(finding, rule_index):
    """Build a SARIF result from a finding."""
    risk_label = finding.get("risk_label", "MEDIUM")
    asset = finding.get("asset", "unknown")
    metadata = finding.get("metadata") or {}
    line_range = metadata.get("file_line_range")

    # Determine file location
    # Strip leading slash for relative paths
    artifact_path = asset.lstrip("/") if asset else "unknown"

    # Default region
    start_line = 1
    end_line = 1
    if line_range and isinstance(line_range, list) and len(line_range) >= 2:
        start_line = max(1, line_range[0])
        end_line = max(start_line, line_range[1])

    result = {
        "ruleId": finding.get("id", "unknown"),
        "ruleIndex": rule_index,
        "level": RISK_TO_SARIF_LEVEL.get(risk_label, "warning"),
        "message": {
            "text": (
                f"[{risk_label}] {finding.get('issue_type', 'Security finding')} "
                f"(score: {finding.get('risk_score', 0)}, "
                f"tool: {finding.get('tool', 'unknown')})"
            ),
        },
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": artifact_path,
                        "uriBaseId": "%SRCROOT%",
                    },
                    "region": {
                        "startLine": start_line,
                        "endLine": end_line,
                    },
                },
            }
        ],
        "properties": {
            "risk_score": finding.get("risk_score", 0),
            "risk_label": risk_label,
            "tool": finding.get("tool", "unknown"),
            "stage": finding.get("stage", "unknown"),
            "security-severity": RISK_TO_GH_SEVERITY.get(risk_label, "medium"),
        },
    }

    # Add correlation metadata if present
    if metadata.get("correlation_boost"):
        result["properties"]["correlated_tools"] = metadata.get("correlated_tools", [])
        result["properties"]["correlation_count"] = metadata.get("correlation_count", 0)

    return result


def generate_sarif(report):
    """Generate a complete SARIF document."""
    findings = report.get("all_findings", [])

    tool = build_tool_descriptor()
    rules = []
    results = []
    seen_rule_ids = {}

    for finding in findings:
        rule_id = finding.get("id", "unknown")

        # Deduplicate rules
        if rule_id not in seen_rule_ids:
            seen_rule_ids[rule_id] = len(rules)
            rules.append(build_rule(finding))

        rule_index = seen_rule_ids[rule_id]
        results.append(build_result(finding, rule_index))

    tool["driver"]["rules"] = rules

    sarif = {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": tool,
                "results": results,
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "endTimeUtc": datetime.now(timezone.utc).isoformat(),
                    }
                ],
                "properties": {
                    "report_generated_at": report.get("generated_at", ""),
                    "statistics": report.get("statistics", {}),
                },
            }
        ],
    }

    return sarif


def main():
    print("\n📋 Generating SARIF report...\n")

    if not REPORT_FILE.exists():
        raise FileNotFoundError("risk_report.json not found")

    with open(REPORT_FILE) as f:
        report = json.load(f)

    sarif = generate_sarif(report)

    with open(OUTPUT_FILE, "w") as f:
        json.dump(sarif, f, indent=2)

    total_results = len(sarif["runs"][0]["results"])
    total_rules = len(sarif["runs"][0]["tool"]["driver"]["rules"])

    print(f"✅ SARIF report generated")
    print(f"   Results: {total_results}")
    print(f"   Rules: {total_rules}")
    print(f"   Saved: {OUTPUT_FILE}")
    print(f"\n   Upload to GitHub with:")
    print(f"   github/codeql-action/upload-sarif@v3\n")


if __name__ == "__main__":
    main()
