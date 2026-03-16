"""
Finding Normalization Engine
============================
Converts raw scanner outputs (Semgrep, Trivy, Checkov)
into a unified finding format for downstream processing.
"""

import json
from datetime import datetime, timezone
from pathlib import Path

FINDINGS_DIR = Path("findings")


# ==============================
# SEVERITY NORMALIZATION
# ==============================

SEVERITY_SCORES = {
    "CRITICAL": 9,
    "HIGH": 7,
    "MEDIUM": 5,
    "LOW": 3,
    "INFO": 1,
}


def severity_to_score(severity):
    if not severity:
        return 1
    return SEVERITY_SCORES.get(str(severity).upper(), 1)


# ==============================
# CHECKOV SEVERITY MAPPING
# ==============================
# Checkov does not provide a severity field
# in its output. Map check IDs to appropriate
# severity levels based on security impact.

CHECKOV_SEVERITY = {
    # CRITICAL — container escape / full compromise
    "CKV_K8S_1":  "CRITICAL",  # privileged containers
    "CKV_K8S_6":  "CRITICAL",  # root user
    "CKV_K8S_37": "CRITICAL",  # privileged escalation

    # HIGH — significant security risk
    "CKV_K8S_14": "HIGH",      # image tag latest
    "CKV_K8S_43": "HIGH",      # image digest missing
    "CKV_K8S_21": "HIGH",      # default namespace
    "CKV_K8S_28": "HIGH",      # NET_RAW capability
    "CKV_K8S_22": "HIGH",      # read-only filesystem

    # MEDIUM — operational/availability risk
    "CKV_K8S_8":  "MEDIUM",    # liveness probe
    "CKV_K8S_9":  "MEDIUM",    # readiness probe
    "CKV_K8S_10": "MEDIUM",    # CPU requests
    "CKV_K8S_11": "MEDIUM",    # CPU limits
    "CKV_K8S_12": "MEDIUM",    # memory limits
    "CKV_K8S_13": "MEDIUM",    # memory requests
    "CKV_K8S_15": "LOW",       # image pull policy
}


def get_checkov_severity(check_id):
    """Look up severity from Checkov check ID, default to MEDIUM."""
    label = CHECKOV_SEVERITY.get(check_id, "MEDIUM")
    return severity_to_score(label)


# ==============================
# SEMGREP NORMALIZATION
# ==============================

def normalize_semgrep():
    path = FINDINGS_DIR / "semgrep.json"
    if not path.exists():
        return []

    with open(path) as f:
        data = json.load(f)

    results = []
    for item in data.get("results", []):
        results.append({
            "tool": "semgrep",
            "stage": "SAST",
            "asset": item.get("path"),
            "issue_type": item.get("check_id"),
            "id": item.get("check_id"),
            "severity": severity_to_score(
                item.get("extra", {}).get("severity")
            ),
            "evidence": item.get("extra", {}).get("message"),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "metadata": {
                "line_start": item.get("start", {}).get("line"),
                "line_end": item.get("end", {}).get("line"),
            },
        })

    return results


# ==============================
# TRIVY NORMALIZATION
# ==============================

def normalize_trivy():
    path = FINDINGS_DIR / "trivy.json"
    if not path.exists():
        return []

    with open(path) as f:
        data = json.load(f)

    results = []
    for result in data.get("Results", []):
        for vuln in result.get("Vulnerabilities", []) or []:
            results.append({
                "tool": "trivy",
                "stage": "SCA",
                "asset": result.get("Target"),
                "issue_type": "CVE",
                "id": vuln.get("VulnerabilityID"),
                "severity": severity_to_score(
                    vuln.get("Severity")
                ),
                "evidence": vuln.get("Title"),
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "metadata": {
                    "pkg_name": vuln.get("PkgName"),
                    "installed_version": vuln.get("InstalledVersion"),
                    "fixed_version": vuln.get("FixedVersion"),
                    "cvss_score": vuln.get("CVSS", {}).get(
                        "nvd", {}
                    ).get("V3Score"),
                },
            })

    return results


# ==============================
# CHECKOV NORMALIZATION
# ==============================

def _parse_checkov_checks(data):
    """Extract failed checks from a Checkov output (dict or list)."""
    results = []

    entries = data if isinstance(data, list) else [data]

    for entry in entries:
        failed = entry.get("results", {}).get("failed_checks", [])

        for check in failed:
            check_id = check.get("check_id", "")
            results.append({
                "tool": "checkov",
                "stage": "IaC",
                "asset": check.get("file_path"),
                "issue_type": check.get("check_name"),
                "id": check_id,
                "severity": get_checkov_severity(check_id),
                "evidence": (
                    check.get("description")
                    or check.get("guideline")
                ),
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "metadata": {
                    "resource": check.get("resource"),
                    "file_line_range": check.get("file_line_range"),
                },
            })

    return results


def normalize_checkov():
    results = []

    for filename in ["checkov.json", "terraform_checkov.json"]:
        path = FINDINGS_DIR / filename
        if not path.exists():
            continue

        with open(path) as f:
            data = json.load(f)

        results.extend(_parse_checkov_checks(data))

    return results


# ==============================
# MAIN NORMALIZATION PIPELINE
# ==============================

def main():
    all_findings = []

    all_findings.extend(normalize_semgrep())
    all_findings.extend(normalize_trivy())
    all_findings.extend(normalize_checkov())

    output_path = FINDINGS_DIR / "normalized_findings.json"

    with open(output_path, "w") as f:
        json.dump(all_findings, f, indent=2)

    # Print summary per tool
    tool_counts = {}
    for finding in all_findings:
        tool = finding["tool"]
        tool_counts[tool] = tool_counts.get(tool, 0) + 1

    print(f"\n✅ Normalized {len(all_findings)} findings")
    for tool, count in sorted(tool_counts.items()):
        print(f"   {tool}: {count}")
    print(f"\nSaved: {output_path}\n")


if __name__ == "__main__":
    main()
