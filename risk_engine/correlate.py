"""
Vulnerability Correlation Engine
=================================
Groups related findings detected by multiple scanners,
deduplicates, and boosts severity for cross-tool matches.
"""

import json
from pathlib import Path
from collections import defaultdict

FINDINGS_DIR = Path("findings")


# ==============================
# ISSUE CATEGORY MAPPING
# ==============================
# Map diverse issue types into broad categories
# so findings from different tools can be correlated.

CATEGORY_KEYWORDS = {
    "container-security": [
        "privileged", "root", "run_as", "security_context",
        "capability", "NET_RAW", "namespace",
    ],
    "image-hygiene": [
        "latest", "image tag", "digest", "image pull",
    ],
    "resource-limits": [
        "cpu", "memory", "limit", "request", "resource",
    ],
    "availability": [
        "liveness", "readiness", "probe", "health",
    ],
    "injection": [
        "sql", "injection", "command", "xss", "ssrf",
        "os.popen", "subprocess", "exec",
    ],
    "secrets": [
        "secret", "key", "password", "token", "credential",
        "hardcoded", "api_key",
    ],
    "crypto": [
        "md5", "sha1", "weak", "hash", "crypto", "tls",
    ],
    "dependency-vuln": [
        "cve", "CVE",
    ],
}


def classify_issue(finding):
    """Classify a finding into a broad category for correlation."""
    text = " ".join([
        str(finding.get("issue_type", "")),
        str(finding.get("evidence", "")),
        str(finding.get("id", "")),
    ]).lower()

    for category, keywords in CATEGORY_KEYWORDS.items():
        if any(kw.lower() in text for kw in keywords):
            return category

    return "other"


def correlation_key(finding):
    """
    Generate correlation key for grouping related findings.
    Uses asset + category so different tools can be matched.
    """
    category = classify_issue(finding)
    asset = finding.get("asset", "unknown")
    return (asset, category)


def correlate_findings(findings):
    groups = defaultdict(list)

    for f in findings:
        key = correlation_key(f)
        groups[key].append(f)

    merged = []

    for key, items in groups.items():
        if len(items) == 1:
            item = dict(items[0])
            item["metadata"] = item.get("metadata") or {}
            item["metadata"]["category"] = key[1]
            merged.append(item)
            continue

        # Pick the finding with the highest severity as base
        items.sort(key=lambda x: x.get("severity", 0), reverse=True)
        base = dict(items[0])

        tools = sorted({i["tool"] for i in items})
        all_ids = [i.get("id") for i in items if i.get("id")]

        base["metadata"] = base.get("metadata") or {}
        base["metadata"]["correlated_tools"] = tools
        base["metadata"]["correlated_ids"] = all_ids
        base["metadata"]["correlation_count"] = len(items)
        base["metadata"]["category"] = key[1]

        # Boost severity if multiple tools detected it (max 10)
        if len(tools) > 1:
            base["severity"] = min(base["severity"] + 1, 10)
            base["metadata"]["correlation_boost"] = True
        else:
            base["metadata"]["correlation_boost"] = False

        merged.append(base)

    return merged


def main():
    input_path = FINDINGS_DIR / "normalized_findings.json"

    if not input_path.exists():
        raise FileNotFoundError("normalized_findings.json not found")

    with open(input_path) as f:
        findings = json.load(f)

    print(f"\n📥 Original findings: {len(findings)}")

    correlated = correlate_findings(findings)

    output_path = FINDINGS_DIR / "correlated_findings.json"

    with open(output_path, "w") as f:
        json.dump(correlated, f, indent=2)

    reduction = len(findings) - len(correlated)
    boosted = sum(
        1 for c in correlated
        if c.get("metadata", {}).get("correlation_boost")
    )

    print(f"📤 After correlation: {len(correlated)}")
    print(f"🔗 Deduplicated: {reduction}")
    print(f"⬆️  Cross-tool boosted: {boosted}")
    print(f"\nSaved: {output_path}\n")


if __name__ == "__main__":
    main()
