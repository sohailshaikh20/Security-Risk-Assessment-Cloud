"""
Security Trend Analysis
========================
Tracks average risk score across pipeline runs and
generates a trend chart to show security posture over time.
"""

import json
import os
from pathlib import Path
from datetime import datetime, timezone

import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

FINDINGS_DIR = Path("findings")
RISK_REPORT = FINDINGS_DIR / "risk_report.json"
HISTORY_FILE = FINDINGS_DIR / "risk_history.json"

DPI = 150
FIGSIZE = (10, 5)


def load_current_risk():
    if not RISK_REPORT.exists():
        raise FileNotFoundError("risk_report.json not found")

    with open(RISK_REPORT) as f:
        data = json.load(f)

    scores = [f["risk_score"] for f in data["all_findings"]]

    if not scores:
        return 0.0, 0, 0.0

    avg_risk = round(sum(scores) / len(scores), 3)
    max_risk = round(max(scores), 3)

    return avg_risk, len(scores), max_risk


def load_history():
    if not HISTORY_FILE.exists():
        return []

    with open(HISTORY_FILE) as f:
        return json.load(f)


def save_history(history):
    with open(HISTORY_FILE, "w") as f:
        json.dump(history, f, indent=2)


def update_history(avg_risk, total_findings, max_risk):
    history = load_history()

    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "commit": os.getenv("GITHUB_SHA", "local")[:8],
        "run_number": os.getenv("GITHUB_RUN_NUMBER", str(len(history) + 1)),
        "avg_risk": avg_risk,
        "max_risk": max_risk,
        "total_findings": total_findings,
    }

    history.append(entry)
    save_history(history)

    return history


def generate_trend_plot(history):
    df = pd.DataFrame(history)

    if df.empty:
        print("⚠️  No history data to plot")
        return

    fig, ax = plt.subplots(figsize=FIGSIZE)

    x_labels = [
        f"#{h.get('run_number', i)}"
        for i, h in enumerate(history)
    ]

    ax.plot(
        x_labels, df["avg_risk"],
        marker="o", linewidth=2.5, markersize=8,
        color="#3B82F6", label="Avg Risk",
        zorder=3,
    )

    if "max_risk" in df.columns:
        ax.plot(
            x_labels, df["max_risk"],
            marker="s", linewidth=1.5, markersize=6,
            color="#EF4444", alpha=0.7, label="Max Risk",
            linestyle="--", zorder=2,
        )

    # Add threshold zones
    ax.axhspan(0.75, 1.0, alpha=0.08, color="#DC2626", label="Critical Zone")
    ax.axhspan(0.55, 0.75, alpha=0.06, color="#EA580C", label="High Zone")
    ax.axhline(y=0.55, color="#EA580C", linestyle=":", alpha=0.5)

    # Add value labels on points
    for i, row in df.iterrows():
        ax.annotate(
            f'{row["avg_risk"]:.3f}',
            (x_labels[i], row["avg_risk"]),
            textcoords="offset points",
            xytext=(0, 12), ha="center", fontsize=9,
        )

    ax.set_title("Security Risk Trend Across Pipeline Runs")
    ax.set_xlabel("Pipeline Run")
    ax.set_ylabel("Risk Score")
    ax.set_ylim(0, max(1.0, df["avg_risk"].max() + 0.1))
    ax.legend(loc="upper right", fontsize=9)
    ax.grid(True, alpha=0.3)

    # Handle single data point
    if len(df) == 1:
        ax.set_xlim(-0.5, 0.5)
        ax.annotate(
            "First pipeline run — trend will appear after more runs",
            xy=(0.5, 0.02), xycoords="axes fraction",
            fontsize=9, fontstyle="italic", color="#6B7280",
            ha="center",
        )

    plt.tight_layout()
    plt.savefig(FINDINGS_DIR / "security_trend.png", dpi=DPI)
    plt.close()
    print("📊 Saved security_trend.png")


def main():
    avg_risk, total_findings, max_risk = load_current_risk()

    print(f"\n📈 Current average risk: {avg_risk}")
    print(f"   Max risk: {max_risk}")
    print(f"   Total findings: {total_findings}")

    history = update_history(avg_risk, total_findings, max_risk)

    generate_trend_plot(history)

    print(f"   History entries: {len(history)}\n")


if __name__ == "__main__":
    main()
