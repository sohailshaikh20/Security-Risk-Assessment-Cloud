"""
Security Visualization Engine
==============================
Generates publication-quality charts from the risk report.
"""

import json
from pathlib import Path

import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker

FINDINGS_DIR = Path("findings")
REPORT_FILE = FINDINGS_DIR / "risk_report.json"

# ==============================
# STYLE CONFIGURATION
# ==============================

COLORS = {
    "CRITICAL": "#DC2626",
    "HIGH": "#EA580C",
    "MEDIUM": "#F59E0B",
    "LOW": "#3B82F6",
    "INFO": "#6B7280",
}

TOOL_COLORS = {
    "semgrep": "#8B5CF6",
    "trivy": "#06B6D4",
    "checkov": "#10B981",
}

DPI = 150
FIGSIZE = (10, 6)

plt.rcParams.update({
    "font.family": "sans-serif",
    "font.size": 11,
    "axes.titlesize": 14,
    "axes.titleweight": "bold",
    "axes.grid": True,
    "grid.alpha": 0.3,
    "figure.facecolor": "white",
})


def load_data():
    with open(REPORT_FILE) as f:
        data = json.load(f)

    findings = data["all_findings"]

    if not findings:
        print("⚠️  No findings to visualize")
        return None

    df = pd.DataFrame(findings)
    return df


def plot_risk_distribution(df):
    """Histogram of risk scores with severity color zones."""
    fig, ax = plt.subplots(figsize=FIGSIZE)

    bins = [0, 0.15, 0.35, 0.55, 0.75, 1.0]
    labels = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    colors = [COLORS[l] for l in labels]

    counts, _, patches = ax.hist(
        df["risk_score"], bins=bins,
        edgecolor="white", linewidth=1.5,
    )

    for patch, color in zip(patches, colors):
        patch.set_facecolor(color)
        patch.set_alpha(0.85)

    # Add count labels on bars
    for patch, count in zip(patches, counts):
        if count > 0:
            ax.text(
                patch.get_x() + patch.get_width() / 2,
                count + 0.3,
                str(int(count)),
                ha="center", va="bottom",
                fontweight="bold", fontsize=12,
            )

    ax.set_title("Risk Score Distribution")
    ax.set_xlabel("Risk Score")
    ax.set_ylabel("Number of Findings")
    ax.set_xticks([0, 0.15, 0.35, 0.55, 0.75, 1.0])
    ax.yaxis.set_major_locator(ticker.MaxNLocator(integer=True))

    # Add severity zone labels
    for i, label in enumerate(labels):
        mid = (bins[i] + bins[i + 1]) / 2
        ax.text(
            mid, -0.08, label,
            ha="center", fontsize=8, color=colors[i],
            fontweight="bold",
            transform=ax.get_xaxis_transform(),
        )

    plt.tight_layout()
    plt.savefig(FINDINGS_DIR / "risk_distribution.png", dpi=DPI)
    plt.close()
    print("📊 Saved risk_distribution.png")


def plot_top_assets(df):
    """Horizontal bar chart of riskiest assets."""
    asset_risk = (
        df.groupby("asset")["risk_score"]
        .agg(["max", "mean", "count"])
        .sort_values("max", ascending=True)
        .tail(10)
    )

    fig, ax = plt.subplots(figsize=FIGSIZE)

    # Shorten long asset names
    labels = [
        a if len(a) <= 40 else "..." + a[-37:]
        for a in asset_risk.index
    ]

    bars = ax.barh(
        labels, asset_risk["max"],
        color=[
            COLORS.get(
                "CRITICAL" if v >= 0.75
                else "HIGH" if v >= 0.55
                else "MEDIUM" if v >= 0.35
                else "LOW",
                COLORS["INFO"]
            )
            for v in asset_risk["max"]
        ],
        edgecolor="white", linewidth=0.5,
    )

    # Add score labels
    for bar, (_, row) in zip(bars, asset_risk.iterrows()):
        ax.text(
            bar.get_width() + 0.01,
            bar.get_y() + bar.get_height() / 2,
            f'{row["max"]:.2f} ({int(row["count"])} findings)',
            va="center", fontsize=9,
        )

    ax.set_title("Top Risky Assets")
    ax.set_xlabel("Max Risk Score")
    ax.set_xlim(0, min(asset_risk["max"].max() + 0.15, 1.1))

    plt.tight_layout()
    plt.savefig(FINDINGS_DIR / "top_risky_assets.png", dpi=DPI)
    plt.close()
    print("📊 Saved top_risky_assets.png")


def plot_tool_contribution(df):
    """Stacked bar chart showing findings per tool by severity."""
    fig, ax = plt.subplots(figsize=FIGSIZE)

    # Get risk_label if available, otherwise derive it
    if "risk_label" not in df.columns:
        def label(s):
            if s >= 0.75:
                return "CRITICAL"
            if s >= 0.55:
                return "HIGH"
            if s >= 0.35:
                return "MEDIUM"
            return "LOW"
        df["risk_label"] = df["risk_score"].apply(label)

    tools = df["tool"].unique()
    severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

    pivot = pd.crosstab(df["tool"], df["risk_label"])

    # Ensure all severity columns exist
    for sev in severity_order:
        if sev not in pivot.columns:
            pivot[sev] = 0
    pivot = pivot[
        [s for s in severity_order if s in pivot.columns]
    ]

    pivot.plot(
        kind="bar", stacked=True, ax=ax,
        color=[COLORS.get(c, "#999") for c in pivot.columns],
        edgecolor="white", linewidth=0.5,
    )

    # Add total count labels
    for i, tool in enumerate(pivot.index):
        total = pivot.loc[tool].sum()
        ax.text(
            i, total + 0.3, str(int(total)),
            ha="center", fontweight="bold", fontsize=11,
        )

    ax.set_title("Findings by Security Tool (by Severity)")
    ax.set_ylabel("Number of Findings")
    ax.set_xlabel("")
    ax.set_xticklabels(ax.get_xticklabels(), rotation=0)
    ax.yaxis.set_major_locator(ticker.MaxNLocator(integer=True))
    ax.legend(title="Risk Level", loc="upper right")

    plt.tight_layout()
    plt.savefig(FINDINGS_DIR / "tool_contribution.png", dpi=DPI)
    plt.close()
    print("📊 Saved tool_contribution.png")


def plot_severity_pie(df):
    """Pie chart of finding severity distribution."""
    if "risk_label" not in df.columns:
        return

    counts = df["risk_label"].value_counts()

    fig, ax = plt.subplots(figsize=(8, 8))

    colors = [COLORS.get(label, "#999") for label in counts.index]

    wedges, texts, autotexts = ax.pie(
        counts.values,
        labels=counts.index,
        colors=colors,
        autopct="%1.0f%%",
        startangle=90,
        pctdistance=0.8,
        wedgeprops={"edgecolor": "white", "linewidth": 2},
    )

    for text in autotexts:
        text.set_fontweight("bold")
        text.set_fontsize(12)

    ax.set_title("Finding Severity Distribution")

    plt.tight_layout()
    plt.savefig(FINDINGS_DIR / "severity_breakdown.png", dpi=DPI)
    plt.close()
    print("📊 Saved severity_breakdown.png")


def main():
    df = load_data()

    if df is None:
        return

    plot_risk_distribution(df)
    plot_top_assets(df)
    plot_tool_contribution(df)
    plot_severity_pie(df)

    print("\n✅ All visualizations generated\n")


if __name__ == "__main__":
    main()
