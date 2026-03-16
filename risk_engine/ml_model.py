"""
Machine Learning Risk Prediction
=================================
Trains a RandomForest classifier to predict high-risk
findings. Includes synthetic data augmentation when real
findings are insufficient, and an Isolation Forest fallback
for anomaly-based risk scoring.
"""

import json
import random
from pathlib import Path

import pandas as pd
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
from sklearn.preprocessing import LabelEncoder

FINDINGS_DIR = Path("findings")

INPUT_FILE = FINDINGS_DIR / "risk_report.json"
OUTPUT_FILE = FINDINGS_DIR / "ml_risk_predictions.json"

MIN_SAMPLES = 30
MIN_CLASSES = 2
RISK_THRESHOLD = 0.55


def load_data():
    if not INPUT_FILE.exists():
        raise FileNotFoundError("risk_report.json not found")

    with open(INPUT_FILE) as f:
        report = json.load(f)

    findings = report["all_findings"]
    rows = []

    for finding in findings:
        explanation = finding.get("explanation", {})
        features = explanation.get("feature_values", {})

        rows.append({
            "severity": features.get("severity_norm", 0),
            "confidence": features.get("confidence", 0),
            "freshness": features.get("freshness_norm", 0),
            "exposure": features.get("exposure", "unknown"),
            "criticality": features.get("criticality", "unknown"),
            "stage": features.get("stage", "unknown"),
            "risk_score": finding.get("risk_score", 0),
            "tool": finding.get("tool"),
            "id": finding.get("id"),
            "asset": finding.get("asset"),
            "risk_label": finding.get("risk_label", "LOW"),
        })

    return pd.DataFrame(rows)


def generate_synthetic_data(df):
    """
    Generate synthetic training samples to ensure the model
    can learn meaningful patterns. Augments real findings with
    varied severity/exposure/criticality combinations.
    """
    synthetic = []

    # Define templates for each risk profile
    profiles = [
        # Critical: high severity, internet-facing, prod
        {"severity": 0.9, "exposure": "internet", "criticality": "prod",
         "confidence": 0.85, "freshness": 1.0, "stage": "SAST",
         "tool": "semgrep", "risk_score": 0.85},
        {"severity": 0.7, "exposure": "internet", "criticality": "prod",
         "confidence": 0.80, "freshness": 0.8, "stage": "IaC",
         "tool": "checkov", "risk_score": 0.75},
        {"severity": 0.9, "exposure": "internet", "criticality": "prod",
         "confidence": 0.85, "freshness": 1.0, "stage": "SCA",
         "tool": "trivy", "risk_score": 0.82},

        # High: elevated severity, mixed exposure
        {"severity": 0.7, "exposure": "internet", "criticality": "staging",
         "confidence": 0.75, "freshness": 0.8, "stage": "SAST",
         "tool": "semgrep", "risk_score": 0.60},
        {"severity": 0.5, "exposure": "internet", "criticality": "prod",
         "confidence": 0.80, "freshness": 1.0, "stage": "SCA",
         "tool": "trivy", "risk_score": 0.58},

        # Medium: moderate severity, internal
        {"severity": 0.5, "exposure": "internal", "criticality": "staging",
         "confidence": 0.70, "freshness": 0.5, "stage": "SAST",
         "tool": "semgrep", "risk_score": 0.40},
        {"severity": 0.5, "exposure": "unknown", "criticality": "unknown",
         "confidence": 0.80, "freshness": 0.8, "stage": "IaC",
         "tool": "checkov", "risk_score": 0.38},

        # Low: minor issues, dev environments
        {"severity": 0.3, "exposure": "internal", "criticality": "dev",
         "confidence": 0.70, "freshness": 0.5, "stage": "SAST",
         "tool": "semgrep", "risk_score": 0.20},
        {"severity": 0.1, "exposure": "unknown", "criticality": "dev",
         "confidence": 0.80, "freshness": 0.2, "stage": "IaC",
         "tool": "checkov", "risk_score": 0.15},
        {"severity": 0.3, "exposure": "internal", "criticality": "dev",
         "confidence": 0.85, "freshness": 0.5, "stage": "SCA",
         "tool": "trivy", "risk_score": 0.22},
    ]

    random.seed(42)

    for profile in profiles:
        # Create 3–5 variations of each profile
        for _ in range(random.randint(3, 5)):
            row = dict(profile)
            # Add noise
            row["severity"] = max(0, min(1, row["severity"] + random.gauss(0, 0.05)))
            row["confidence"] = max(0, min(1, row["confidence"] + random.gauss(0, 0.03)))
            row["freshness"] = max(0, min(1, row["freshness"] + random.gauss(0, 0.05)))
            row["risk_score"] = max(0, min(1, row["risk_score"] + random.gauss(0, 0.05)))
            row["id"] = "synthetic"
            row["asset"] = "synthetic"
            row["risk_label"] = (
                "CRITICAL" if row["risk_score"] >= 0.75
                else "HIGH" if row["risk_score"] >= 0.55
                else "MEDIUM" if row["risk_score"] >= 0.35
                else "LOW"
            )
            synthetic.append(row)

    synth_df = pd.DataFrame(synthetic)
    combined = pd.concat([df, synth_df], ignore_index=True)

    print(f"   Real samples: {len(df)}")
    print(f"   Synthetic samples: {len(synth_df)}")
    print(f"   Total training set: {len(combined)}")

    return combined


def preprocess(df):
    """Encode categorical features for ML."""
    encoders = {}
    feature_cols = [
        "severity", "confidence", "freshness",
        "exposure", "criticality", "stage", "tool",
    ]

    # Preserve original values before encoding
    for col in ["exposure", "criticality", "stage", "tool"]:
        df[f"{col}_original"] = df[col].astype(str)
        le = LabelEncoder()
        df[col] = le.fit_transform(df[col].astype(str))
        encoders[col] = le

    return df, encoders, feature_cols


def create_target(df):
    df["high_risk"] = df["risk_score"].apply(
        lambda x: 1 if x >= RISK_THRESHOLD else 0
    )
    return df


def train_classifier(df, feature_cols):
    """Train RandomForest if we have enough diverse data."""
    X = df[feature_cols]
    y = df["high_risk"]

    unique_classes = y.nunique()

    if unique_classes < MIN_CLASSES:
        print("\n⚠️  Only one class in target — skipping classifier")
        return None, X

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.3, random_state=42, stratify=y
    )

    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=6,
        random_state=42,
        class_weight="balanced",
    )

    model.fit(X_train, y_train)

    predictions = model.predict(X_test)

    print("\n📊 RandomForest Classification Report\n")
    print(classification_report(y_test, predictions, zero_division=0))

    # Feature importance
    importances = dict(zip(feature_cols, model.feature_importances_))
    print("🔍 Feature Importance:")
    for feat, imp in sorted(
        importances.items(), key=lambda x: x[1], reverse=True
    ):
        bar = "█" * int(imp * 40)
        print(f"   {feat:15s} {imp:.3f} {bar}")

    return model, X


def run_isolation_forest(df, feature_cols):
    """Anomaly-based risk scoring as supplementary signal."""
    X = df[feature_cols]

    iso = IsolationForest(
        n_estimators=100,
        contamination=0.2,
        random_state=42,
    )

    iso.fit(X)

    # Anomaly score: lower = more anomalous
    raw_scores = iso.decision_function(X)

    # Normalize to 0–1 where 1 = most anomalous
    min_s, max_s = raw_scores.min(), raw_scores.max()
    if max_s > min_s:
        normalized = 1.0 - (raw_scores - min_s) / (max_s - min_s)
    else:
        normalized = [0.5] * len(raw_scores)

    df["anomaly_score"] = [round(float(s), 4) for s in normalized]

    return df


def predict(model, X, df):
    if model is None:
        print("⚠️  Using rule-based fallback for probabilities")
        df["ml_risk_probability"] = df["risk_score"]
        return df

    probs = model.predict_proba(X)

    if probs.shape[1] < 2:
        df["ml_risk_probability"] = df["risk_score"]
    else:
        df["ml_risk_probability"] = [
            round(float(p), 4) for p in probs[:, 1]
        ]

    return df


def save_results(df):
    # Only save real findings (not synthetic)
    real = df[df["id"] != "synthetic"].copy()

    # Restore original categorical values for readability
    for col in ["tool", "exposure", "criticality", "stage"]:
        orig_col = f"{col}_original"
        if orig_col in real.columns:
            real[col] = real[orig_col]

    output_cols = [
        "id", "asset", "tool", "risk_score", "risk_label",
        "severity", "confidence", "freshness",
        "high_risk", "ml_risk_probability", "anomaly_score",
    ]

    # Only include columns that exist
    cols = [c for c in output_cols if c in real.columns]
    results = real[cols].to_dict(orient="records")

    with open(OUTPUT_FILE, "w") as f:
        json.dump(results, f, indent=2)

    print(f"\n💾 Saved ML predictions to {OUTPUT_FILE}")
    print(f"   Predictions for {len(results)} real findings\n")


def main():
    print("\n🤖 Loading risk report...\n")

    df = load_data()

    if df.empty:
        print("⚠️  No findings to analyze")
        return

    # Augment with synthetic data for robust training
    print("📈 Augmenting training data...")
    df = generate_synthetic_data(df)

    df, encoders, feature_cols = preprocess(df)
    df = create_target(df)

    # Train supervised classifier
    model, X = train_classifier(df, feature_cols)

    # Run unsupervised anomaly detection
    df = run_isolation_forest(df, feature_cols)

    # Generate predictions
    df = predict(model, X, df)

    save_results(df)


if __name__ == "__main__":
    main()
