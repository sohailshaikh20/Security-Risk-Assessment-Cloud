.PHONY: all scan normalize correlate score ml visualize dashboard sarif gate clean test

# =====================================================
# Full pipeline
# =====================================================

all: scan normalize correlate score ml visualize dashboard sarif gate

# =====================================================
# Security scanning
# =====================================================

scan:
	@echo "\n🔍 Running security scanners...\n"
	@mkdir -p findings
	semgrep --config=auto app/starbucks --json > findings/semgrep.json || true
	trivy fs --format json --output findings/trivy.json app/starbucks || true
	checkov -d app/starbucks --output json > findings/checkov.json || true
	checkov -d terraform --output json > findings/terraform_checkov.json || true
	@echo "\n✅ Scans complete\n"

# =====================================================
# Risk engine pipeline
# =====================================================

normalize:
	python risk_engine/normalize.py

correlate:
	python risk_engine/correlate.py

score:
	python risk_engine/score.py

ml:
	python risk_engine/ml_model.py

visualize:
	python risk_engine/visualize.py
	python risk_engine/trend_analysis.py

dashboard:
	python risk_engine/dashboard.py

sarif:
	python risk_engine/sarif_report.py

gate:
	python risk_engine/gate.py

# =====================================================
# Analysis only (skip scanning, use existing findings)
# =====================================================

analyze: normalize correlate score ml visualize dashboard sarif gate

# =====================================================
# Testing
# =====================================================

test:
	python -m pytest tests/ -v

# =====================================================
# Cleanup
# =====================================================

clean:
	rm -f findings/normalized_findings.json
	rm -f findings/correlated_findings.json
	rm -f findings/risk_report.json
	rm -f findings/risk_report.md
	rm -f findings/ml_risk_predictions.json
	rm -f findings/gate_result.json
	rm -f findings/security_dashboard.html
	rm -f findings/devsecops-results.sarif
	rm -f findings/*.png
	@echo "✅ Cleaned generated files"
