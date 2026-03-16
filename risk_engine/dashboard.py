"""
Security Dashboard Generator
==============================
Generates a self-contained interactive HTML dashboard
from the risk report. No server required — opens in
any browser.
"""

import json
from pathlib import Path

FINDINGS_DIR = Path("findings")
REPORT_FILE = FINDINGS_DIR / "risk_report.json"
ML_FILE = FINDINGS_DIR / "ml_risk_predictions.json"
OUTPUT_FILE = FINDINGS_DIR / "security_dashboard.html"


def load_data():
    with open(REPORT_FILE) as f:
        report = json.load(f)

    ml_data = []
    if ML_FILE.exists():
        with open(ML_FILE) as f:
            ml_data = json.load(f)

    return report, ml_data


def generate_dashboard(report, ml_data):
    stats = report.get("statistics", {})
    findings = report.get("all_findings", [])
    assets = report.get("assets", [])
    generated = report.get("generated_at", "")

    # Serialize JSON directly into script tags — no HTML escaping needed
    # since it goes inside <script> not into HTML attributes
    findings_js = json.dumps(findings)
    assets_js = json.dumps(assets)
    ml_js = json.dumps(ml_data)
    stats_js = json.dumps(stats)

    # Build HTML with DATA embedded as JS variables
    html = []
    html.append("""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>DevSecOps Security Dashboard</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<style>
  @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Inter:wght@300;400;500;600;700&display=swap');
  * { margin: 0; padding: 0; box-sizing: border-box; }
  :root {
    --bg-primary: #0a0e1a; --bg-secondary: #111827; --bg-card: #1a2035;
    --bg-card-hover: #1f2847; --border: #2a3352;
    --text-primary: #e2e8f0; --text-secondary: #94a3b8; --text-muted: #64748b;
    --accent-blue: #3b82f6; --accent-cyan: #06b6d4;
    --critical: #ef4444; --high: #f97316; --medium: #eab308;
    --low: #3b82f6; --info: #6b7280; --success: #22c55e;
  }
  body { font-family: 'Inter', -apple-system, sans-serif; background: var(--bg-primary); color: var(--text-primary); min-height: 100vh; }
  .header { background: linear-gradient(135deg, var(--bg-secondary) 0%, #0f172a 100%); border-bottom: 1px solid var(--border); padding: 1.5rem 2rem; display: flex; align-items: center; justify-content: space-between; position: sticky; top: 0; z-index: 100; }
  .header-left { display: flex; align-items: center; gap: 1rem; }
  .logo { width: 36px; height: 36px; background: linear-gradient(135deg, var(--accent-blue), var(--accent-cyan)); border-radius: 8px; display: flex; align-items: center; justify-content: center; font-size: 18px; }
  .header h1 { font-size: 1.2rem; font-weight: 700; letter-spacing: -0.02em; }
  .header h1 span { color: var(--accent-cyan); }
  .header-meta { font-size: 0.75rem; color: var(--text-muted); font-family: 'JetBrains Mono', monospace; }
  .container { max-width: 1400px; margin: 0 auto; padding: 1.5rem 2rem; }
  .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 1rem; margin-bottom: 1.5rem; }
  .stat-card { background: var(--bg-card); border: 1px solid var(--border); border-radius: 12px; padding: 1.2rem; transition: all 0.2s; }
  .stat-card:hover { background: var(--bg-card-hover); border-color: var(--accent-blue); box-shadow: 0 0 20px rgba(59,130,246,0.15); }
  .stat-card .label { font-size: 0.7rem; text-transform: uppercase; letter-spacing: 0.08em; color: var(--text-muted); margin-bottom: 0.5rem; font-weight: 600; }
  .stat-card .value { font-size: 1.8rem; font-weight: 700; font-family: 'JetBrains Mono', monospace; line-height: 1; }
  .stat-card .sub { font-size: 0.72rem; color: var(--text-secondary); margin-top: 0.4rem; }
  .stat-card.critical .value { color: var(--critical); }
  .stat-card.high .value { color: var(--high); }
  .stat-card.medium .value { color: var(--medium); }
  .stat-card.low .value { color: var(--low); }
  .stat-card.total .value { color: var(--accent-cyan); }
  .stat-card.score .value { color: var(--accent-blue); }
  .charts-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 1.25rem; margin-bottom: 1.5rem; }
  @media (max-width: 900px) { .charts-grid { grid-template-columns: 1fr; } }
  .chart-card { background: var(--bg-card); border: 1px solid var(--border); border-radius: 12px; padding: 1.25rem; }
  .chart-card h3 { font-size: 0.85rem; font-weight: 600; margin-bottom: 1rem; color: var(--text-secondary); text-transform: uppercase; letter-spacing: 0.04em; }
  .chart-container { position: relative; height: 260px; }
  .table-section { background: var(--bg-card); border: 1px solid var(--border); border-radius: 12px; overflow: hidden; margin-bottom: 1.5rem; }
  .table-header { padding: 1rem 1.25rem; display: flex; align-items: center; justify-content: space-between; border-bottom: 1px solid var(--border); }
  .table-header h3 { font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.04em; color: var(--text-secondary); }
  .filters { display: flex; gap: 0.5rem; }
  .filter-btn { padding: 0.35rem 0.75rem; border-radius: 6px; border: 1px solid var(--border); background: transparent; color: var(--text-secondary); font-size: 0.72rem; font-weight: 500; cursor: pointer; transition: all 0.15s; font-family: 'Inter', sans-serif; }
  .filter-btn:hover, .filter-btn.active { background: var(--accent-blue); color: white; border-color: var(--accent-blue); }
  table { width: 100%; border-collapse: collapse; }
  th { padding: 0.7rem 1rem; text-align: left; font-size: 0.68rem; text-transform: uppercase; letter-spacing: 0.06em; color: var(--text-muted); font-weight: 600; border-bottom: 1px solid var(--border); background: rgba(0,0,0,0.2); }
  td { padding: 0.65rem 1rem; font-size: 0.8rem; border-bottom: 1px solid rgba(42,51,82,0.5); vertical-align: middle; }
  tr:hover td { background: rgba(59,130,246,0.04); }
  .badge { display: inline-block; padding: 0.2rem 0.55rem; border-radius: 4px; font-size: 0.65rem; font-weight: 700; letter-spacing: 0.04em; font-family: 'JetBrains Mono', monospace; }
  .badge-critical { background: rgba(239,68,68,0.15); color: var(--critical); }
  .badge-high { background: rgba(249,115,22,0.15); color: var(--high); }
  .badge-medium { background: rgba(234,179,8,0.15); color: var(--medium); }
  .badge-low { background: rgba(59,130,246,0.15); color: var(--low); }
  .badge-info { background: rgba(107,114,128,0.15); color: var(--info); }
  .tool-badge { display: inline-block; padding: 0.15rem 0.5rem; border-radius: 4px; font-size: 0.68rem; font-weight: 500; font-family: 'JetBrains Mono', monospace; }
  .tool-semgrep { background: rgba(139,92,246,0.15); color: #a78bfa; }
  .tool-trivy { background: rgba(6,182,212,0.15); color: #22d3ee; }
  .tool-checkov { background: rgba(16,185,129,0.15); color: #34d399; }
  .score-bar { display: flex; align-items: center; gap: 0.5rem; }
  .score-bar-track { flex: 1; height: 6px; background: rgba(255,255,255,0.06); border-radius: 3px; overflow: hidden; min-width: 60px; }
  .score-bar-fill { height: 100%; border-radius: 3px; }
  .score-val { font-family: 'JetBrains Mono', monospace; font-size: 0.78rem; font-weight: 600; min-width: 40px; }
  .mono { font-family: 'JetBrains Mono', monospace; font-size: 0.75rem; }
  .text-truncate { max-width: 220px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  .explanation-row { display: none; }
  .explanation-row.visible { display: table-row; }
  .explanation-content { padding: 1rem; background: rgba(0,0,0,0.3); border-radius: 8px; margin: 0.5rem; }
  .explanation-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 0.75rem; }
  .explain-item { display: flex; justify-content: space-between; padding: 0.3rem 0; font-size: 0.75rem; border-bottom: 1px solid rgba(255,255,255,0.04); }
  .explain-item .ek { color: var(--text-muted); }
  .explain-item .ev { font-family: 'JetBrains Mono', monospace; color: var(--accent-cyan); }
  .gate-status { display: flex; align-items: center; gap: 0.5rem; padding: 0.4rem 1rem; border-radius: 8px; font-size: 0.78rem; font-weight: 600; }
  .gate-fail { background: rgba(239,68,68,0.12); border: 1px solid rgba(239,68,68,0.3); color: var(--critical); }
  .gate-pass { background: rgba(34,197,94,0.12); border: 1px solid rgba(34,197,94,0.3); color: var(--success); }
  .pulse { width: 8px; height: 8px; border-radius: 50%; animation: pulse 2s infinite; }
  .pulse-red { background: var(--critical); }
  .pulse-green { background: var(--success); }
  @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.4; } }
  .footer { text-align: center; padding: 2rem; color: var(--text-muted); font-size: 0.72rem; border-top: 1px solid var(--border); }
  .no-charts { display: flex; align-items: center; justify-content: center; height: 260px; color: var(--text-muted); font-style: italic; }
</style>
</head>
<body>
""")

    html.append(f"""
<div class="header">
  <div class="header-left">
    <div class="logo">&#x1f6e1;</div>
    <div>
      <h1>DevSec<span>Ops</span> Security Dashboard</h1>
      <div class="header-meta">Generated: {generated}</div>
    </div>
  </div>
  <div id="gateStatus"></div>
</div>

<div class="container">
  <div class="stats-grid" id="statsGrid"></div>

  <div class="charts-grid">
    <div class="chart-card">
      <h3>Risk Distribution</h3>
      <div class="chart-container" id="riskDistContainer"><canvas id="riskDistChart"></canvas></div>
    </div>
    <div class="chart-card">
      <h3>Findings by Tool &amp; Severity</h3>
      <div class="chart-container" id="toolContainer"><canvas id="toolChart"></canvas></div>
    </div>
    <div class="chart-card">
      <h3>Risk Score Breakdown (Top Findings)</h3>
      <div class="chart-container" id="breakdownContainer"><canvas id="breakdownChart"></canvas></div>
    </div>
    <div class="chart-card">
      <h3>ML Prediction vs Rule-Based Score</h3>
      <div class="chart-container" id="mlContainer"><canvas id="mlChart"></canvas></div>
    </div>
  </div>

  <div class="table-section">
    <div class="table-header">
      <h3>All Findings</h3>
      <div class="filters">
        <button class="filter-btn active" onclick="filterFindings('all')">All</button>
        <button class="filter-btn" onclick="filterFindings('CRITICAL')">Critical</button>
        <button class="filter-btn" onclick="filterFindings('HIGH')">High</button>
        <button class="filter-btn" onclick="filterFindings('MEDIUM')">Medium</button>
        <button class="filter-btn" onclick="filterFindings('LOW')">Low</button>
      </div>
    </div>
    <div style="overflow-x: auto;">
      <table>
        <thead>
          <tr>
            <th>Risk</th><th>Score</th><th>Tool</th><th>ID</th>
            <th>Issue</th><th>Asset</th><th>Stage</th><th>ML Prob</th>
          </tr>
        </thead>
        <tbody id="findingsBody"></tbody>
      </table>
    </div>
  </div>
</div>

<div class="footer">
  AI-Assisted DevSecOps Risk Assessment &mdash; MD Sohail Shaikh &mdash; Generated by automated security pipeline
</div>
""")

    # Embed data as proper JS variables inside a script block
    html.append("<script>\n")
    html.append(f"const findings = {findings_js};\n")
    html.append(f"const assets = {assets_js};\n")
    html.append(f"const mlData = {ml_js};\n")
    html.append(f"const stats = {stats_js};\n")
    html.append("""
// Build ML lookup
const mlLookup = {};
mlData.forEach(m => { mlLookup[m.id] = m; });

const COLORS = { CRITICAL: '#ef4444', HIGH: '#f97316', MEDIUM: '#eab308', LOW: '#3b82f6', INFO: '#6b7280' };

// Gate status
const gateEl = document.getElementById('gateStatus');
if (stats.critical_count > 0 || stats.max_risk >= 0.7) {
  gateEl.innerHTML = '<div class="gate-status gate-fail"><div class="pulse pulse-red"></div>GATE FAILED</div>';
} else {
  gateEl.innerHTML = '<div class="gate-status gate-pass"><div class="pulse pulse-green"></div>GATE PASSED</div>';
}

// Stat cards
const grid = document.getElementById('statsGrid');
const cards = [
  { label: 'Total Findings', value: stats.total_findings || 0, cls: 'total', sub: 'Avg: ' + (stats.avg_risk || 0) },
  { label: 'Max Risk Score', value: stats.max_risk || 0, cls: 'score', sub: 'Highest single finding' },
  { label: 'Critical', value: stats.critical_count || 0, cls: 'critical', sub: 'Zero tolerance' },
  { label: 'High', value: stats.high_count || 0, cls: 'high', sub: 'Score >= 0.55' },
  { label: 'Medium', value: stats.medium_count || 0, cls: 'medium', sub: 'Score >= 0.35' },
  { label: 'Low', value: stats.low_count || 0, cls: 'low', sub: 'Score < 0.35' },
];
cards.forEach(c => {
  grid.innerHTML += '<div class="stat-card ' + c.cls + '">' +
    '<div class="label">' + c.label + '</div>' +
    '<div class="value">' + c.value + '</div>' +
    '<div class="sub">' + c.sub + '</div></div>';
});

// Charts — only render if Chart.js loaded
function renderCharts() {
  if (typeof Chart === 'undefined') {
    document.querySelectorAll('.chart-container').forEach(el => {
      el.innerHTML = '<div class="no-charts">Charts require internet (Chart.js CDN)</div>';
    });
    return;
  }

  // Risk Distribution Doughnut
  const riskBuckets = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
  findings.forEach(f => { riskBuckets[f.risk_label || 'LOW']++; });
  new Chart(document.getElementById('riskDistChart'), {
    type: 'doughnut',
    data: {
      labels: Object.keys(riskBuckets),
      datasets: [{ data: Object.values(riskBuckets), backgroundColor: Object.keys(riskBuckets).map(k => COLORS[k]), borderWidth: 0, hoverOffset: 8 }]
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      plugins: { legend: { position: 'right', labels: { color: '#94a3b8', font: { size: 11 } } } },
      cutout: '55%'
    }
  });

  // Tool + Severity Stacked Bar
  const toolSev = {};
  findings.forEach(f => {
    const t = f.tool || 'unknown';
    if (!toolSev[t]) toolSev[t] = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
    toolSev[t][f.risk_label || 'LOW']++;
  });
  const toolLabels = Object.keys(toolSev);
  const sevOrder = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
  new Chart(document.getElementById('toolChart'), {
    type: 'bar',
    data: {
      labels: toolLabels,
      datasets: sevOrder.map(s => ({
        label: s, data: toolLabels.map(t => toolSev[t][s] || 0), backgroundColor: COLORS[s],
      }))
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      scales: {
        x: { stacked: true, ticks: { color: '#94a3b8' }, grid: { display: false } },
        y: { stacked: true, ticks: { color: '#94a3b8', stepSize: 1 }, grid: { color: 'rgba(255,255,255,0.04)' } }
      },
      plugins: { legend: { labels: { color: '#94a3b8', font: { size: 10 } } } }
    }
  });

  // Score Breakdown Horizontal Bar
  const topN = findings.slice(0, 8);
  const bLabels = topN.map(f => f.id || 'unknown');
  const wKeys = ['severity', 'exposure', 'criticality', 'confidence', 'freshness'];
  const wColors = ['#ef4444', '#f97316', '#eab308', '#3b82f6', '#8b5cf6'];
  new Chart(document.getElementById('breakdownChart'), {
    type: 'bar',
    data: {
      labels: bLabels,
      datasets: wKeys.map((k, i) => ({
        label: k.charAt(0).toUpperCase() + k.slice(1),
        data: topN.map(f => (f.explanation && f.explanation.score_breakdown && f.explanation.score_breakdown[k]) || 0),
        backgroundColor: wColors[i],
      }))
    },
    options: {
      indexAxis: 'y', responsive: true, maintainAspectRatio: false,
      scales: {
        x: { stacked: true, ticks: { color: '#94a3b8' }, grid: { color: 'rgba(255,255,255,0.04)' } },
        y: { stacked: true, ticks: { color: '#94a3b8', font: { size: 9 } }, grid: { display: false } }
      },
      plugins: { legend: { labels: { color: '#94a3b8', font: { size: 10 } } } }
    }
  });

  // ML vs Rule Scatter
  const mlFindings = findings.filter(f => mlLookup[f.id]);
  new Chart(document.getElementById('mlChart'), {
    type: 'scatter',
    data: {
      datasets: [{
        label: 'Findings',
        data: mlFindings.map(f => ({ x: f.risk_score, y: mlLookup[f.id] ? mlLookup[f.id].ml_risk_probability : 0 })),
        backgroundColor: mlFindings.map(f => COLORS[f.risk_label] || '#6b7280'),
        pointRadius: 8, pointHoverRadius: 12,
      }, {
        label: 'Perfect correlation',
        data: [{ x: 0, y: 0 }, { x: 1, y: 1 }],
        type: 'line', borderColor: 'rgba(255,255,255,0.15)', borderDash: [6, 4], pointRadius: 0,
      }]
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      scales: {
        x: { title: { display: true, text: 'Rule-Based Score', color: '#94a3b8' }, ticks: { color: '#94a3b8' }, min: 0, max: 1, grid: { color: 'rgba(255,255,255,0.04)' } },
        y: { title: { display: true, text: 'ML Probability', color: '#94a3b8' }, ticks: { color: '#94a3b8' }, min: 0, max: 1, grid: { color: 'rgba(255,255,255,0.04)' } }
      },
      plugins: { legend: { display: false } }
    }
  });
}

// Table rendering
function getBarColor(score) {
  if (score >= 0.75) return COLORS.CRITICAL;
  if (score >= 0.55) return COLORS.HIGH;
  if (score >= 0.35) return COLORS.MEDIUM;
  return COLORS.LOW;
}

function renderTable(filter) {
  const tbody = document.getElementById('findingsBody');
  const filtered = filter === 'all' ? findings : findings.filter(f => f.risk_label === filter);

  tbody.innerHTML = filtered.map((f, i) => {
    const ml = mlLookup[f.id];
    const mlProb = ml ? ml.ml_risk_probability : null;
    const barColor = getBarColor(f.risk_score);
    const pct = Math.round(f.risk_score * 100);
    const toolClass = 'tool-' + (f.tool || 'unknown');
    const badgeClass = 'badge-' + (f.risk_label || 'low').toLowerCase();

    let row = '<tr style="cursor:pointer" onclick="toggleExplanation(' + i + ')">';
    row += '<td><span class="badge ' + badgeClass + '">' + (f.risk_label || 'LOW') + '</span></td>';
    row += '<td><div class="score-bar"><span class="score-val" style="color:' + barColor + '">' + f.risk_score + '</span>';
    row += '<div class="score-bar-track"><div class="score-bar-fill" style="width:' + pct + '%;background:' + barColor + '"></div></div></div></td>';
    row += '<td><span class="tool-badge ' + toolClass + '">' + (f.tool || '') + '</span></td>';
    row += '<td class="mono">' + (f.id || '') + '</td>';
    row += '<td class="text-truncate">' + (f.issue_type || '') + '</td>';
    row += '<td class="mono text-truncate">' + (f.asset || '') + '</td>';
    row += '<td>' + (f.stage || '') + '</td>';
    row += '<td class="mono">' + (mlProb !== null ? mlProb.toFixed(2) : '—') + '</td>';
    row += '</tr>';

    // Explanation row
    row += '<tr class="explanation-row" id="explain-' + i + '"><td colspan="8"><div class="explanation-content">';
    row += '<div style="font-size:0.75rem;font-weight:600;margin-bottom:0.5rem;color:var(--accent-cyan)">Score Explanation</div>';
    row += '<div class="explanation-grid">';
    if (f.explanation && f.explanation.score_breakdown) {
      Object.entries(f.explanation.score_breakdown).forEach(([k, v]) => {
        const w = f.explanation.weights ? f.explanation.weights[k] : '?';
        row += '<div class="explain-item"><span class="ek">' + k + '</span><span class="ev">' + v + ' (weight: ' + w + ')</span></div>';
      });
    }
    if (f.explanation && f.explanation.feature_values) {
      Object.entries(f.explanation.feature_values).forEach(([k, v]) => {
        row += '<div class="explain-item"><span class="ek">' + k + '</span><span class="ev">' + v + '</span></div>';
      });
    }
    row += '</div></div></td></tr>';
    return row;
  }).join('');
}

function toggleExplanation(i) {
  const el = document.getElementById('explain-' + i);
  if (el) el.classList.toggle('visible');
}

function filterFindings(filter) {
  document.querySelectorAll('.filter-btn').forEach(b => {
    b.classList.remove('active');
    if (b.textContent.trim().toUpperCase() === filter || (filter === 'all' && b.textContent.trim() === 'All')) {
      b.classList.add('active');
    }
  });
  renderTable(filter);
}

// Initialize
renderTable('all');

// Render charts after page load (gives Chart.js time to load from CDN)
window.addEventListener('load', renderCharts);
</script>
</body>
</html>""")

    return "\n".join(html)


def main():
    print("\n🎨 Generating interactive security dashboard...\n")

    report, ml_data = load_data()
    html_content = generate_dashboard(report, ml_data)

    with open(OUTPUT_FILE, "w") as f:
        f.write(html_content)

    print(f"✅ Dashboard saved to {OUTPUT_FILE}")
    print(f"   Open in browser to view\n")


if __name__ == "__main__":
    main()
