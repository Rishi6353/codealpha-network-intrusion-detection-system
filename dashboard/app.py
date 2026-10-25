
import json
from collections import Counter
from datetime import datetime
from pathlib import Path

from flask import Flask, render_template_string, jsonify

app = Flask(__name__)

PROJECT_DIR = Path(__file__).resolve().parent.parent
EVE_LOG = PROJECT_DIR / "logs" / "eve.json"

HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>NetGuard | Network Intrusion Detection</title>
<script src="https://cdn.plot.ly/plotly-3.0.1.min.js"></script>
<style>
:root {
    color-scheme: dark;
    --bg: #0b1120;
    --panel: #111c30;
    --border: #263750;
    --muted: #93a4bd;
    --text: #e8eef8;
    --cyan: #38bdf8;
    --red: #fb7185;
}
* { box-sizing: border-box; }
body {
    margin: 0;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    background: var(--bg);
    color: var(--text);
}
header {
    padding: 24px 5%;
    background: #111827;
    border-bottom: 1px solid var(--border);
}
.brand { font-size: 25px; font-weight: 750; }
.brand span { color: var(--cyan); }
.subtitle { margin-top: 7px; color: var(--muted); font-size: 13px; }
main { max-width: 1450px; margin: auto; padding: 26px 5%; }
.section-title { font-size: 18px; margin: 0 0 16px; }
.status {
    display: inline-block; padding: 6px 10px; border-radius: 20px;
    color: #86efac; background: #123426; font-size: 12px; margin-top: 15px;
}
.cards {
    display: grid; grid-template-columns: repeat(4, minmax(0, 1fr));
    gap: 16px; margin-bottom: 28px;
}
.card, .panel {
    background: var(--panel); border: 1px solid var(--border);
    border-radius: 14px; padding: 20px;
}
.card-label { color: var(--muted); font-size: 13px; }
.card-value { font-size: 30px; font-weight: 750; margin-top: 12px; }
.card-note { color: var(--muted); font-size: 12px; margin-top: 7px; }
.charts {
    display: grid; grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 16px; margin-bottom: 28px;
}
.panel { min-width: 0; margin-bottom: 0; }
.panel h2 { font-size: 16px; margin: 0 0 12px; }
.chart { height: 290px; width: 100%; }
.table-wrap { overflow-x: auto; }
table { width: 100%; border-collapse: collapse; font-size: 13px; }
th, td {
    padding: 12px 10px; border-bottom: 1px solid var(--border);
    text-align: left; white-space: nowrap;
}
th { color: var(--muted); font-weight: 600; }
.severity { color: var(--red); font-weight: 700; }
.empty { color: var(--muted); padding: 22px 0; }
.footer { color: var(--muted); font-size: 12px; margin-top: 22px; }
.toolbar { display:flex; align-items:center; justify-content:space-between; gap:12px; margin-bottom:18px; }
button {
    color:var(--text); background:#1e3551; border:1px solid #35516f;
    border-radius:8px; padding:9px 13px; cursor:pointer;
}
@media(max-width:850px) {
    .cards { grid-template-columns: repeat(2, minmax(0, 1fr)); }
    .charts { grid-template-columns: 1fr; }
}
@media(max-width:480px) {
    main { padding: 20px 4%; }
    .cards { gap:10px; }
    .card { padding:14px; }
    .card-value { font-size:24px; }
}
</style>
</head>
<body>
<header>
    <div class="brand"><span>Net</span>Guard</div>
    <div class="subtitle">NETWORK INTRUSION DETECTION SYSTEM · SURICATA TELEMETRY</div>
    <div class="status">● Dashboard online</div>
</header>
<main>
    <div class="toolbar">
        <div>
            <h1 class="section-title">Network overview</h1>
            <div class="subtitle">Metrics from your local Suricata EVE JSON log</div>
        </div>
        <button onclick="loadDashboard()">Refresh data</button>
    </div>

    <section class="cards">
        <div class="card">
            <div class="card-label">Total Events</div>
            <div class="card-value" id="total">—</div>
            <div class="card-note">Valid log records</div>
        </div>
        <div class="card">
            <div class="card-label">Alerts</div>
            <div class="card-value" id="alerts">—</div>
            <div class="card-note">Suricata rule matches</div>
        </div>
        <div class="card">
            <div class="card-label">Unique Source IPs</div>
            <div class="card-value" id="sources">—</div>
            <div class="card-note">Across recorded events</div>
        </div>
        <div class="card">
            <div class="card-label">Event Types</div>
            <div class="card-value" id="types">—</div>
            <div class="card-note">Distinct event categories</div>
        </div>
    </section>

    <section class="charts">
        <div class="panel">
            <h2>Events by type</h2>
            <div id="eventChart" class="chart"></div>
        </div>
        <div class="panel">
            <h2>Alerts by severity</h2>
            <div id="severityChart" class="chart"></div>
        </div>
        <div class="panel">
            <h2>Event activity over time</h2>
            <div id="timelineChart" class="chart"></div>
        </div>
        <div class="panel">
            <h2>Top source IPs</h2>
            <div id="sourceChart" class="chart"></div>
        </div>
    </section>

    <section class="panel">
        <h2>Recent alerts</h2>
        <div class="table-wrap">
            <table>
                <thead>
                    <tr>
                        <th>Timestamp</th><th>Severity</th><th>Signature</th>
                        <th>Source</th><th>Destination</th><th>Protocol</th>
                    </tr>
                </thead>
                <tbody id="alertRows"></tbody>
            </table>
        </div>
        <div id="noAlerts" class="empty" style="display:none">
            No alert events found in the current log.
        </div>
    </section>
    <div id="lastUpdated" class="footer"></div>
</main>
<script>
const layoutBase = {
    paper_bgcolor: 'rgba(0,0,0,0)',
    plot_bgcolor: 'rgba(0,0,0,0)',
    font: {color: '#cbd5e1'},
    margin: {t: 12, r: 15, b: 45, l: 45},
    xaxis: {gridcolor: '#263750'},
    yaxis: {gridcolor: '#263750'}
};
const plotConfig = {responsive: true, displayModeBar: false};

async function loadDashboard() {
    try {
        const response = await fetch('/api/data');
        const data = await response.json();
        if (!response.ok) throw new Error(data.error || 'Could not load data');

        document.getElementById('total').textContent = data.total_events;
        document.getElementById('alerts').textContent = data.alert_count;
        document.getElementById('sources').textContent = data.unique_sources;
        document.getElementById('types').textContent = Object.keys(data.event_counts).length;
        document.getElementById('lastUpdated').textContent =
            'Last refreshed: ' + new Date().toLocaleString() +
            ' · Auto-refresh every 10 seconds';

        Plotly.react('eventChart', [{
            type:'bar', x:Object.keys(data.event_counts),
            y:Object.values(data.event_counts),
            marker:{color:'#38bdf8'}
        }], {...layoutBase, margin:{t:12,r:10,b:70,l:45}}, plotConfig);

        const severityLabels = Object.keys(data.severity_counts).sort();
        Plotly.react('severityChart', [{
            type:'bar', x:severityLabels,
            y:severityLabels.map(k => data.severity_counts[k]),
            marker:{color:'#fb7185'}
        }], {...layoutBase, xaxis:{...layoutBase.xaxis, title:'Severity (1 = highest)'}}, plotConfig);

        Plotly.react('timelineChart', [{
            type:'scatter', mode:'lines+markers',
            x:data.timeline.map(p => p.time), y:data.timeline.map(p => p.count),
            line:{color:'#a78bfa', width:2}, marker:{size:5}
        }], {...layoutBase, xaxis:{...layoutBase.xaxis, title:'Time'},
             yaxis:{...layoutBase.yaxis, title:'Events'}}, plotConfig);

        Plotly.react('sourceChart', [{
            type:'bar', orientation:'h',
            x:data.top_sources.map(p => p.count),
            y:data.top_sources.map(p => p.ip),
            marker:{color:'#34d399'}
        }], {...layoutBase, margin:{t:12,r:15,b:40,l:120},
             xaxis:{...layoutBase.xaxis, title:'Events'},
             yaxis:{...layoutBase.yaxis, autorange:'reversed'}}, plotConfig);

        const tbody = document.getElementById('alertRows');
        tbody.replaceChildren();
        document.getElementById('noAlerts').style.display =
            data.recent_alerts.length ? 'none' : 'block';

        for (const alert of data.recent_alerts) {
            const row = document.createElement('tr');
            const values = [
                alert.timestamp, alert.severity, alert.signature,
                alert.src_ip, alert.dest_ip, alert.proto
            ];
            values.forEach((value, index) => {
                const cell = document.createElement('td');
                cell.textContent = value ?? '—';
                if (index === 1) cell.className = 'severity';
                row.appendChild(cell);
            });
            tbody.appendChild(row);
        }
    } catch (error) {
        document.getElementById('lastUpdated').textContent =
            'Dashboard data error: ' + error.message;
    }
}
loadDashboard();
setInterval(loadDashboard, 10000);
</script>
</body>
</html>
"""


def read_events():
    events = []
    if not EVE_LOG.exists():
        return events

    try:
        with EVE_LOG.open("r", encoding="utf-8") as log_file:
            for line in log_file:
                try:
                    event = json.loads(line)
                    if isinstance(event, dict):
                        events.append(event)
                except json.JSONDecodeError:
                    continue
    except OSError as exc:
        app.logger.warning("Unable to read EVE log: %s", exc)

    return events


def build_dashboard_data(events):
    event_counts = Counter(
        event.get("event_type", "unknown") for event in events
    )
    alerts = [
        event for event in events if event.get("event_type") == "alert"
    ]

    sources = Counter(
        event["src_ip"] for event in events if event.get("src_ip")
    )
    severities = Counter()
    timeline = Counter()

    for event in events:
        if event.get("event_type") == "alert":
            severity = event.get("alert", {}).get("severity")
            if severity is not None:
                severities[str(severity)] += 1

        timestamp = event.get("timestamp")
        if timestamp:
            try:
                parsed = datetime.fromisoformat(
                    timestamp.replace("Z", "+00:00")
                )
                timeline[parsed.strftime("%Y-%m-%d %H:%M")] += 1
            except ValueError:
                continue

    recent_alerts = []
    for event in reversed(alerts[-20:]):
        alert_info = event.get("alert") or {}
        recent_alerts.append({
            "timestamp": event.get("timestamp", "—"),
            "severity": alert_info.get("severity", "—"),
            "signature": alert_info.get("signature", "Unknown alert"),
            "src_ip": event.get("src_ip", "—"),
            "dest_ip": event.get("dest_ip", "—"),
            "proto": event.get("proto", "—"),
        })

    return {
        "total_events": len(events),
        "alert_count": len(alerts),
        "unique_sources": len(sources),
        "event_counts": dict(sorted(event_counts.items())),
        "severity_counts": dict(severities),
        "timeline": [
            {"time": key, "count": value}
            for key, value in sorted(timeline.items())[-60:]
        ],
        "top_sources": [
            {"ip": ip, "count": count}
            for ip, count in sources.most_common(10)
        ],
        "recent_alerts": recent_alerts,
    }


@app.route("/")
def index():
    return render_template_string(HTML)


@app.route("/api/data")
def api_data():
    return jsonify(build_dashboard_data(read_events()))


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5001, debug=False)
