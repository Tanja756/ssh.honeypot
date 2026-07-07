#!/usr/bin/env python3
"""
Web Dashboard for SSH Honeypot.

Usage:
    python3 dashboard.py [--host 127.0.0.1] [--port 5000] [--log honeypot.log]

Opens a browser-accessible dashboard showing real-time attack statistics
with a live credential stream via Server-Sent Events.
"""

from __future__ import annotations

import json
import os
import queue
import sys
import threading
import time
from collections import Counter, defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import flask

# ── In-memory stats ──────────────────────────────────────────────

_stats_lock = threading.Lock()


class Stats:
    def __init__(self) -> None:
        self.total_events = 0
        self.auth_attempts = 0
        self.unique_ips: set[str] = set()
        self.top_ips: Counter[str] = Counter()
        self.top_countries: Counter[str] = Counter()
        self.top_passwords: Counter[str] = Counter()
        self.top_credentials: Counter[str] = Counter()
        self.top_usernames: Counter[str] = Counter()
        self.attempts_per_hour: Counter[str] = Counter()
        self.recent_events: deque[dict[str, Any]] = deque(maxlen=200)
        self.active_sessions: set[str] = set()
        self._closed_sessions: set[str] = set()

    def ingest(self, record: dict[str, Any]) -> None:
        self.total_events += 1
        self.recent_events.append(record)

        event_type = record.get("event", "")
        if event_type == "auth_attempt":
            self.auth_attempts += 1
            src_ip = record.get("src_ip", "")
            if src_ip:
                self.top_ips[src_ip] += 1
                self.unique_ips.add(src_ip)

            username = record.get("username", "")
            password = record.get("password", "")
            if username:
                self.top_usernames[username] += 1
            if password and password not in ("<public_key>", "<keyboard-interactive>"):
                self.top_passwords[password] += 1
                if username:
                    cred = f"{username}:{password}"
                    self.top_credentials[cred] += 1

            country = record.get("country", "")
            if country:
                self.top_countries[country] += 1

            hour = record.get("timestamp", "")[:13]
            if hour:
                self.attempts_per_hour[hour] += 1

            session_id = record.get("session_id", "")
            if session_id:
                self.active_sessions.add(session_id)

        if event_type in ("connection_dropped", "connection_timeout", "connection_error"):
            session_id = record.get("session_id", "")
            if session_id and session_id in self.active_sessions:
                self.active_sessions.discard(session_id)
                self._closed_sessions.add(session_id)


_stats = Stats()

# ── Log file tailer ──────────────────────────────────────────────

_log_path: str = "honeypot.log"
_listeners: list[queue.Queue] = []
_tailer_started = False

def _tail_log() -> None:
    global _tailer_started
    if _tailer_started:
        return
    _tailer_started = True

    path = Path(_log_path)

    try:
        if path.exists():
            known_size = path.stat().st_size
        else:
            known_size = 0
    except OSError:
        known_size = 0

    while True:
        try:
            if not path.exists():
                time.sleep(1)
                continue

            st = path.stat()
            if st.st_size < known_size:
                known_size = 0
                continue
            if st.st_size == known_size:
                time.sleep(0.5)
                continue

            with open(path, "r", encoding="utf-8") as f:
                f.seek(known_size)
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        record: dict[str, Any] = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    with _stats_lock:
                        _stats.ingest(record)
                    _broadcast(record)

                known_size = f.tell()

        except OSError:
            time.sleep(1)

        time.sleep(0.5)


def _broadcast(record: dict[str, Any]) -> None:
    dead: list[queue.Queue] = []
    for q in _listeners:
        try:
            q.put_nowait(record)
        except queue.Full:
            dead.append(q)
    for q in dead:
        _listeners.remove(q)


# ── Flask app ────────────────────────────────────────────────────

app = flask.Flask(__name__)


@app.route("/")
def index() -> str:
    return INDEX_HTML


@app.route("/api/stats")
def api_stats() -> flask.Response:
    with _stats_lock:
        now = datetime.now(timezone.utc)
        current_hour = now.strftime("%Y-%m-%dT%H")

        attempts_last_hour = sum(
            v for k, v in _stats.attempts_per_hour.items()
            if k >= current_hour
        )

        data = {
            "total_events": _stats.total_events,
            "auth_attempts": _stats.auth_attempts,
            "unique_ips": len(_stats.unique_ips),
            "active_sessions": len(_stats.active_sessions),
            "attempts_last_hour": attempts_last_hour,
            "top_ips": _stats.top_ips.most_common(20),
            "top_countries": _stats.top_countries.most_common(20),
            "top_passwords": _stats.top_passwords.most_common(20),
            "top_usernames": _stats.top_usernames.most_common(20),
            "top_credentials": _stats.top_credentials.most_common(20),
            "attempts_per_hour": dict(
                sorted(_stats.attempts_per_hour.items())[-48:]
            ),
        }
    return flask.jsonify(data)


@app.route("/api/timeline")
def api_timeline() -> flask.Response:
    limit = flask.request.args.get("limit", 50, type=int)
    with _stats_lock:
        items = list(_stats.recent_events)[-limit:]
    return flask.jsonify(items)


@app.route("/api/events/stream")
def events_stream() -> flask.Response:
    q: queue.Queue = queue.Queue(maxsize=256)
    _listeners.append(q)

    def generate() -> Any:
        try:
            while True:
                record = q.get()
                yield f"data: {json.dumps(record, ensure_ascii=False)}\n\n"
        except GeneratorExit:
            if q in _listeners:
                _listeners.remove(q)

    return flask.Response(
        generate(),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


# ── CLI ──────────────────────────────────────────────────────────

def parse_args() -> tuple[str, int, str]:
    host = "127.0.0.1"
    port = 5000
    log = "honeypot.log"

    args = sys.argv[1:]
    i = 0
    while i < len(args):
        if args[i] == "--host" and i + 1 < len(args):
            host = args[i + 1]
            i += 2
        elif args[i] == "--port" and i + 1 < len(args):
            port = int(args[i + 1])
            i += 2
        elif args[i] == "--log" and i + 1 < len(args):
            log = args[i + 1]
            i += 2
        elif args[i] in ("--help", "-h"):
            print("Usage: python dashboard.py [--host HOST] [--port PORT] [--log LOG_FILE]")
            sys.exit(0)
        else:
            i += 1

    return host, port, log


def main() -> None:
    global _log_path
    host, port, _log_path = parse_args()

    tailer = threading.Thread(target=_tail_log, daemon=True)
    tailer.start()

    print(f"  [+] Dashboard: http://{host}:{port}")
    print(f"  [+] Tailing: {_log_path}")
    app.run(host=host, port=port, debug=False, use_reloader=False)


# ── Embedded HTML ────────────────────────────────────────────────

INDEX_HTML = """\
<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SSH Honeypot Dashboard</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, monospace; background: #0d1117; color: #c9d1d9; padding: 20px; }
  h1 { font-size: 1.5em; margin-bottom: 16px; color: #58a6ff; }
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 12px; margin-bottom: 16px; }
  .card { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 14px; }
  .card h2 { font-size: 0.85em; color: #8b949e; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 8px; }
  .stat-value { font-size: 1.8em; font-weight: 600; color: #f0f6fc; }
  table { width: 100%; border-collapse: collapse; font-size: 0.85em; }
  th, td { text-align: left; padding: 4px 6px; border-bottom: 1px solid #21262d; }
  th { color: #8b949e; font-weight: 500; }
  td { color: #c9d1d9; }
  .num { text-align: right; font-variant-numeric: tabular-nums; }
  .live { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 14px; margin-bottom: 16px; max-height: 300px; overflow-y: auto; font-size: 0.85em; }
  .live-entry { padding: 2px 0; display: flex; gap: 12px; }
  .live-time { color: #8b949e; white-space: nowrap; }
  .live-ip { color: #f0883e; }
  .live-cred { color: #7ee787; }
  .live-country { color: #8b949e; }
  .badge { display: inline-block; padding: 1px 6px; border-radius: 4px; font-size: 0.8em; }
  .badge-ok { background: #1b3a1b; color: #7ee787; }
  .badge-warn { background: #3a2a1b; color: #f0883e; }
  .live-bar { color: #58a6ff; }
  #attempts-chart { display: flex; align-items: flex-end; gap: 2px; height: 60px; margin-top: 8px; }
  #attempts-chart div { background: #1f6feb; min-width: 6px; border-radius: 2px 2px 0 0; flex: 1; }
</style>
</head>
<body>
<h1>SSH Honeypot Dashboard</h1>

<div class="grid">
  <div class="card">
    <h2>Auth Attempts</h2>
    <div class="stat-value" id="stat-attempts">0</div>
  </div>
  <div class="card">
    <h2>Unique IPs</h2>
    <div class="stat-value" id="stat-ips">0</div>
  </div>
  <div class="card">
    <h2>Active Connections</h2>
    <div class="stat-value" id="stat-active">0</div>
  </div>
  <div class="card">
    <h2>Attempts / hour</h2>
    <div class="stat-value" id="stat-hourly">0</div>
  </div>
</div>

<div class="grid">
  <div class="card">
    <h2>Top IPs</h2>
    <table><tbody id="top-ips"></tbody></table>
  </div>
  <div class="card">
    <h2>Top Countries</h2>
    <table><tbody id="top-countries"></tbody></table>
  </div>
  <div class="card">
    <h2>Top Passwords</h2>
    <table><tbody id="top-passwords"></tbody></table>
  </div>
  <div class="card">
    <h2>Top Credentials</h2>
    <table><tbody id="top-credentials"></tbody></table>
  </div>
</div>

<div class="card">
  <h2>Attempts Timeline</h2>
  <div id="attempts-chart"></div>
</div>

<div class="live" id="live-feed">
  <div style="color:#8b949e; margin-bottom:6px;">Live attack stream</div>
</div>

<script>
const STATS_INTERVAL = 5000;
const MAX_FEED = 100;

function escapeHtml(text) {
  const d = document.createElement('div');
  d.textContent = text;
  return d.innerHTML;
}

function fmtTime(ts) {
  if (!ts) return '';
  const d = new Date(ts);
  return d.toLocaleTimeString();
}

function renderTable(id, data, labelCol, valCol) {
  const tbody = document.getElementById(id);
  tbody.innerHTML = data.map(([label, val]) =>
    `<tr><td>${escapeHtml(label)}</td><td class="num">${val}</td></tr>`
  ).join('');
}

function updateStats(data) {
  document.getElementById('stat-attempts').textContent = data.auth_attempts;
  document.getElementById('stat-ips').textContent = data.unique_ips;
  document.getElementById('stat-active').textContent = data.active_sessions;
  document.getElementById('stat-hourly').textContent = data.attempts_last_hour;
  renderTable('top-ips', data.top_ips, 'IP', 'Attempts');
  renderTable('top-countries', data.top_countries, 'Country', 'Attempts');
  renderTable('top-passwords', data.top_passwords, 'Password', 'Count');
  renderTable('top-credentials', data.top_credentials, 'Credential', 'Count');

  const chart = document.getElementById('attempts-chart');
  const hours = Object.entries(data.attempts_per_hour);
  const maxVal = Math.max(1, ...hours.map(([,v]) => v));
  chart.innerHTML = hours.map(([h, v]) => {
    const pct = (v / maxVal * 100).toFixed(0);
    const label = h.slice(11, 16);
    return `<div style="height:${pct}%" title="${label} - ${v}"></div>`;
  }).join('');
}

async function fetchStats() {
  try {
    const r = await fetch('/api/stats');
    updateStats(await r.json());
  } catch (_) {}
}

function addLiveEntry(record) {
  const feed = document.getElementById('live-feed');
  const div = document.createElement('div');
  div.className = 'live-entry';

  const time = document.createElement('span');
  time.className = 'live-time';
  time.textContent = fmtTime(record.timestamp);
  div.appendChild(time);

  if (record.src_ip) {
    const ip = document.createElement('span');
    ip.className = 'live-ip';
    ip.textContent = record.src_ip;
    div.appendChild(ip);
  }

  if (record.username && record.password) {
    const cred = document.createElement('span');
    cred.className = 'live-cred';
    cred.textContent = `${record.username}/${record.password}`;
    div.appendChild(cred);
  }

  if (record.country) {
    const c = document.createElement('span');
    c.className = 'live-country';
    c.textContent = record.country;
    div.appendChild(c);
  }

  feed.appendChild(div);

  const entries = feed.children;
  while (entries.length > MAX_FEED + 1) {
    feed.removeChild(entries[1]);
  }
  feed.scrollTop = feed.scrollHeight;
}

// SSE live stream
const evtSource = new EventSource('/api/events/stream');
evtSource.onmessage = (e) => {
  try {
    const record = JSON.parse(e.data);
    addLiveEntry(record);
  } catch(_) {}
};

// Polling for stats
fetchStats();
setInterval(fetchStats, STATS_INTERVAL);
</script>
</body>
</html>
"""


if __name__ == "__main__":
    main()
