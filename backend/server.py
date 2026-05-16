# ============================================================
# DLP WEB SERVER
# Run from project root:  python backend/server.py
# ============================================================

import os
import sys
import threading
import webbrowser
import time
from queue import Queue, Empty

# Resolve paths relative to project root (parent of backend/)
BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(BACKEND_DIR)
FRONTEND_DIR = os.path.join(PROJECT_DIR, "frontend")

# Set working directory to project root so config.json / dlp.key / dlp.db are found
os.chdir(PROJECT_DIR)
sys.path.insert(0, BACKEND_DIR)

from flask import Flask, jsonify, request, send_from_directory
from flask_socketio import SocketIO, emit

from dlp_engine import DB, DLPEngine, CONFIG, CONFIG_FILE
from windows_log_monitor import WindowsLogMonitor
from activity_monitor import ActivityMonitor
from firewall_monitor import FirewallMonitor
from clipboard_monitor import ClipboardMonitor

app = Flask(__name__, static_folder=FRONTEND_DIR, static_url_path="")
app.config["SECRET_KEY"] = os.urandom(24)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading", logger=False, engineio_logger=False)

_event_queue = Queue()
_db = None
_engine = None

# ============================================================
# BROADCASTER — reads from queue and emits to all clients
# ============================================================

def _broadcaster():
    while True:
        try:
            event = _event_queue.get(timeout=1)
            socketio.emit("dlp_event", event)
            socketio.emit("stats_update", _db.stats())  # send AFTER event row is visible
        except Empty:
            continue

# ============================================================
# ROUTES — static
# ============================================================

@app.route("/")
def index():
    return send_from_directory(FRONTEND_DIR, "index.html")

# ============================================================
# API
# ============================================================

@app.route("/api/logs")
def api_logs():
    limit    = min(int(request.args.get("limit", 500)), 2000)
    action   = request.args.get("action", None)
    since_id = int(request.args.get("since_id", 0))
    rows = _db.recent(limit=limit, action=action, since_id=since_id)
    return jsonify([
        {
            "id":      r[0],
            "time":    r[1],
            "type":    r[2],
            "action":  r[3],
            "source":  r[4],
            "details": r[5] or "",
        }
        for r in rows
    ])


@app.route("/api/stats")
def api_stats():
    return jsonify(_db.stats())


@app.route("/api/config", methods=["GET"])
def api_config():
    return jsonify({k: v for k, v in CONFIG.items()})


@app.route("/api/config", methods=["POST"])
def api_config_save():
    import json as _json
    try:
        data = request.get_json(force=True) or {}
        allowed = {"watch_paths", "quarantine_path", "keywords", "trusted_ips"}
        for k, v in data.items():
            if k in allowed:
                CONFIG[k] = v
        with open(CONFIG_FILE, "w") as f:
            _json.dump(CONFIG, f, indent=2)
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/status")
def api_status():
    return jsonify({"status": "running", "watching": CONFIG["watch_paths"]})

# ============================================================
# SOCKET EVENTS
# ============================================================

@socketio.on("connect")
def on_connect():
    if _db is not None:
        emit("stats_update", _db.stats())

# ============================================================
# MAIN
# ============================================================

def _open_browser():
    time.sleep(1.8)
    webbrowser.open("http://localhost:5000")


if __name__ == "__main__":
    print("=" * 55)
    print("  Enterprise DLP System — Web Dashboard")
    print("=" * 55)

    _db = DB()

    def _on_event(event):
        _event_queue.put(event)  # broadcaster emits dlp_event then stats_update

    _engine    = DLPEngine(db=_db, event_callback=_on_event)
    _winlog    = WindowsLogMonitor(db=_db, event_callback=_on_event)
    _activity  = ActivityMonitor(db=_db, event_callback=_on_event)
    _firewall  = FirewallMonitor(db=_db, event_callback=_on_event)
    _clipboard = ClipboardMonitor(db=_db, event_callback=_on_event)

    threading.Thread(target=_engine.start,    daemon=True).start()
    threading.Thread(target=_winlog.start,    daemon=True).start()
    threading.Thread(target=_activity.start,  daemon=True).start()
    threading.Thread(target=_firewall.start,  daemon=True).start()
    threading.Thread(target=_clipboard.start, daemon=True).start()
    threading.Thread(target=_broadcaster,     daemon=True).start()
    threading.Thread(target=_open_browser,    daemon=True).start()

    print(f"  Dashboard : http://localhost:5000")
    print(f"  Files     : {CONFIG['watch_paths']}")
    print(f"  Win Logs  : Security, System, PowerShell, Defender")
    print(f"  Activity  : Browser history, Processes, Network")
    print(f"  Firewall  : Packet log, port scans, C2 detection, rule changes")
    print(f"  Email     : Clipboard scan, compose window detection")
    print(f"  Database  : {CONFIG['db']}")
    print("  Press Ctrl+C to stop\n")

    try:
        socketio.run(app, host="0.0.0.0", port=5000, debug=False, use_reloader=False, allow_unsafe_werkzeug=True)
    except KeyboardInterrupt:
        print("\nShutting down...")
        _engine.stop()
        _winlog.stop()
        _activity.stop()
        _firewall.stop()
        _clipboard.stop()
