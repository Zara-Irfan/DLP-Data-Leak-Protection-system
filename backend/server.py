# ============================================================
# DLP WEB SERVER
# Run from project root:  python backend/server.py
# ============================================================

import os
import sys
import threading
import webbrowser
import time
from datetime import datetime, timedelta
from queue import Queue, Empty

# Resolve paths relative to project root (parent of backend/)
BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(BACKEND_DIR)
FRONTEND_DIR = os.path.join(PROJECT_DIR, "frontend")

# Set working directory to project root so config.json / dlp.key / dlp.db are found
os.chdir(PROJECT_DIR)
sys.path.insert(0, BACKEND_DIR)

# Load .env if present
from dotenv import load_dotenv
load_dotenv(os.path.join(PROJECT_DIR, ".env"))

from flask import (Flask, jsonify, request, send_from_directory,
                   session, redirect, url_for)
from flask_socketio import SocketIO, emit

from dlp_engine import DB, DLPEngine, CONFIG, CONFIG_FILE
from windows_log_monitor import WindowsLogMonitor
from activity_monitor import ActivityMonitor
from firewall_monitor import FirewallMonitor
from clipboard_monitor import ClipboardMonitor
from auth import (init_auth, is_user_subscribed, trial_days_left,
                  oauth, STRIPE_PUB_KEY, STRIPE_PRICE_ID,
                  STRIPE_WEBHOOK_SEC, GOOGLE_CLIENT_ID)
import stripe as _stripe

# ── Persistent session secret (survives server restarts) ─────
_SECRET_FILE = os.path.join(PROJECT_DIR, ".flask_secret")
if os.getenv("FLASK_SECRET_KEY"):
    _session_key = os.getenv("FLASK_SECRET_KEY").encode()
elif os.path.exists(_SECRET_FILE):
    with open(_SECRET_FILE, "rb") as _f:
        _session_key = _f.read()
else:
    _session_key = os.urandom(32)
    with open(_SECRET_FILE, "wb") as _f:
        _f.write(_session_key)

app = Flask(__name__, static_folder=FRONTEND_DIR, static_url_path="")
app.config["SECRET_KEY"] = _session_key
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading",
                    logger=False, engineio_logger=False)

init_auth(app)

_event_queue = Queue()
_db = None
_engine = None

# ── Static file extensions that never need auth ──────────────
_STATIC_EXTS = frozenset({
    ".css", ".js", ".ico", ".png", ".jpg", ".jpeg",
    ".gif", ".woff", ".woff2", ".svg", ".map", ".ttf",
})

# ── Auth middleware ───────────────────────────────────────────

@app.before_request
def _require_auth():
    # Logout handled here so static-file routing can't intercept it
    if request.path == "/logout":
        session.clear()
        return redirect("/login")
    # Allow static assets
    ext = os.path.splitext(request.path)[1].lower()
    if ext in _STATIC_EXTS:
        return None
    # Fully public routes
    public = ("/login", "/auth/", "/webhook/stripe")
    if any(request.path.startswith(p) for p in public):
        return None
    # Not authenticated
    if not session.get("user_email"):
        if request.path.startswith("/api/"):
            return jsonify({"error": "not_authenticated"}), 401
        return redirect("/login")
    # Pricing / payment pages — accessible while logged in but unsubscribed
    unguarded = ("/pricing", "/create-checkout-session",
                 "/payment-success", "/payment-cancel", "/api/me")
    if request.path in unguarded:
        return None
    # Require active subscription for dashboard + all other APIs
    if not session.get("subscribed"):
        if request.path.startswith("/api/"):
            return jsonify({"error": "subscription_required"}), 402
        return redirect("/pricing")

# ============================================================
# BROADCASTER — reads from queue and emits to all clients
# ============================================================

def _broadcaster():
    while True:
        try:
            event = _event_queue.get(timeout=1)
            socketio.emit("dlp_event", event)
            socketio.emit("stats_update", _db.stats())
        except Empty:
            continue

# ============================================================
# STATIC PAGES
# ============================================================

@app.route("/")
def index():
    return send_from_directory(FRONTEND_DIR, "index.html")

@app.route("/login")
def login():
    if session.get("user_email"):
        return redirect("/") if session.get("subscribed") else redirect("/pricing")
    return send_from_directory(FRONTEND_DIR, "login.html")

@app.route("/pricing")
def pricing():
    return send_from_directory(FRONTEND_DIR, "pricing.html")

# ============================================================
# GOOGLE OAUTH
# ============================================================

@app.route("/auth/google")
def auth_google():
    if not GOOGLE_CLIENT_ID:
        return redirect("/login?error=oauth_not_configured")
    redirect_uri = url_for("auth_google_callback", _external=True)
    return oauth.google.authorize_redirect(redirect_uri)

@app.route("/auth/google/callback")
def auth_google_callback():
    if not GOOGLE_CLIENT_ID:
        return redirect("/login?error=oauth_not_configured")
    try:
        token     = oauth.google.authorize_access_token()
        user_info = token.get("userinfo") or {}
        email     = user_info.get("email", "")
        if not email:
            return redirect("/login?error=no_email")
        name    = user_info.get("name", email)
        picture = user_info.get("picture", "")
        _db.upsert_user(email, name, picture)
        user = _db.get_user(email)
        session["user_email"]   = email
        session["user_name"]    = name
        session["user_picture"] = picture
        session["subscribed"]   = is_user_subscribed(user)
        return redirect("/") if session["subscribed"] else redirect("/pricing")
    except Exception:
        return redirect("/login?error=oauth_error")

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")

# ============================================================
# STRIPE PAYMENT
# ============================================================

@app.route("/create-checkout-session", methods=["POST"])
def create_checkout_session():
    if not session.get("user_email"):
        return jsonify({"error": "not_authenticated"}), 401
    if not STRIPE_PRICE_ID:
        return jsonify({"error": "stripe_not_configured"}), 503
    try:
        base = request.host_url.rstrip("/")
        checkout = _stripe.checkout.Session.create(
            customer_email=session["user_email"],
            payment_method_types=["card"],
            line_items=[{"price": STRIPE_PRICE_ID, "quantity": 1}],
            mode="subscription",
            success_url=f"{base}/payment-success?session_id={{CHECKOUT_SESSION_ID}}",
            cancel_url=f"{base}/pricing?cancelled=1",
        )
        return jsonify({"url": checkout.url})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/payment-success")
def payment_success():
    if session.get("user_email"):
        _db.set_subscription(session["user_email"], "active")
        session["subscribed"] = True
    return redirect("/")

@app.route("/payment-cancel")
def payment_cancel():
    return redirect("/pricing?cancelled=1")

@app.route("/webhook/stripe", methods=["POST"])
def stripe_webhook():
    payload    = request.get_data()
    sig_header = request.headers.get("Stripe-Signature", "")
    try:
        event = _stripe.Webhook.construct_event(payload, sig_header, STRIPE_WEBHOOK_SEC)
    except Exception:
        return "", 400

    etype = event["type"]
    if etype in ("customer.subscription.created", "customer.subscription.updated"):
        sub    = event["data"]["object"]
        status = "active" if sub["status"] == "active" else "inactive"
        email  = _email_from_sub(sub)
        if email:
            _db.set_subscription(email, status, sub["customer"])
    elif etype == "customer.subscription.deleted":
        sub   = event["data"]["object"]
        email = _email_from_sub(sub)
        if email:
            _db.set_subscription(email, "inactive")
    return "", 200

def _email_from_sub(sub):
    email = sub.get("customer_email", "")
    if not email:
        try:
            customer = _stripe.Customer.retrieve(sub["customer"])
            email = customer.get("email", "")
        except Exception:
            pass
    return email

# ============================================================
# API
# ============================================================

@app.route("/api/me")
def api_me():
    if not session.get("user_email"):
        return jsonify({"authenticated": False})
    user = _db.get_user(session["user_email"])
    if not user:
        return jsonify({"authenticated": False})
    return jsonify({
        "authenticated":   True,
        "email":           user["email"],
        "name":            user["name"],
        "picture":         user["picture"],
        "subscribed":      is_user_subscribed(user),
        "status":          user["subscription_status"],
        "trial_days_left": trial_days_left(user),
        "stripe_pub_key":  STRIPE_PUB_KEY,
        "price_id":        STRIPE_PRICE_ID,
    })

@app.route("/api/logs")
def api_logs():
    try:
        limit = min(int(request.args.get("limit", 500)), 2000)
    except (ValueError, TypeError):
        limit = 500
    action = request.args.get("action", None)
    try:
        since_id = int(request.args.get("since_id", 0))
    except (ValueError, TypeError):
        since_id = 0
    rows = _db.recent(limit=limit, action=action, since_id=since_id)
    return jsonify([
        {"id": r[0], "time": r[1], "type": r[2],
         "action": r[3], "source": r[4], "details": r[5] or ""}
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
        data    = request.get_json(force=True) or {}
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
        _event_queue.put(event)

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

    auth_status = "configured" if GOOGLE_CLIENT_ID else "NOT configured (set GOOGLE_CLIENT_ID in .env)"
    pay_status  = "configured" if STRIPE_PRICE_ID  else "NOT configured (set STRIPE_PRICE_ID in .env)"

    print(f"  Dashboard  : http://localhost:5000")
    print(f"  Google Auth: {auth_status}")
    print(f"  Stripe     : {pay_status}")
    print(f"  Database   : {CONFIG['db']}")
    print("  Press Ctrl+C to stop\n")

    try:
        socketio.run(app, host="0.0.0.0", port=5000, debug=False,
                     use_reloader=False, allow_unsafe_werkzeug=True)
    except KeyboardInterrupt:
        print("\nShutting down...")
        _engine.stop()
        _winlog.stop()
        _activity.stop()
        _firewall.stop()
        _clipboard.stop()
