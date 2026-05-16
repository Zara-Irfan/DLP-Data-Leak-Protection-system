# ============================================================
# DLP ENGINE — core detection, no UI dependencies
# ============================================================

import os
import re
import json
import time
import shutil
import sqlite3
import threading
from datetime import datetime

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from cryptography.fernet import Fernet

CONFIG_FILE = "config.json"
KEY_FILE = "dlp.key"


def load_config():
    defaults = {
        "watch_paths": ["./monitor"],
        "quarantine_path": "./quarantine",
        "db": "dlp.db",
        "trusted_ips": ["8.8.8.8", "1.1.1.1"],
        "keywords": ["confidential", "secret", "password", "api_key", "ssn"],
    }
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "r") as f:
            defaults.update(json.load(f))
    return defaults


def load_or_create_key():
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as f:
            return f.read()
    key = Fernet.generate_key()
    with open(KEY_FILE, "wb") as f:
        f.write(key)
    return key


CONFIG = load_config()

# ============================================================
# DATABASE
# ============================================================

class DB:
    def __init__(self):
        self._lock = threading.Lock()
        self.conn = sqlite3.connect(CONFIG["db"], check_same_thread=False)
        self.conn.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY,
            time TEXT,
            type TEXT,
            action TEXT,
            source TEXT,
            details TEXT
        )
        """)
        self.conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            email TEXT UNIQUE NOT NULL,
            name TEXT,
            picture TEXT,
            stripe_customer_id TEXT,
            subscription_status TEXT DEFAULT 'trial',
            created_at TEXT
        )
        """)
        self.conn.commit()

    def get_user(self, email: str):
        with self._lock:
            cur = self.conn.execute(
                "SELECT id, email, name, picture, stripe_customer_id, "
                "subscription_status, created_at FROM users WHERE email=?",
                (email,)
            )
            row = cur.fetchone()
        if not row:
            return None
        return dict(zip(
            ["id", "email", "name", "picture", "stripe_customer_id",
             "subscription_status", "created_at"],
            row
        ))

    def upsert_user(self, email: str, name: str, picture: str):
        with self._lock:
            self.conn.execute(
                "INSERT INTO users (email, name, picture, subscription_status, created_at) "
                "VALUES (?, ?, ?, 'trial', ?) "
                "ON CONFLICT(email) DO UPDATE SET name=excluded.name, picture=excluded.picture",
                (email, name, picture, datetime.now().isoformat())
            )
            self.conn.commit()

    def set_subscription(self, email: str, status: str, customer_id: str = None):
        with self._lock:
            if customer_id:
                self.conn.execute(
                    "UPDATE users SET subscription_status=?, stripe_customer_id=? WHERE email=?",
                    (status, customer_id, email)
                )
            else:
                self.conn.execute(
                    "UPDATE users SET subscription_status=? WHERE email=?",
                    (status, email)
                )
            self.conn.commit()

    def log(self, t, a, s, d):
        with self._lock:
            cur = self.conn.execute(
                "INSERT INTO logs VALUES (NULL,?,?,?,?,?)",
                (datetime.now().isoformat(), t, a, s, d)
            )
            self.conn.commit()
            return cur.lastrowid

    def recent(self, limit=200, action=None, since_id=0):
        with self._lock:
            if action and action != "ALL":
                cur = self.conn.execute(
                    "SELECT id, time, type, action, source, details FROM logs "
                    "WHERE action=? AND id > ? ORDER BY id DESC LIMIT ?",
                    (action, since_id, limit)
                )
            else:
                cur = self.conn.execute(
                    "SELECT id, time, type, action, source, details FROM logs "
                    "WHERE id > ? ORDER BY id DESC LIMIT ?",
                    (since_id, limit)
                )
            return cur.fetchall()

    def stats(self):
        with self._lock:
            cur = self.conn.execute(
                "SELECT action, COUNT(*) FROM logs GROUP BY action"
            )
            result = {r[0]: r[1] for r in cur.fetchall()}
            total_cur = self.conn.execute("SELECT COUNT(*) FROM logs")
            result["TOTAL"] = total_cur.fetchone()[0]
            return result

# ============================================================
# CLASSIFIER
# ============================================================

class Classifier:
    PATTERNS = {
        "CREDENTIAL": (
            r"password\s*[:=]\s*\S+"
            r"|api[_-]?key\s*[:=]\s*\S+"
            r"|token\s*[:=]\s*\S+"
            r"|secret\s*[:=]\s*\S+"
        ),
        "FINANCIAL": (
            r"\b4[0-9]{12}(?:[0-9]{3})?\b"
            r"|\b5[1-5][0-9]{14}\b"
            r"|\b3[47][0-9]{13}\b"
            r"|\b6(?:011|5[0-9]{2})[0-9]{12}\b"
        ),
        "PII": r"\b[A-Z][a-z]{1,20} [A-Z][a-z]{1,20}\b",
    }

    def detect(self, text):
        hits = []
        for label, pattern in self.PATTERNS.items():
            if re.search(pattern, text, re.I):
                hits.append(label)
        for word in CONFIG["keywords"]:
            if word.lower() in text.lower():
                hits.append("PROPRIETARY")
                break
        return list(set(hits))

# ============================================================
# POLICY
# ============================================================

class Policy:
    def evaluate(self, findings):
        if "CREDENTIAL" in findings:
            return "BLOCK"
        if "FINANCIAL" in findings:
            return "QUARANTINE"
        if "PROPRIETARY" in findings:
            return "ENCRYPT"
        if "PII" in findings:
            return "ALERT"
        return "ALLOW"

# ============================================================
# ENCRYPTION
# ============================================================

class Encryptor:
    def __init__(self):
        self.f = Fernet(load_or_create_key())

    def encrypt(self, path):
        try:
            with open(path, "rb") as fh:
                data = fh.read()
            enc_path = path + ".enc"
            with open(enc_path, "wb") as fh:
                fh.write(self.f.encrypt(data))
            os.remove(path)
            return enc_path
        except Exception:
            return None

    def decrypt(self, path):
        try:
            with open(path, "rb") as fh:
                data = fh.read()
            out = path[:-4] if path.endswith(".enc") else path + ".dec"
            with open(out, "wb") as fh:
                fh.write(self.f.decrypt(data))
            return out
        except Exception:
            return None

# ============================================================
# FILE SYSTEM HANDLER
# ============================================================

class Handler(FileSystemEventHandler):
    DEBOUNCE = 1.5

    def __init__(self, db, classifier, policy, enc, event_cb):
        self.db = db
        self.classifier = classifier
        self.policy = policy
        self.enc = enc
        self.event_cb = event_cb
        self._seen = {}
        self._lock = threading.Lock()
        # Track .enc paths that DLP itself just created so we don't alert on them
        self._dlp_enc: dict = {}   # enc_path -> monotonic time

    def _debounce(self, path):
        now = time.monotonic()
        with self._lock:
            if now - self._seen.get(path, 0) < self.DEBOUNCE:
                return False
            self._seen[path] = now
        return True

    def process(self, path, file_op="Modified"):
        if not os.path.isfile(path):
            return
        if path.endswith(".enc"):
            return
        if not self._debounce(path):
            return

        try:
            with open(path, "r", errors="ignore") as fh:
                data = fh.read()
        except (PermissionError, FileNotFoundError):
            return

        findings = self.classifier.detect(data)
        fname = os.path.basename(path)

        if not findings:
            ev = {
                "time":    datetime.now().isoformat(),
                "type":    "ENDPOINT",
                "action":  "ALLOW",
                "source":  fname,
                "details": f"FILE_{file_op.upper()} — No sensitive content found in: {fname}",
            }
            ev["id"] = self.db.log("ENDPOINT", "ALLOW", path, ev["details"])
            self.event_cb(ev)
            return

        action = self.policy.evaluate(findings)

        qpath = os.path.abspath(CONFIG["quarantine_path"])
        action_desc = ""

        try:
            if action == "BLOCK":
                os.remove(path)
                action_desc = (
                    f"ACCESS BLOCKED — File permanently deleted: {fname}\n"
                    f"Reason: Contains credentials ({', '.join(findings)})\n"
                    f"The file has been removed and cannot be accessed."
                )
            elif action == "QUARANTINE":
                os.makedirs(qpath, exist_ok=True)
                # Add timestamp to avoid overwriting existing quarantined files
                ts = datetime.now().strftime("%Y%m%d_%H%M%S")
                dest_fname = f"{ts}_{fname}"
                dest = os.path.join(qpath, dest_fname)
                shutil.move(path, dest)
                action_desc = (
                    f"ACCESS BLOCKED — File moved to quarantine: {fname}\n"
                    f"Reason: Contains financial data ({', '.join(findings)})\n"
                    f"Quarantine location: {dest}\n"
                    f"The file has been removed from its original location."
                )
            elif action == "ENCRYPT":
                enc_path = path + ".enc"
                with self._lock:
                    self._dlp_enc[enc_path] = time.monotonic()
                self.enc.encrypt(path)
                action_desc = (
                    f"File encrypted and access restricted: {fname}\n"
                    f"Reason: Contains proprietary content ({', '.join(findings)})\n"
                    f"Encrypted file: {enc_path}"
                )
            elif action == "ALERT":
                action_desc = (
                    f"Sensitive content detected — no action taken: {fname}\n"
                    f"Reason: Contains personal information ({', '.join(findings)})\n"
                    f"Review this file manually."
                )
            else:
                action_desc = f"File {file_op.lower()}: {fname}"
        except (FileNotFoundError, PermissionError) as e:
            action_desc = f"Action attempted but failed ({e}): {fname}"

        event = {
            "time":    datetime.now().isoformat(),
            "type":    "ENDPOINT",
            "action":  action,
            "source":  fname,
            "details": f"{','.join(findings)} — {action_desc}",
        }
        event["id"] = self.db.log("ENDPOINT", action, path, event["details"])
        self.event_cb(event)

    def _check_enc_tamper(self, path: str):
        """Alert and delete an encrypted file that was modified outside of DLP."""
        # 5-second grace window — skip if DLP itself just created this file
        with self._lock:
            created_at = self._dlp_enc.get(path, 0)
        if time.monotonic() - created_at < 5.0:
            return
        if not self._debounce(path):
            return
        fname = os.path.basename(path)
        try:
            os.remove(path)
            desc = (
                f"ENC_TAMPER — Encrypted file externally modified and deleted: {fname} — "
                f"This DLP-protected file was changed outside the system. "
                f"The tampered file has been removed to prevent data corruption."
            )
        except (FileNotFoundError, PermissionError):
            desc = (
                f"ENC_TAMPER — Encrypted file externally modified: {fname} — "
                f"This DLP-protected file was changed outside the system."
            )
        ev = {
            "time":    datetime.now().isoformat(),
            "type":    "ENDPOINT",
            "action":  "BLOCK",
            "source":  fname,
            "details": desc,
        }
        ev["id"] = self.db.log("ENDPOINT", "BLOCK", path, ev["details"])
        self.event_cb(ev)

    def on_created(self, event):
        if event.is_directory:
            return
        path = event.src_path
        if path.endswith(".enc"):
            return  # DLP creates these — not a security event
        self.process(path, "Created")

    def on_modified(self, event):
        if event.is_directory:
            return
        path = event.src_path
        if path.endswith(".enc"):
            self._check_enc_tamper(path)  # external modification of protected file
            return
        self.process(path, "Modified")

    def on_deleted(self, event):
        if event.is_directory:
            return
        path = event.src_path
        fname = os.path.basename(path)
        if fname.endswith(".enc"):
            return
        # Skip if DLP itself triggered this deletion (processed recently)
        if time.monotonic() - self._seen.get(path, 0) < 5.0:
            return
        ev = {
            "time":    datetime.now().isoformat(),
            "type":    "ENDPOINT",
            "action":  "ALERT",
            "source":  fname,
            "details": f"FILE_DELETED — File was deleted: {fname}",
        }
        ev["id"] = self.db.log("ENDPOINT", "ALERT", path, ev["details"])
        self.event_cb(ev)

# ============================================================
# NETWORK DLP
# ============================================================

class NetworkDLP:
    def __init__(self, classifier, db, event_cb):
        self.classifier = classifier
        self.db         = db
        self.event_cb   = event_cb

    def start(self):
        import platform
        if platform.system() == "Darwin":
            return
        try:
            from scapy.all import sniff, Raw

            def inspect(pkt):
                if Raw not in pkt:
                    return
                payload = pkt[Raw].load.decode("utf-8", errors="ignore")
                findings = self.classifier.detect(payload)
                if findings:
                    source  = pkt.summary()[:60]
                    details = ",".join(findings)
                    ev = {
                        "time":    datetime.now().isoformat(),
                        "type":    "NETWORK",
                        "action":  "ALERT",
                        "source":  source,
                        "details": details,
                    }
                    ev["id"] = self.db.log("NETWORK", "ALERT", source, details)
                    self.event_cb(ev)

            sniff(prn=inspect, store=0, filter="tcp")
        except ImportError:
            pass
        except Exception:
            pass

# ============================================================
# ENGINE
# ============================================================

class DLPEngine:
    def __init__(self, db, event_callback=None):
        self.db = db
        self.event_cb = event_callback or (lambda e: None)
        self.classifier = Classifier()
        self.policy = Policy()
        self.enc = Encryptor()
        self.obs = Observer()
        self.net = NetworkDLP(self.classifier, self.db, self.event_cb)
        self._running = False

    def start(self):
        self._running = True

        for p in CONFIG["watch_paths"]:
            os.makedirs(p, exist_ok=True)
            handler = Handler(
                self.db, self.classifier, self.policy,
                self.enc, self.event_cb
            )
            self.obs.schedule(handler, p, recursive=True)

        self.obs.start()

        import threading as _t
        _t.Thread(target=self.net.start, daemon=True).start()

        while self._running:
            time.sleep(1)

    def stop(self):
        self._running = False
        self.obs.stop()
        self.obs.join()
