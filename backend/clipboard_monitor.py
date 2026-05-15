"""
Clipboard & Email Monitor
- Polls clipboard every 2 seconds for sensitive content
- Detects: passwords, dates of birth, email addresses, SSNs, credit card numbers
- Escalates alert when an email compose window is open at the same time
- Also detects when email compose windows are opened (even if content is typed, not pasted)
"""

import hashlib
import json
import re
import subprocess
import time
import threading
from datetime import datetime

POLL_SECS  = 2
DEDUP_SECS = 120  # seconds before re-alerting on exact same clipboard content

# ── Sensitive data patterns ────────────────────────────────────────────────────

_PATTERNS = [
    ("DATE_OF_BIRTH",
     r"\b(?:0?[1-9]|1[0-2])[\/\-\.](?:0?[1-9]|[12]\d|3[01])[\/\-\.](?:(?:19|20)?\d{2})\b"),
    ("EMAIL_ADDRESS",
     r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,7}\b"),
    ("CREDENTIAL",
     r"(?i)(?:password|passwd|pwd|pass|secret|api[_\-]?key|token)\s*[:=\s]+\S{4,}"),
    ("SSN",
     r"\b\d{3}[-\s]\d{2}[-\s]\d{4}\b"),
    ("CREDIT_CARD",
     r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}"
     r"|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b"),
]

# Window title fragments that indicate an email compose window
_COMPOSE_SIGNALS = frozenset({
    "compose", "new message", "new email", "reply to",
    "forward:", "re: ", "fwd:", "write new", "new mail",
    "composing", "message (html)", "message (plain",
})

# Email service / client names that must also appear in the title
_EMAIL_CONTEXTS = frozenset({
    "gmail", "yahoo mail", "thunderbird", "outlook",
    "hotmail", "protonmail", "mail.google", "mail -",
})


# ── Helpers ────────────────────────────────────────────────────────────────────

def _get_clipboard() -> str:
    try:
        r = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive",
             "-Command", "Get-Clipboard"],
            capture_output=True, text=True, timeout=3
        )
        return (r.stdout or "").strip()
    except Exception:
        return ""


def _get_all_window_titles() -> list:
    try:
        cmd = (
            "Get-Process | Where-Object { $_.MainWindowTitle -ne '' } | "
            "Select-Object -ExpandProperty MainWindowTitle | ConvertTo-Json -Compress"
        )
        r = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", cmd],
            capture_output=True, text=True, timeout=4
        )
        raw = (r.stdout or "").strip()
        if not raw:
            return []
        data = json.loads(raw)
        return [data] if isinstance(data, str) else list(data)
    except Exception:
        return []


def _find_compose_window() -> str:
    """Return the title of any open email compose window, or empty string."""
    for title in _get_all_window_titles():
        lower = title.lower()
        has_compose = any(sig in lower for sig in _COMPOSE_SIGNALS)
        has_email   = any(ctx in lower for ctx in _EMAIL_CONTEXTS)
        # Gmail/Outlook webmail: e.g. "Compose - Gmail - Google Chrome"
        if has_compose and has_email:
            return title
        # Outlook desktop: "Untitled - Message (HTML) - Microsoft Outlook"
        if ("message (html)" in lower or "message (plain" in lower) and "outlook" in lower:
            return title
        # Thunderbird: "Compose: Subject - Mozilla Thunderbird"
        if "thunderbird" in lower and ("compose" in lower or "re:" in lower or "fwd:" in lower):
            return title
    return ""


# ── Monitor ────────────────────────────────────────────────────────────────────

class ClipboardMonitor:
    def __init__(self, db, event_callback):
        self.db        = db
        self.callback  = event_callback
        self._running  = False
        self._last_hash = ""
        self._alerted: dict = {}          # content_hash -> monotonic time
        self._known_compose: set = set()  # compose window titles already reported

    def start(self):
        import platform
        if platform.system() != "Windows":
            return
        self._running = True
        self._emit("ALLOW", "Email/Clipboard",
                   "SYSTEM — Email & clipboard monitor started "
                   "(scanning for sensitive data in copy/paste and email compose)")

        # Separate thread: watch for compose windows opening
        threading.Thread(target=self._compose_loop, daemon=True).start()

        # Main loop: scan clipboard
        while self._running:
            try:
                self._poll_clipboard()
            except Exception:
                pass
            time.sleep(POLL_SECS)

    def stop(self):
        self._running = False

    # ── Emitter ───────────────────────────────────────────────────────────────

    def _emit(self, action: str, source: str, details: str):
        ev = {
            "time":    datetime.now().isoformat(),
            "type":    "CLIPBOARD",
            "action":  action,
            "source":  source,
            "details": details,
        }
        self.db.log("CLIPBOARD", action, source, details)
        self.callback(ev)

    # ── Compose window watcher ────────────────────────────────────────────────

    def _compose_loop(self):
        """Alert once each time a NEW email compose window is detected."""
        while self._running:
            time.sleep(3)
            try:
                title = _find_compose_window()
                if title and title not in self._known_compose:
                    self._known_compose.add(title)
                    # Trim memory
                    if len(self._known_compose) > 200:
                        self._known_compose = set(list(self._known_compose)[-100:])
                    self._emit(
                        "ALERT", "Email",
                        f"EMAIL_COMPOSE — Email compose window opened: '{title[:80]}' — "
                        f"monitor is active: any sensitive data (passwords, DOB, personal info) "
                        f"typed or pasted here will be flagged immediately"
                    )
            except Exception:
                pass

    # ── Clipboard scanner ─────────────────────────────────────────────────────

    def _poll_clipboard(self):
        text = _get_clipboard()
        if not text or len(text) > 30_000:
            return

        h = hashlib.md5(text.encode()).hexdigest()
        if h == self._last_hash:
            return
        self._last_hash = h

        now = time.monotonic()
        self._alerted = {k: v for k, v in self._alerted.items()
                         if now - v < DEDUP_SECS}
        if h in self._alerted:
            return

        findings = [label for label, pat in _PATTERNS
                    if re.search(pat, text, re.I | re.M)]
        if not findings:
            return

        self._alerted[h] = now

        compose = _find_compose_window()
        labels  = ", ".join(findings)
        preview = text[:150].replace("\n", " ").replace("\r", "")
        if len(text) > 150:
            preview += "…"

        if compose:
            self._emit(
                "ALERT", "Email/Clipboard",
                f"EMAIL_DATA_LEAK — {labels} detected in clipboard while email compose "
                f"window is open ('{compose[:70]}') — "
                f"sensitive data is about to be sent via email. "
                f"Content: {preview}"
            )
        else:
            self._emit(
                "ALERT", "Clipboard",
                f"SENSITIVE_CLIPBOARD — {labels} copied to clipboard — "
                f"sensitive data detected. Content: {preview}"
            )
