"""
Windows Event Log Monitor
Reads Security, System, PowerShell, and Defender event logs using wevtutil
(built into every Windows machine — no extra dependencies).

What gets flagged and why
─────────────────────────
BLOCK  : audit log cleared (1102) — nearly always an attacker covering tracks
ALERT  : account changes, scheduled tasks, service installs, brute-force logins,
         suspicious PowerShell commands, Defender detections
ALLOW  : successful logons logged for context (informational only)

All findings are written to the DLP database and broadcast to the dashboard.
Historical events from the last 24 hours are loaded on startup.
"""

import re
import subprocess
import threading
import time
import platform
import xml.etree.ElementTree as ET
from collections import deque
from datetime import datetime, timedelta, timezone

PLATFORM = platform.system()

# ── XML namespace used in Windows event log XML ─────────────
_NS = "http://schemas.microsoft.com/win/2004/08/events/event"
_NSD = {"e": _NS}

# ── Security event rules ─────────────────────────────────────
# Format: event_id -> (action, classification, plain-English reason)
_SECURITY_RULES = {
    1102: ("BLOCK", "LOG_TAMPER",     "Audit log cleared — attacker may be hiding tracks"),
    4697: ("ALERT", "PERSISTENCE",    "Service installed via Service Control Manager"),
    4698: ("ALERT", "PERSISTENCE",    "Scheduled task created"),
    4702: ("ALERT", "PERSISTENCE",    "Scheduled task modified"),
    4720: ("ALERT", "ACCOUNT_CHANGE", "New local user account created"),
    4726: ("ALERT", "ACCOUNT_CHANGE", "User account deleted"),
    4728: ("ALERT", "PRIVILEGE_ESC",  "User added to a global privileged group"),
    4732: ("ALERT", "PRIVILEGE_ESC",  "User added to local Administrators group"),
    4756: ("ALERT", "PRIVILEGE_ESC",  "User added to a universal security group"),
    4648: ("ALERT", "CREDENTIAL",     "Logon attempted with explicit credentials"),
    4624: ("ALLOW", "LOGON",          "Successful logon"),
}

# ── System log rules ─────────────────────────────────────────
_SYSTEM_RULES = {
    7045: ("ALERT", "PERSISTENCE", "New service was installed on the system"),
    7040: ("ALERT", "CONFIG_CHANGE","Service start type was changed"),
}

# ── Windows Defender rules ───────────────────────────────────
_DEFENDER_RULES = {
    1116: ("ALERT", "MALWARE",      "Defender: Malware or unwanted software detected"),
    1117: ("BLOCK", "MALWARE",      "Defender: Action taken against malware — check immediately"),
    5001: ("ALERT", "DEFENSE_EVA",  "Defender: Real-time protection was disabled"),
    5007: ("ALERT", "CONFIG_CHANGE","Defender: Configuration changed"),
}

# ── PowerShell suspicious string patterns ───────────────────
# Each entry: (regex_pattern, human label)
# Conservative list — only patterns that are genuinely alarming
_PS_PATTERNS = [
    (r"invoke-expression|(?<!\w)iex\s*[(\[]",   "Script injection (Invoke-Expression/IEX)"),
    (r"downloadstring|downloadfile",             "Web download of code or file"),
    (r"net\.webclient|new-object.*webclient",    "WebClient object — possible download/upload"),
    (r"invoke-webrequest|irm\s+http",            "HTTP request from PowerShell"),
    (r"frombase64string",                        "Base64 decode — common obfuscation technique"),
    (r"mimikatz|invoke-mimikatz",                "Mimikatz credential theft tool"),
    (r"-e(?:nc(?:odedcommand)?)?\s+[A-Za-z0-9+/]{20}", "Base64-encoded command (-enc)"),
    (r"set-mppreference.{0,60}disable",          "Attempt to disable Windows Defender"),
    (r"vssadmin.{0,30}delete|shadowcopy.{0,30}delete", "Volume shadow copy deletion (ransomware indicator)"),
    (r"net\s+user\s+\S+\s+\S+\s+/add",          "User account created via net command"),
    (r"net\s+localgroup\s+administrators.{0,30}\/add", "User added to Admins via net command"),
    (r"reg\s+(add|delete).{0,60}(run|currentversion\\run|winlogon)", "Registry autorun key modification"),
    (r"certutil.{0,40}(-decode|-urlcache)",      "certutil used for file decode/download (LOLBIN abuse)"),
    (r"wscript|cscript.{0,30}\.vbs",             "VBScript execution"),
    (r"mshta\.exe|mshta\s+http",                 "MSHTA execution — common malware technique"),
]

# ── Logs to query ────────────────────────────────────────────
# Format: log_name -> list of event IDs to filter (None = all, slow)
_WATCH_LOGS = {
    "Security": [
        1102, 4624, 4625, 4648, 4697, 4698, 4702,
        4720, 4726, 4728, 4732, 4756,
    ],
    "System": [7040, 7045],
    "Microsoft-Windows-PowerShell/Operational": [4104],
    "Microsoft-Windows-Windows Defender/Operational": [1116, 1117, 5001, 5007],
}

# ── Brute-force detection ────────────────────────────────────
_BF_WINDOW    = 300   # 5-minute rolling window
_BF_THRESHOLD = 5     # failed logins before alerting

# ── Logon types that warrant an alert ───────────────────────
# Type 3 = Network, Type 10 = RemoteInteractive, Type 7 = Unlock
_ALERT_LOGON_TYPES = {"3", "10"}


def _txt(el, *tags):
    """Walk a chain of child tags and return the last one's text."""
    cur = el
    for tag in tags:
        if cur is None:
            return ""
        cur = cur.find(f"{{{_NS}}}{tag}") or cur.find(tag)
    return (cur.text or "").strip() if cur is not None else ""


def _attr(el, *tags_then_attr):
    """Walk to a child element and return an attribute from it."""
    *tags, attr_name = tags_then_attr
    cur = el
    for tag in tags:
        if cur is None:
            return ""
        cur = cur.find(f"{{{_NS}}}{tag}") or cur.find(tag)
    return cur.get(attr_name, "") if cur is not None else ""


class WindowsLogMonitor:
    POLL_SECS = 10

    def __init__(self, db, event_callback):
        self.db        = db
        self.callback  = event_callback
        self._running  = False
        self._last_id  = {}    # log_name -> highest RecordID we have processed
        self._bf_times = deque()  # monotonic timestamps of failed login events
        self._seen     = set()    # de-dupe: RecordIDs already processed

    # ── Public ───────────────────────────────────────────────

    def start(self):
        if PLATFORM != "Windows":
            self._emit("ALLOW", "SysLogMonitor",
                       "Windows log monitoring skipped — not running on Windows")
            return

        self._running = True
        self._emit("ALLOW", "SysLogMonitor",
                   "Windows Event Log monitor started — scanning last 24 hours")

        self._scan(initial=True)

        while self._running:
            time.sleep(self.POLL_SECS)
            if self._running:
                self._scan(initial=False)

    def stop(self):
        self._running = False

    # ── Internal ─────────────────────────────────────────────

    def _emit(self, action, source, details):
        event = {
            "time":    datetime.now().isoformat(),
            "type":    "SYSLOG",
            "action":  action,
            "source":  source,
            "details": details,
        }
        self.db.log("SYSLOG", action, source, details)
        self.callback(event)

    def _scan(self, initial: bool):
        for log_name in _WATCH_LOGS:
            if not self._running:
                return
            try:
                self._read_log(log_name, initial)
            except Exception:
                pass

    def _wevtutil(self, log_name: str, xpath: str) -> str:
        """Run wevtutil and return stdout. Returns '' on any failure."""
        cmd = [
            "wevtutil", "qe", log_name,
            f"/q:{xpath}",
            "/c:300",
            "/rd:false",          # oldest first so record IDs are ascending
            "/f:xml",
        ]
        try:
            r = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="ignore",
                timeout=25,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            return r.stdout
        except Exception:
            return ""

    def _build_xpath(self, log_name: str, initial: bool) -> str:
        ids     = _WATCH_LOGS[log_name]
        last_id = self._last_id.get(log_name, 0)

        id_clause = (
            "(" + " or ".join(f"EventID={i}" for i in ids) + ")"
            if ids else ""
        )

        if initial:
            since = (
                datetime.utcnow().replace(tzinfo=timezone.utc) - timedelta(hours=24)
            ).strftime("%Y-%m-%dT%H:%M:%S.000Z")
            time_clause = f"TimeCreated[@SystemTime >= '{since}']"
            parts = [p for p in [id_clause, time_clause] if p]
            inner = " and ".join(parts) if parts else ""
            return f"*[System[{inner}]]" if inner else "*"

        if last_id > 0:
            rec_clause = f"EventRecordID > {last_id}"
            parts = [p for p in [id_clause, rec_clause] if p]
            inner = " and ".join(parts)
            return f"*[System[{inner}]]"

        # First non-initial poll with no last_id: grab most recent 50
        return f"*[System[{id_clause}]]" if id_clause else "*"

    def _parse_events(self, xml_text: str) -> list:
        """Split wevtutil multi-event output and parse each <Event> block."""
        events = []
        # wevtutil outputs bare concatenated <Event> elements, not wrapped
        for chunk in re.split(r"(?=<Event[\s>])", xml_text):
            chunk = chunk.strip()
            if not chunk:
                continue
            if not chunk.endswith("</Event>"):
                chunk += "</Event>"
            try:
                root = ET.fromstring(chunk)
                ev = self._extract(root)
                if ev:
                    events.append(ev)
            except ET.ParseError:
                pass
        return events

    def _extract(self, root) -> dict | None:
        sys_el = root.find(f"{{{_NS}}}System") or root.find("System")
        if sys_el is None:
            return None

        # EventID
        eid_el = sys_el.find(f"{{{_NS}}}EventID") or sys_el.find("EventID")
        try:
            event_id = int((eid_el.text or "0").strip()) & 0xFFFF
        except (AttributeError, ValueError):
            return None

        # TimeCreated (attribute, not text)
        tc_el = sys_el.find(f"{{{_NS}}}TimeCreated") or sys_el.find("TimeCreated")
        time_str = tc_el.get("SystemTime", "") if tc_el is not None else ""

        # EventRecordID
        rec_el = sys_el.find(f"{{{_NS}}}EventRecordID") or sys_el.find("EventRecordID")
        try:
            record_id = int((rec_el.text or "0").strip())
        except (AttributeError, ValueError):
            record_id = 0

        # Computer
        comp_el = sys_el.find(f"{{{_NS}}}Computer") or sys_el.find("Computer")
        computer = (comp_el.text or "").strip() if comp_el is not None else ""

        # EventData key=value pairs
        data_el = root.find(f"{{{_NS}}}EventData") or root.find("EventData")
        fields = {}
        raw_parts = []
        if data_el is not None:
            for child in data_el:
                name = child.get("Name", "")
                val  = (child.text or "").strip()
                if val:
                    fields[name] = val
                    raw_parts.append(f"{name}={val}" if name else val)

        return {
            "event_id":  event_id,
            "time":      time_str,
            "record_id": record_id,
            "computer":  computer or "localhost",
            "fields":    fields,
            "raw":       "; ".join(raw_parts[:8]),  # first 8 fields as context
        }

    def _read_log(self, log_name: str, initial: bool):
        xpath  = self._build_xpath(log_name, initial)
        xml_out = self._wevtutil(log_name, xpath)
        if not xml_out.strip():
            return

        events = self._parse_events(xml_out)
        for ev in events:
            rid = ev["record_id"]

            # Advance the high-water mark
            if rid > self._last_id.get(log_name, 0):
                self._last_id[log_name] = rid

            # De-duplicate (initial scan + live overlap protection)
            if rid in self._seen:
                continue
            self._seen.add(rid)

            self._analyze(log_name, ev, historical=initial)

        # Keep _seen from growing unbounded
        if len(self._seen) > 100_000:
            self._seen = set(sorted(self._seen)[-50_000:])

    # ── Rule engine ──────────────────────────────────────────

    def _analyze(self, log_name: str, ev: dict, historical: bool):
        eid      = ev["event_id"]
        computer = ev["computer"]
        fields   = ev["fields"]
        raw      = ev["raw"]
        hist_tag = "[HISTORICAL] " if historical else ""

        src_base = f"{'Security' if 'Security' in log_name else log_name.split('/')[-1]}@{computer}"

        # ── 4625: Failed logon — brute force detection ───────
        if eid == 4625:
            user = fields.get("TargetUserName", fields.get("SubjectUserName", "unknown"))
            now  = time.monotonic()
            self._bf_times.append(now)
            while self._bf_times and self._bf_times[0] < now - _BF_WINDOW:
                self._bf_times.popleft()
            count = len(self._bf_times)
            # Alert only on the exact threshold crossing (not on every subsequent event)
            if count == _BF_THRESHOLD:
                self._emit(
                    "ALERT", f"Security@{computer}",
                    f"{hist_tag}BRUTE_FORCE — {count} failed logins in "
                    f"{_BF_WINDOW}s. Last target user: {user}",
                )
            return

        # ── 4624: Successful logon — only flag network/remote types ──
        if eid == 4624:
            logon_type = fields.get("LogonType", "")
            if logon_type in _ALERT_LOGON_TYPES:
                user   = fields.get("TargetUserName", "?")
                ip     = fields.get("IpAddress", fields.get("WorkstationName", "?"))
                ltype  = {"3": "Network", "10": "RemoteInteractive"}.get(logon_type, logon_type)
                self._emit(
                    "ALLOW", f"Security@{computer}",
                    f"{hist_tag}LOGON — {ltype} logon: user={user} from={ip}",
                )
            return

        # ── Security log rules ───────────────────────────────
        if eid in _SECURITY_RULES:
            action, classification, reason = _SECURITY_RULES[eid]
            detail = f"{hist_tag}{classification} — {reason}"
            # Enrich with key fields where useful
            if eid in (4720, 4726):
                user = fields.get("TargetUserName", "")
                if user:
                    detail += f". Account: {user}"
            elif eid in (4728, 4732, 4756):
                member = fields.get("MemberName", fields.get("SubjectUserName", ""))
                group  = fields.get("GroupName",  "")
                if member or group:
                    detail += f". Member={member} Group={group}"
            elif eid in (4697, 4698, 4702):
                name = (fields.get("ServiceName") or fields.get("TaskName") or
                        fields.get("SubjectUserName") or "")
                if name:
                    detail += f". Name: {name}"
            elif eid == 4648:
                user   = fields.get("TargetUserName",   "")
                server = fields.get("TargetServerName", "")
                if user or server:
                    detail += f". Target: {user}@{server}"
            self._emit(action, src_base, detail)
            return

        # ── System log rules ─────────────────────────────────
        if eid in _SYSTEM_RULES:
            action, classification, reason = _SYSTEM_RULES[eid]
            svc_name = fields.get("ServiceName", fields.get("param1", ""))
            detail   = f"{hist_tag}{classification} — {reason}"
            if svc_name:
                detail += f". Service: {svc_name}"
            if eid == 7045:
                svc_file = fields.get("ImagePath", fields.get("param3", ""))
                if svc_file:
                    detail += f". Binary: {svc_file}"
            self._emit(action, f"System@{computer}", detail)
            return

        # ── Defender rules ───────────────────────────────────
        if eid in _DEFENDER_RULES:
            action, classification, reason = _DEFENDER_RULES[eid]
            threat = (fields.get("Threat Name") or fields.get("ThreatName") or
                      fields.get("Product Name") or "")
            path   = (fields.get("Path") or fields.get("Detection Path") or "")
            detail = f"{hist_tag}{classification} — {reason}"
            if threat:
                detail += f". Threat: {threat}"
            if path:
                detail += f". Path: {path}"
            self._emit(action, f"Defender@{computer}", detail)
            return

        # ── PowerShell script block (4104) ───────────────────
        if eid == 4104:
            # Combine all EventData into one searchable string
            script_text = " ".join(ev["fields"].values()).lower()
            for pattern, label in _PS_PATTERNS:
                if re.search(pattern, script_text, re.I):
                    # Extract a short but useful snippet around the match
                    m = re.search(pattern, script_text, re.I)
                    start  = max(0, m.start() - 40)
                    end    = min(len(script_text), m.end() + 80)
                    snippet = script_text[start:end].replace("\n", " ").strip()
                    self._emit(
                        "ALERT", f"PowerShell@{computer}",
                        f"{hist_tag}SUSPICIOUS_EXEC — {label}. Snippet: ...{snippet}...",
                    )
                    break   # one alert per script block
