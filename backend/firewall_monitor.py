"""
Firewall Monitor
- Auto-enables Windows Firewall logging (dropped + allowed packets)
- Tails pfirewall.log in real time for all inbound/outbound traffic
- Detects port scans, C2 beacons, sensitive-port probes, unusual protocols
- Monitors Security event log for firewall rule changes and service tampering
"""

import os
import re
import subprocess
import threading
import time
from collections import defaultdict, deque
from datetime import datetime
from pathlib import Path

FIREWALL_LOG = Path(r"C:\Windows\System32\LogFiles\Firewall\pfirewall.log")
POLL_SECS    = 2

# ── Threat intelligence ───────────────────────────────────────────────────────

# Ports used by malware C2 / RAT / backdoor frameworks
_C2_PORTS = frozenset({
    4444, 4445, 4446,           # Metasploit default
    1337, 31337,                # "Elite" hacker ports
    8888, 9001, 9030,           # Tor / various C2
    6666, 6667, 6668, 6669,     # IRC (botnet C2)
    1234, 12345, 54321,         # Generic backdoors
    5900, 5901,                 # VNC (remote control)
    65535,                      # Common RAT port
})

# Service ports that should never receive inbound internet connections
_SENSITIVE_INBOUND = {
    21:    "FTP file transfer",
    22:    "SSH remote access",
    23:    "Telnet (unencrypted remote access)",
    135:   "Windows RPC",
    139:   "NetBIOS",
    445:   "SMB file sharing",
    1433:  "Microsoft SQL Server",
    1434:  "SQL Server browser",
    3306:  "MySQL database",
    3389:  "Remote Desktop (RDP)",
    5432:  "PostgreSQL database",
    5985:  "WinRM HTTP",
    5986:  "WinRM HTTPS",
    27017: "MongoDB database",
    6379:  "Redis database",
    9200:  "Elasticsearch",
    2375:  "Docker API (unauthenticated)",
    2376:  "Docker TLS API",
    11211: "Memcached",
}

# Protocols unusual in a regular desktop/laptop environment
_UNUSUAL_PROTO = frozenset({"GRE", "IGMP", "ESP", "AH", "OSPF"})

# Security event IDs for firewall changes
_FW_RULE_EVENTS = {
    "4946": "A rule was ADDED to the Windows Firewall exception list",
    "4947": "A Windows Firewall rule was MODIFIED",
    "4948": "A Windows Firewall rule was DELETED",
    "4950": "A Windows Firewall setting was changed",
    "5025": "Windows Firewall service was STOPPED",
    "5030": "Windows Firewall service FAILED to start",
    "5034": "Windows Firewall Driver was stopped",
    "5035": "Windows Firewall Driver failed to start",
}


def _is_private(ip: str) -> bool:
    return bool(re.match(
        r"^(10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.|127\.|::1)", ip
    ))


class FirewallMonitor:
    PORT_SCAN_WINDOW = 30   # seconds to look back
    PORT_SCAN_THRESH = 8    # unique blocked ports → port scan alert
    FLOOD_WINDOW     = 10   # seconds
    FLOOD_THRESH     = 60   # blocked packets from same IP → flood alert

    def __init__(self, db, event_callback):
        self.db       = db
        self.callback = event_callback
        self._running = False
        self._log_pos = 0

        # EventRecordID watermark per event ID
        self._last_record: dict[str, int] = {}

        # Port-scan tracker: src_ip -> deque[(monotonic, dst_port)]
        self._scan: dict[str, deque] = defaultdict(deque)

        # Connection-flood tracker: src_ip -> list[monotonic]
        self._flood: dict[str, list] = defaultdict(list)

        # Deduplicate C2/sensitive-inbound alerts within 60 s
        self._alerted: dict[str, float] = {}

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    @staticmethod
    def _is_admin() -> bool:
        try:
            import subprocess
            r = subprocess.run(
                ["whoami", "/groups"],
                capture_output=True, text=True, timeout=5
            )
            return "S-1-16-12288" in (r.stdout or "")
        except Exception:
            return False

    def start(self):
        import platform
        if platform.system() != "Windows":
            return

        self._running = True
        admin = self._is_admin()

        if admin:
            self._enable_fw_logging()
            if FIREWALL_LOG.exists():
                self._log_pos = FIREWALL_LOG.stat().st_size
            self._emit("ALLOW", "Firewall",
                       "SYSTEM — Firewall monitor started (full packet log + rule change detection)")
        else:
            self._emit("ALERT", "Firewall",
                       "SYSTEM — Firewall monitor running in limited mode — "
                       "launch via run.bat for full firewall packet logging")

        # Watermark existing firewall rule-change events (best-effort)
        for eid in _FW_RULE_EVENTS:
            self._last_record[eid] = self._max_record_id("Security", eid)

        # Background thread: firewall rule change events
        threading.Thread(target=self._rule_change_loop, daemon=True).start()

        # Main loop: tail the packet log (skipped silently if log doesn't exist)
        while self._running:
            self._poll_log()
            time.sleep(POLL_SECS)

    def stop(self):
        self._running = False

    # ── Internal emitter ──────────────────────────────────────────────────────

    def _emit(self, action: str, source: str, details: str):
        ev = {
            "time":    datetime.now().isoformat(),
            "type":    "FIREWALL",
            "action":  action,
            "source":  source,
            "details": details,
        }
        self.db.log("FIREWALL", action, source, details)
        self.callback(ev)

    def _dedup_emit(self, key: str, action: str, source: str, details: str):
        """Emit at most once per 60 s per key."""
        now = time.monotonic()
        if now - self._alerted.get(key, 0) < 60:
            return
        self._alerted[key] = now
        # Prune old entries
        self._alerted = {k: v for k, v in self._alerted.items() if now - v < 120}
        self._emit(action, source, details)

    # ── Enable Windows Firewall packet logging ────────────────────────────────

    def _enable_fw_logging(self):
        for setting in ("droppedconnections", "allowedconnections"):
            try:
                subprocess.run(
                    ["netsh", "advfirewall", "set", "allprofiles",
                     "logging", setting, "enable"],
                    capture_output=True, timeout=5
                )
            except Exception:
                pass
        # Set log file size to 32 MB (default 4 MB fills quickly)
        try:
            subprocess.run(
                ["netsh", "advfirewall", "set", "allprofiles",
                 "logging", "maxfilesize", "32767"],
                capture_output=True, timeout=5
            )
        except Exception:
            pass

    # ── Parse firewall log file ────────────────────────────────────────────────

    def _poll_log(self):
        if not FIREWALL_LOG.exists():
            return
        try:
            with open(FIREWALL_LOG, "r", errors="ignore") as fh:
                fh.seek(self._log_pos)
                lines = fh.readlines()
                self._log_pos = fh.tell()
            for line in lines:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                self._parse_line(line)
        except Exception:
            pass

    def _parse_line(self, line: str):
        """
        pfirewall.log fields (space-delimited):
        date time action proto src-ip dst-ip src-port dst-port size ... path
        path = SEND | RECEIVE | FORWARD
        """
        parts = line.split()
        if len(parts) < 9:
            return
        try:
            fw_action = parts[2].upper()   # DROP / ALLOW
            proto     = parts[3].upper()
            src_ip    = parts[4]
            dst_ip    = parts[5]
            src_port  = int(parts[6]) if parts[6] != "-" else 0
            dst_port  = int(parts[7]) if parts[7] != "-" else 0
            direction = parts[-1].upper()  # SEND / RECEIVE
        except (ValueError, IndexError):
            return

        # Skip loopback / link-local
        if src_ip.startswith("127.") or dst_ip.startswith("127.") or \
           src_ip.startswith("169.254.") or dst_ip.startswith("169.254."):
            return

        is_inbound  = (direction == "RECEIVE")
        is_outbound = (direction == "SEND")
        is_blocked  = (fw_action == "DROP")
        is_allowed  = (fw_action == "ALLOW")

        # ── Unusual protocol ─────────────────────────────────
        if proto in _UNUSUAL_PROTO and not _is_private(src_ip) and not _is_private(dst_ip):
            remote = src_ip if is_inbound else dst_ip
            self._dedup_emit(
                f"proto:{proto}:{remote}",
                "ALERT", "Firewall",
                f"UNUSUAL_PROTO — {proto} protocol traffic "
                f"{'from' if is_inbound else 'to'} {remote} — "
                f"this protocol is rarely used legitimately and may indicate "
                f"a covert tunnel or VPN bypass attempt"
            )

        # ── Inbound blocked ───────────────────────────────────
        if is_blocked and is_inbound:
            external_ip = src_ip if not _is_private(src_ip) else None

            if external_ip:
                # Port scan detection
                self._track_scan(external_ip, dst_port, proto)

                # Connection flood detection
                self._track_flood(external_ip)

                # Probe on sensitive service port
                if dst_port in _SENSITIVE_INBOUND:
                    svc = _SENSITIVE_INBOUND[dst_port]
                    self._dedup_emit(
                        f"probe:{external_ip}:{dst_port}",
                        "ALERT", "Firewall",
                        f"INBOUND_PROBE — Firewall blocked {external_ip} trying to reach "
                        f"{svc} (port {dst_port}) — attackers routinely probe this port "
                        f"to attempt unauthorized access"
                    )

        # ── Outbound allowed to C2 port ───────────────────────
        if is_allowed and is_outbound and not _is_private(dst_ip):
            if dst_port in _C2_PORTS:
                self._dedup_emit(
                    f"c2:{dst_ip}:{dst_port}",
                    "ALERT", "Firewall",
                    f"C2_BEACON — Your computer made an outbound connection to "
                    f"{dst_ip} on port {dst_port} ({proto}) — this port is used by "
                    f"malware to contact command-and-control servers"
                )

        # ── Inbound allowed on sensitive port from internet ───
        if is_allowed and is_inbound and not _is_private(src_ip):
            if dst_port in _SENSITIVE_INBOUND:
                svc = _SENSITIVE_INBOUND[dst_port]
                self._dedup_emit(
                    f"inallow:{src_ip}:{dst_port}",
                    "ALERT", "Firewall",
                    f"INBOUND_ALLOWED — Firewall permitted {src_ip} to reach "
                    f"{svc} (port {dst_port}) — verify this access is intentional, "
                    f"as this port is a high-value attack target"
                )

    # ── Port scan detection ───────────────────────────────────────────────────

    def _track_scan(self, src_ip: str, dst_port: int, proto: str):
        now = time.monotonic()
        dq  = self._scan[src_ip]
        dq.append((now, dst_port))

        # Evict old entries
        cutoff = now - self.PORT_SCAN_WINDOW
        while dq and dq[0][0] < cutoff:
            dq.popleft()

        unique_ports = len({p for _, p in dq})
        if unique_ports >= self.PORT_SCAN_THRESH:
            dq.clear()
            self._emit(
                "ALERT", "Firewall",
                f"PORT_SCAN — {src_ip} probed {unique_ports} different ports on your "
                f"computer within {self.PORT_SCAN_WINDOW} seconds — this is a textbook "
                f"network reconnaissance attack used before a break-in attempt"
            )

    # ── Flood detection ───────────────────────────────────────────────────────

    def _track_flood(self, src_ip: str):
        now = time.monotonic()
        ts  = self._flood[src_ip]
        ts.append(now)

        cutoff = now - self.FLOOD_WINDOW
        self._flood[src_ip] = [t for t in ts if t >= cutoff]

        if len(self._flood[src_ip]) >= self.FLOOD_THRESH:
            self._flood[src_ip] = []
            self._emit(
                "ALERT", "Firewall",
                f"CONN_FLOOD — {src_ip} sent {self.FLOOD_THRESH}+ blocked packets in "
                f"{self.FLOOD_WINDOW} seconds — possible denial-of-service or brute-force attack"
            )

    # ── Firewall rule change monitoring ──────────────────────────────────────

    def _rule_change_loop(self):
        while self._running:
            time.sleep(5)
            for eid, msg in _FW_RULE_EVENTS.items():
                try:
                    new_max = self._max_record_id("Security", eid)
                    if new_max <= self._last_record.get(eid, 0):
                        continue
                    self._last_record[eid] = new_max

                    if eid in {"5025", "5030", "5034", "5035"}:
                        action = "BLOCK"
                        extra  = "Your firewall is now disabled — your system has NO protection against network attacks"
                    elif eid == "4948":
                        action = "ALERT"
                        extra  = "Deleted firewall rules can open security holes in your system"
                    else:
                        action = "ALERT"
                        extra  = "Unauthorized changes can bypass your firewall protection"

                    self._emit(action, "Firewall",
                               f"FIREWALL_CHANGE — {msg} (Event {eid}) — {extra}")
                except Exception:
                    pass

    # ── Watermark helper ─────────────────────────────────────────────────────

    def _max_record_id(self, log: str, event_id: str) -> int:
        try:
            import xml.etree.ElementTree as ET
            result = subprocess.run(
                ["wevtutil", "qe", log,
                 f"/q:*[System[EventID={event_id}]]",
                 "/c:1", "/rd:true", "/f:xml"],
                capture_output=True, text=True, timeout=5
            )
            raw = result.stdout.strip()
            if not raw:
                return 0
            root = ET.fromstring(f"<R>{raw}</R>")
            ns = "http://schemas.microsoft.com/win/2004/08/events/event"
            for ev in root:
                sys_el = ev.find(f"{{{ns}}}System")
                if sys_el is not None:
                    rid = sys_el.find(f"{{{ns}}}EventRecordID")
                    if rid is not None:
                        return int(rid.text)
        except Exception:
            pass
        return 0
