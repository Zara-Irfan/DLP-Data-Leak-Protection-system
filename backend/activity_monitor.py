"""
Activity Monitor
Tracks browser history (Chrome, Edge, Firefox), running processes,
and active network connections in real time.

Every action is recorded. Suspicious ones are flagged immediately.
"""

import os
import re
import shutil
import sqlite3
import tempfile
import threading
import time
import platform
from datetime import datetime
from pathlib import Path

PLATFORM = platform.system()

# ── Chrome / Edge time conversion ───────────────────────────
# Chrome stores timestamps as microseconds since 1601-01-01
_CHROME_DELTA = 11_644_473_600  # seconds between 1601 and 1970 epoch

def _chrome_time(t):
    try:
        return datetime.fromtimestamp(t / 1_000_000 - _CHROME_DELTA)
    except Exception:
        return datetime.now()

# ── Browser DB paths ─────────────────────────────────────────
_LOCAL  = os.environ.get("LOCALAPPDATA", "")
_APPDATA = os.environ.get("APPDATA", "")
_PROFILE = os.environ.get("USERPROFILE", "")

CHROMIUM_BROWSERS = {
    "Chrome": Path(_LOCAL) / "Google"    / "Chrome" / "User Data" / "Default" / "History",
    "Edge":   Path(_LOCAL) / "Microsoft" / "Edge"   / "User Data" / "Default" / "History",
    "Brave":  Path(_LOCAL) / "BraveSoftware" / "Brave-Browser" / "User Data" / "Default" / "History",
    "Opera":  Path(_APPDATA) / "Opera Software" / "Opera Stable" / "History",
}

# Firefox profile discovery
def _firefox_histories():
    base = Path(_APPDATA) / "Mozilla" / "Firefox" / "Profiles"
    if not base.exists():
        return {}
    paths = {}
    for d in base.iterdir():
        if d.is_dir():
            db = d / "places.sqlite"
            if db.exists():
                paths[f"Firefox({d.name[:8]})"] = db
    return paths

# ── Suspicious URL detection ──────────────────────────────────
# Upload / file-sharing services — common exfiltration channels
_UPLOAD_DOMAINS = {
    "mega.nz", "wetransfer.com", "sendspace.com", "filebin.net",
    "transfer.sh", "anonfiles.com", "uploadfiles.io", "gofile.io",
    "file.io", "pixeldrain.com", "ufile.io", "dropmefiles.com",
    "mediafire.com", "uploaded.net", "zippyshare.com",
}

# Paste / code-sharing sites — sensitive data often pasted here
_PASTE_DOMAINS = {
    "pastebin.com", "paste.ee", "hastebin.com", "ghostbin.co",
    "controlc.com", "paste.ubuntu.com", "dpaste.org", "justpaste.it",
    "rentry.co", "privatebin.net", "bin.birdnest.org",
}

# Crypto / anonymous sites
_ANON_DOMAINS = {
    "protonmail.com", "tutanota.com", "tempmail.com",
    "guerrillamail.com", "10minutemail.com", "throwam.com",
}

# URL patterns that suggest data being embedded in the request
_EXFIL_URL_PATTERNS = [
    (r"[?&][a-zA-Z0-9_]+=(?:[A-Za-z0-9+/]{40,}={0,2})",
     "Base64-encoded data in URL parameters (possible exfiltration)"),
    (r"[?&](?:file|data|content|text|msg|payload)=.{100,}",
     "Large data payload in URL query string"),
]

# ── Processes suppressed from routine ALLOW/PROCESS_START events ─────────────
# Suspicious-dir and bad-cmdline checks still run for ALL of these.
# Browsers are tracked via history + window titles, not process events.
# System processes cycle too frequently to be useful as ALLOW audit entries.
# DLP-spawned utilities (wevtutil, powershell, netsh) appear every 1-2 seconds.
_NOISE_PROCS = frozenset({
    # Browsers
    "chrome.exe", "msedge.exe", "firefox.exe", "brave.exe",
    "opera.exe", "chromium.exe", "iexplore.exe",
    # Windows system processes
    "runtimebroker.exe", "svchost.exe", "conhost.exe", "dllhost.exe",
    "taskhostw.exe", "sihost.exe", "fontdrvhost.exe", "ctfmon.exe",
    "audiodg.exe", "settingsynchost.exe", "backgroundtaskhost.exe",
    "wuauclt.exe", "msiexec.exe", "searchindexer.exe",
    "searchprotocolhost.exe", "searchfilterhost.exe",
    "securityhealthservice.exe", "smartscreen.exe",
    "werfault.exe", "wermgr.exe", "sppsvc.exe",
    # DLP-spawned subprocesses (would flood the log if logged)
    "wevtutil.exe",     # windows_log_monitor runs this every 2 s
    "whoami.exe",       # admin detection on startup
    "netsh.exe",        # firewall_monitor enables logging via netsh
    "powershell.exe",   # activity_monitor runs this every 1 s for window titles
    "pwsh.exe",         # same, PowerShell 7 variant
})

# ── Suspicious process detection ─────────────────────────────
_BAD_PROCESS_NAMES = {
    "mimikatz.exe", "meterpreter.exe", "nc.exe", "ncat.exe",
    "netcat.exe", "wce.exe", "pwdump.exe", "fgdump.exe",
    "gsecdump.exe", "procdump.exe", "psexec.exe",
}

# Processes launched from these dirs are unusual and suspicious
_SUSPICIOUS_DIRS = [p.lower() for p in [
    os.environ.get("TEMP", ""),
    os.environ.get("TMP", ""),
    os.path.join(_PROFILE, "AppData", "Local", "Temp"),
    os.path.join(_PROFILE, "Downloads"),
    "c:\\windows\\temp",
    "c:\\perflogs",
    "c:\\programdata",
] if p]

# Suspicious patterns in the full command-line string
_BAD_CMDLINE = [
    (r"-(?:enc|encodedcommand)\s+[A-Za-z0-9+/]{20,}",
     "Base64-encoded PowerShell command"),
    (r"(?:powershell|pwsh).*(?:-w\s+hid|-windowstyle\s+hid)",
     "Hidden PowerShell window"),
    (r"(?:powershell|pwsh).*(?:-nop|-noprofile).*(?:-c|-command)\s+[\"']?\s*i(?:ex|nvoke-expression)",
     "PowerShell script injection with -noprofile"),
    (r"downloadstring|downloadfile|webclient.*download",
     "PowerShell file download"),
    (r"vssadmin(?:\.exe)?.{0,30}delete.{0,30}shadow",
     "Volume shadow copy deletion (ransomware indicator)"),
    (r"net\s+user\s+\S+\s+\S+\s+/add",
     "New user account created via net.exe"),
    (r"net\s+localgroup\s+administrators.{0,30}/add",
     "User added to Administrators group via net.exe"),
    (r"reg\s+(?:add|delete).{0,80}(?:run|currentversion.run|winlogon)",
     "Registry autorun key modification"),
    (r"certutil.{0,30}(?:-decode|-urlcache|-f)",
     "certutil used for file decode or download"),
    (r"bitsadmin.{0,30}/transfer",
     "BITS transfer (living-off-the-land download)"),
    (r"mshta(?:\.exe)?\s+(?:http|vbscript|javascript)",
     "MSHTA executing remote script"),
    (r"wscript(?:\.exe)?\s+.{0,100}\.(?:vbs|js|hta)",
     "Script interpreter (wscript) executing file"),
    (r"regsvr32(?:\.exe)?.*\/s.*\/u.*\/i:http",
     "regsvr32 executing remote COM object"),
    (r"rundll32(?:\.exe)?\s+javascript:",
     "rundll32 executing JavaScript"),
]

# ── Suspicious ports ─────────────────────────────────────────
_C2_PORTS = {4444, 4445, 1337, 31337, 8888, 9001, 9030, 6667, 6666, 1234}

_NORMAL_PORTS = {
    80, 443, 8080, 8443, 53, 22, 21, 25, 587, 465, 993, 995,
    3389, 5228, 5229, 5230, 1080, 3128, 5353,
}

# ── Friendly application names ───────────────────────────────
_APP_NAMES = {
    # Browsers
    "chrome.exe":        "Google Chrome",
    "msedge.exe":        "Microsoft Edge",
    "firefox.exe":       "Mozilla Firefox",
    "brave.exe":         "Brave Browser",
    "opera.exe":         "Opera Browser",
    "iexplore.exe":      "Internet Explorer",
    "vivaldi.exe":       "Vivaldi Browser",
    # Office
    "winword.exe":       "Microsoft Word",
    "excel.exe":         "Microsoft Excel",
    "powerpnt.exe":      "Microsoft PowerPoint",
    "outlook.exe":       "Microsoft Outlook",
    "onenote.exe":       "Microsoft OneNote",
    "msaccess.exe":      "Microsoft Access",
    "mspub.exe":         "Microsoft Publisher",
    # Dev tools
    "code.exe":          "Visual Studio Code",
    "devenv.exe":        "Visual Studio",
    "pycharm64.exe":     "PyCharm",
    "idea64.exe":        "IntelliJ IDEA",
    "webstorm64.exe":    "WebStorm",
    "sublime_text.exe":  "Sublime Text",
    "atom.exe":          "Atom Editor",
    "notepad++.exe":     "Notepad++",
    "git.exe":           "Git",
    "github desktop.exe":"GitHub Desktop",
    # System tools
    "notepad.exe":       "Notepad",
    "calc.exe":          "Calculator",
    "mspaint.exe":       "Paint",
    "explorer.exe":      "File Explorer",
    "taskmgr.exe":       "Task Manager",
    "regedit.exe":       "Registry Editor",
    "mmc.exe":           "Management Console",
    "control.exe":       "Control Panel",
    "mstsc.exe":         "Remote Desktop",
    "snippingtool.exe":  "Snipping Tool",
    "wt.exe":            "Windows Terminal",
    "cmd.exe":           "Command Prompt",
    "powershell.exe":    "PowerShell",
    "pwsh.exe":          "PowerShell 7",
    "python.exe":        "Python",
    "python3.exe":       "Python 3",
    "node.exe":          "Node.js",
    # Communication
    "teams.exe":         "Microsoft Teams",
    "slack.exe":         "Slack",
    "discord.exe":       "Discord",
    "zoom.exe":          "Zoom",
    "skype.exe":         "Skype",
    "thunderbird.exe":   "Mozilla Thunderbird",
    "whatsapp.exe":      "WhatsApp",
    "telegram.exe":      "Telegram",
    "signal.exe":        "Signal",
    # Media
    "vlc.exe":           "VLC Media Player",
    "spotify.exe":       "Spotify",
    "wmplayer.exe":      "Windows Media Player",
    "mpc-hc64.exe":      "Media Player Classic",
    # Cloud & file
    "onedrive.exe":      "OneDrive",
    "dropbox.exe":       "Dropbox",
    "googledrivesync.exe":"Google Drive",
    "7zfm.exe":          "7-Zip",
    "winrar.exe":        "WinRAR",
    # Adobe
    "acrobat.exe":       "Adobe Acrobat",
    "photoshop.exe":     "Adobe Photoshop",
    "illustrator.exe":   "Adobe Illustrator",
    # Gaming
    "steam.exe":         "Steam",
    "epicgameslauncher.exe": "Epic Games Launcher",
}


class ActivityMonitor:
    """
    Monitors browser history, process launches, and network connections.
    Polls every POLL_SECS seconds. All events go to the DLP database
    and are broadcast to the dashboard in real time.
    """
    POLL_SECS       = 1
    CONN_POLL_SECS  = 3
    NET_SEEN_MAX    = 20_000

    def __init__(self, db, event_callback):
        self.db        = db
        self.callback  = event_callback
        self._running  = False

        # Browser state: name -> last visit ID seen
        self._last_visit: dict[str, int] = {}

        # Process state: set of PIDs seen on last poll
        self._known_pids: set[int] = set()

        # Network state: set of (lport, rip, rport) tuples seen
        self._known_conns: set[tuple] = set()

        # Per-browser initialised flag (skip existing history on first run)
        self._browser_init: set[str] = set()

        # Window title tracking for real-time page-title browsing events
        self._known_window_titles: set[str] = set()

    # ── Lifecycle ────────────────────────────────────────────

    def start(self):
        if PLATFORM != "Windows":
            self._emit("ALLOW", "ActivityMonitor",
                       "SYSTEM — Activity monitoring skipped (not Windows)")
            return

        try:
            import psutil as _p
        except ImportError:
            self._emit("ALERT", "ActivityMonitor",
                       "SYSTEM — psutil not installed; run run.bat to install")
            return

        import psutil
        self._running = True

        # Snapshot existing processes so we only alert on NEW ones
        try:
            self._known_pids = {p.pid for p in psutil.process_iter(["pid"])}
        except Exception:
            pass

        self._emit("ALLOW", "ActivityMonitor",
                   "SYSTEM — Activity monitor started (browser, process, network)")

        # Run network monitor on a slower thread
        threading.Thread(target=self._net_loop, daemon=True).start()

        # Main loop: browser + process
        while self._running:
            self._poll_browsers()
            self._poll_processes()
            self._poll_window_titles()
            time.sleep(self.POLL_SECS)

    def stop(self):
        self._running = False

    # ── Emitter ──────────────────────────────────────────────

    def _emit(self, action, source, details):
        event = {
            "time":    datetime.now().isoformat(),
            "type":    "ACTIVITY",
            "action":  action,
            "source":  source,
            "details": details,
        }
        event["id"] = self.db.log("ACTIVITY", action, source, details)
        self.callback(event)

    # ── Browser monitoring ───────────────────────────────────

    def _poll_browsers(self):
        # Chromium-based
        for name, path in CHROMIUM_BROWSERS.items():
            if path.exists():
                try:
                    self._read_chromium(name, path)
                except Exception:
                    pass
        # Firefox
        try:
            for name, path in _firefox_histories().items():
                try:
                    self._read_firefox(name, path)
                except Exception:
                    pass
        except Exception:
            pass

    def _copy_db(self, src: Path) -> str | None:
        """Copy a locked browser SQLite file to a temp path."""
        try:
            tmp = tempfile.mktemp(suffix=".db")
            shutil.copy2(str(src), tmp)
            return tmp
        except Exception:
            return None

    def _read_chromium(self, name: str, db_path: Path):
        tmp = self._copy_db(db_path)
        if not tmp:
            return
        try:
            con = sqlite3.connect(f"file:{tmp}?mode=ro&immutable=1", uri=True,
                                  timeout=2)
            con.row_factory = sqlite3.Row

            last_id = self._last_visit.get(name, 0)

            if name not in self._browser_init:
                # First run: just record where we are, don't flood with history
                row = con.execute(
                    "SELECT MAX(id) as mx FROM visits"
                ).fetchone()
                self._last_visit[name] = row["mx"] or 0
                self._browser_init.add(name)
                con.close()
                return

            rows = con.execute(
                "SELECT v.id, u.url, u.title, v.visit_time "
                "FROM visits v JOIN urls u ON v.url = u.id "
                "WHERE v.id > ? ORDER BY v.id ASC LIMIT 200",
                (last_id,)
            ).fetchall()
            con.close()

            for row in rows:
                vid = row["id"]
                if vid > self._last_visit.get(name, 0):
                    self._last_visit[name] = vid
                self._analyze_url(name, row["url"] or "", row["title"] or "")

        except Exception:
            pass
        finally:
            try:
                os.unlink(tmp)
            except Exception:
                pass

    def _read_firefox(self, name: str, db_path: Path):
        tmp = self._copy_db(db_path)
        if not tmp:
            return
        try:
            con = sqlite3.connect(f"file:{tmp}?mode=ro&immutable=1", uri=True,
                                  timeout=2)
            con.row_factory = sqlite3.Row

            last_id = self._last_visit.get(name, 0)

            if name not in self._browser_init:
                row = con.execute(
                    "SELECT MAX(id) as mx FROM moz_historyvisits"
                ).fetchone()
                self._last_visit[name] = row["mx"] or 0
                self._browser_init.add(name)
                con.close()
                return

            rows = con.execute(
                "SELECT v.id, p.url, p.title "
                "FROM moz_historyvisits v JOIN moz_places p ON v.place_id = p.id "
                "WHERE v.id > ? ORDER BY v.id ASC LIMIT 200",
                (last_id,)
            ).fetchall()
            con.close()

            for row in rows:
                vid = row["id"]
                if vid > self._last_visit.get(name, 0):
                    self._last_visit[name] = vid
                self._analyze_url(name, row["url"] or "", row["title"] or "")

        except Exception:
            pass
        finally:
            try:
                os.unlink(tmp)
            except Exception:
                pass

    def _analyze_url(self, browser: str, url: str, title: str):
        """URL-based security analysis only — normal browsing is reported by _poll_window_titles."""
        if not url or re.match(
            r"^(chrome|edge|about|chrome-extension|moz-extension|data|blob):", url
        ):
            return

        m = re.match(r"https?://(?:www\.)?([^/?#:]+)", url, re.I)
        domain = m.group(1).lower() if m else ""
        page   = title.strip() if title.strip() else domain

        # Upload / exfiltration sites
        if domain and any(domain == d or domain.endswith("." + d) for d in _UPLOAD_DOMAINS):
            self._emit("ALERT", browser,
                f"DATA_EXFIL — Opened file-sharing site {domain} in {browser} — "
                f"risk of data being uploaded or exfiltrated\n"
                f"Page Title: {page}\n"
                f"Full URL: {url}"
            )
            return

        # Paste sites
        if domain and any(domain == d or domain.endswith("." + d) for d in _PASTE_DOMAINS):
            self._emit("ALERT", browser,
                f"DATA_EXFIL — Opened paste site {domain} in {browser} — "
                f"sensitive data may have been pasted or shared\n"
                f"Page Title: {page}\n"
                f"Full URL: {url}"
            )
            return

        # Suspicious URL structure
        for pat, desc in _EXFIL_URL_PATTERNS:
            if re.search(pat, url):
                self._emit("ALERT", browser,
                    f"SUSPICIOUS_URL — {desc}\n"
                    f"Site: {domain}\n"
                    f"Page Title: {page}\n"
                    f"Full URL: {url}"
                )
                return

        # Plain HTTP (unencrypted)
        if url.startswith("http://") and domain and not re.match(
            r"^(localhost|127\.|192\.168\.|10\.|172\.(?:1[6-9]|2\d|3[01])\.)", domain
        ):
            self._emit("ALERT", browser,
                f"UNENCRYPTED — Visited {domain} over plain HTTP — "
                f"all data sent to this site is visible on the network\n"
                f"Page Title: {page}\n"
                f"Full URL: {url}"
            )

    # ── Window title monitoring (real-time, exact page titles) ───

    _BROWSER_PROCS = {
        "chrome":   "Google Chrome",
        "msedge":   "Microsoft Edge",
        "firefox":  "Mozilla Firefox",
        "brave":    "Brave Browser",
        "opera":    "Opera Browser",
    }

    def _poll_window_titles(self):
        """Read current browser tab titles from visible browser windows only.

        Uses IsWindowVisible() to skip background Chrome/Edge processes that
        retain a window title even after the browser window is closed.
        """
        import subprocess, json

        proc_list = ",".join(self._BROWSER_PROCS.keys())

        # C# type compiled once per PowerShell session (cached by name 'DlpAmWinVis')
        type_src = (
            "using System; using System.Runtime.InteropServices; "
            "public class DlpAmWinVis { "
            "[DllImport(\"user32.dll\")] public static extern bool IsWindowVisible(IntPtr h); "
            "}"
        )
        cmd = (
            "if (-not ([System.Management.Automation.PSTypeName]'DlpAmWinVis').Type) { "
            f"  Add-Type -TypeDefinition '{type_src}' -ErrorAction SilentlyContinue "
            "} ; "
            f"Get-Process {proc_list} -ErrorAction SilentlyContinue | "
            "Where-Object { "
            "  $h = $_.MainWindowHandle ; "
            "  $h -ne [IntPtr]::Zero -and "
            "  $_.MainWindowTitle -ne '' -and "
            "  [DlpAmWinVis]::IsWindowVisible($h) "
            "} | "
            "Select-Object Name,MainWindowTitle | "
            "ConvertTo-Json -Compress -Depth 1"
        )
        try:
            out = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", cmd],
                capture_output=True, text=True, timeout=5
            )
            raw = (out.stdout or "").strip()
            if not raw:
                return

            data = json.loads(raw)
            if isinstance(data, dict):
                data = [data]

            for entry in data:
                proc  = (entry.get("Name") or "").lower()
                title = (entry.get("MainWindowTitle") or "").strip()
                if not title or proc not in self._BROWSER_PROCS:
                    continue

                browser = self._BROWSER_PROCS[proc]

                # Skip generic / empty titles
                if title.lower() in {
                    browser.lower(), "new tab", "google chrome",
                    "microsoft edge", "mozilla firefox", "brave browser", "opera browser",
                }:
                    continue

                key = f"{proc}::{title}"
                if key in self._known_window_titles:
                    continue
                self._known_window_titles.add(key)

                if len(self._known_window_titles) > 5000:
                    self._known_window_titles = set(
                        list(self._known_window_titles)[-2500:]
                    )

                self._analyze_window_title(browser, title)

        except Exception:
            pass

    def _analyze_window_title(self, browser: str, raw_title: str):
        """Convert a browser window title into a detailed, human-readable DLP event."""
        title = raw_title

        # Strip trailing browser name that the OS appends
        for suffix in [
            " - Google Chrome", " - Microsoft Edge", " - Mozilla Firefox",
            " - Brave", " - Opera", " – Google Chrome", " – Microsoft Edge",
            " — Google Chrome", " — Microsoft Edge",
        ]:
            if title.endswith(suffix):
                title = title[:-len(suffix)].strip()
                break

        # Most sites format as "Content - Site Name"
        # e.g. "Never Gonna Give You Up - Rick Astley - YouTube"
        parts = [p.strip() for p in re.split(r'\s*[-–—|]\s*', title) if p.strip()]
        if len(parts) >= 2:
            site    = parts[-1]
            content = " - ".join(parts[:-1])
        else:
            site    = ""
            content = title

        lower_site = site.lower()

        # ── Email compose detection (alert before content is sent) ────────────
        _compose_signals = {"compose", "new message", "new email", "reply to",
                            "fwd:", "re: ", "write new", "draft"}
        _email_sites     = {"gmail", "yahoo mail", "outlook", "hotmail",
                            "protonmail", "mail.google"}

        is_email_site    = any(s in lower_site for s in _email_sites)
        is_compose_title = any(sig in content.lower() for sig in _compose_signals)

        if is_email_site and (is_compose_title or content.lower() in {"compose", "new message"}):
            self._emit(
                "ALERT", browser,
                f"EMAIL_COMPOSE — Email compose window opened on {site} [{browser}] — "
                f"clipboard monitor is active and will flag any sensitive data "
                f"(passwords, DOB, personal info) pasted into this email"
            )
            return

        # Personalise the verb based on the site
        if "google" in lower_site and "search" in lower_site:
            action_verb = f"Searched for '{content}' on Google"
        elif "youtube" in lower_site:
            action_verb = f"Watched '{content}' on YouTube"
        elif "netflix" in lower_site:
            action_verb = f"Watched '{content}' on Netflix"
        elif "spotify" in lower_site:
            action_verb = f"Listened to '{content}' on Spotify"
        elif "twitter" in lower_site or "x.com" in lower_site:
            action_verb = f"Viewed post on X/Twitter: '{content}'"
        elif "reddit" in lower_site:
            action_verb = f"Browsed Reddit: '{content}'"
        elif "gmail" in lower_site or "mail.google" in lower_site:
            action_verb = f"Opened email: '{content}'"
        elif site:
            action_verb = f"Opened '{content}' on {site}"
        else:
            action_verb = f"Opened '{title}'"

        # Flag sensitive keywords in the page title
        lower_title = title.lower()
        if any(w in lower_title for w in [
            "password", "credential", "secret", "confidential",
            "ssn", "social security", "private key", "api key",
        ]):
            self._emit("ALERT", browser,
                       f"SENSITIVE_BROWSE — Sensitive page open: {action_verb} [{browser}]")
        else:
            self._emit("ALLOW", browser, f"BROWSE — {action_verb} [{browser}]")

    # ── Process monitoring ───────────────────────────────────

    def _poll_processes(self):
        try:
            import psutil
            current: dict[int, dict] = {}
            for proc in psutil.process_iter(
                ["pid", "name", "exe", "cmdline", "username", "create_time"]
            ):
                try:
                    current[proc.pid] = proc.info
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

            new_pids = set(current.keys()) - self._known_pids
            for pid in new_pids:
                info = current.get(pid)
                if info:
                    self._analyze_process(pid, info)

            self._known_pids = set(current.keys())
        except Exception:
            pass

    def _friendly(self, name: str, exe: str) -> str:
        """Return a human-readable app name."""
        key = name.lower()
        if key in _APP_NAMES:
            return _APP_NAMES[key]
        # Fall back to the exe basename without extension
        if exe:
            base = os.path.basename(exe)
            return os.path.splitext(base)[0].replace("_", " ").replace("-", " ").title()
        return name or "Unknown App"

    def _analyze_process(self, pid: int, info: dict):
        name    = (info.get("name") or "").lower()
        exe     = info.get("exe") or ""
        cmdline = info.get("cmdline") or []
        cmd_str = " ".join(cmdline)
        exe_low = exe.lower()

        # Skip processes with no real identity (kernel / system threads)
        if not exe and not cmdline:
            return

        friendly = self._friendly(name, exe)

        # ── Known malicious tools ────────────────────────────
        if name in _BAD_PROCESS_NAMES:
            self._emit(
                "BLOCK", "Process",
                f"MALWARE_TOOL — Dangerous tool '{friendly}' was launched on this computer. "
                f"Path: {exe or 'unknown'}"
            )
            return

        # ── Launched from suspicious directory ───────────────
        if exe_low:
            for sus_dir in _SUSPICIOUS_DIRS:
                if sus_dir and exe_low.startswith(sus_dir):
                    if exe_low.endswith(".exe"):
                        self._emit(
                            "ALERT", "Process",
                            f"SUSPICIOUS_EXEC — '{friendly}' was launched from an unusual "
                            f"folder ({os.path.dirname(exe)}) — this is how malware often runs"
                        )
                        return
                    break

        # ── Suspicious command-line patterns ─────────────────
        if cmd_str:
            for pattern, label in _BAD_CMDLINE:
                if re.search(pattern, cmd_str, re.I):
                    short_cmd = cmd_str[:200]
                    self._emit(
                        "ALERT", "Process",
                        f"SUSPICIOUS_EXEC — {friendly} ran a suspicious command: {label}  "
                        f"|  Full command: {short_cmd}"
                    )
                    return

        # ── Skip noisy system / DLP-spawned processes ────────
        # Malicious-tool and suspicious-dir/cmdline checks above still ran.
        # Only the generic ALLOW audit entry is suppressed here.
        if name in _NOISE_PROCS:
            return

        # ── Normal app launch — audit trail ──────────────────
        self._emit(
            "ALLOW", "Process",
            f"PROCESS_START — {friendly} was opened (PID {pid})"
        )

    # ── Network monitoring ───────────────────────────────────

    def _net_loop(self):
        while self._running:
            try:
                self._poll_connections()
            except Exception:
                pass
            time.sleep(self.CONN_POLL_SECS)

    def _poll_connections(self):
        import psutil

        for conn in psutil.net_connections(kind="inet4"):
            if conn.status != "ESTABLISHED":
                continue
            if not conn.raddr:
                continue

            rip, rport = conn.raddr.ip, conn.raddr.port
            lport      = conn.laddr.port if conn.laddr else 0
            key        = (lport, rip, rport)

            if key in self._known_conns:
                continue
            self._known_conns.add(key)

            # Skip loopback / private addresses
            if re.match(r"^(127\.|::1|0\.|169\.254\.|10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.)", rip):
                continue

            # Skip normal well-known ports
            if rport in _NORMAL_PORTS:
                continue

            # Flag known C2 / RAT ports
            if rport in _C2_PORTS:
                self._emit(
                    "ALERT", "Network",
                    f"SUSPICIOUS_CONN — Your computer connected to {rip} on port {rport} "
                    f"— this port is commonly used by hacking tools and remote access trojans"
                )
            else:
                self._emit(
                    "ALLOW", "Network",
                    f"OUTBOUND — Connected to {rip}:{rport}"
                )

            # Trim to avoid unbounded growth
            if len(self._known_conns) > self.NET_SEEN_MAX:
                self._known_conns = set(list(self._known_conns)[-(self.NET_SEEN_MAX // 2):])
