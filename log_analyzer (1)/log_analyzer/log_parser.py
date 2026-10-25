"""
Log parser - turns raw text lines into structured events using regular expressions.

Two log styles are understood:

 1. Syslog / sshd style (no year in the file, so the year is supplied):
      Oct 21 03:12:44 server sshd[2211]: Failed password for root from 203.0.113.45 port 52344 ssh2

 2. Application style (ISO timestamp + level + service):
      2026-10-21 10:15:02 ERROR db: Database connection timeout after 30s

Anything else is REJECTED (kept with a reason) - the parser never crashes on bad input.

NOTE: only IPv4 addresses are recognised (enough for this project).
"""
import hashlib
import ipaddress
import re
from collections import Counter
from datetime import datetime

IP = r"(?:\d{1,3}\.){3}\d{1,3}"

MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
     "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], start=1)}

# ---- line "envelope" patterns -------------------------------------------
ISO_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2})(?:[.,]\d+)?\s+"
    r"\[?(?P<level>DEBUG|INFO|NOTICE|WARN|WARNING|ERROR|CRITICAL|FATAL)\]?\s+"
    r"(?P<service>[\w.\-/]+)\s*:\s*(?P<msg>.+)$",
    re.IGNORECASE,
)

SYSLOG_RE = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<service>[^\s:\[]+)(?:\[\d+\])?:\s+(?P<msg>.+)$"
)

# ---- authentication message patterns ------------------------------------
AUTH_PATTERNS = [
    ("LOGIN_SUCCESS", re.compile(
        rf"Accepted (?:password|publickey|keyboard-interactive/pam) for "
        rf"(?P<user>\S+) from (?P<ip>{IP})", re.I)),
    ("LOGIN_SUCCESS", re.compile(
        rf"User '(?P<user>[^']+)' (?:logged in|login successful)"
        rf"(?: from (?P<ip>{IP}))?", re.I)),
    ("LOGIN_FAILED", re.compile(
        rf"Failed (?:password|publickey|keyboard-interactive/pam) for "
        rf"(?:invalid user )?(?P<user>\S+) from (?P<ip>{IP})", re.I)),
    ("LOGIN_FAILED", re.compile(
        rf"(?:Login|Authentication) failed for user '(?P<user>[^']+)'"
        rf"(?: from (?P<ip>{IP}))?", re.I)),
    ("LOGIN_FAILED", re.compile(
        rf"User '(?P<user>[^']+)' login failed(?: from (?P<ip>{IP}))?", re.I)),
]

# ---- keyword rules for lines that carry no explicit level (syslog) ------
CRITICAL_RE = re.compile(r"\b(kernel panic|panic|fatal|critical|emergency)\b", re.I)
ERROR_RE = re.compile(
    r"\b(error|failed|failure|segfault|exception|out of memory|oom|"
    r"timeout|timed out|denied|cannot|unable)\b", re.I)
WARNING_RE = re.compile(r"\b(warn|warning|deprecated|retry|low disk|high load)\b", re.I)

LEVEL_MAP = {
    "DEBUG": "INFO", "INFO": "INFO", "NOTICE": "INFO",
    "WARN": "WARNING", "WARNING": "WARNING",
    "ERROR": "ERROR", "CRITICAL": "CRITICAL", "FATAL": "CRITICAL",
}


class ParseError(Exception):
    """Raised for a line that cannot be turned into an event."""


def _guess_severity(msg):
    if CRITICAL_RE.search(msg):
        return "CRITICAL"
    if ERROR_RE.search(msg):
        return "ERROR"
    if WARNING_RE.search(msg):
        return "WARNING"
    return "INFO"


def make_signature(service, msg):
    """
    Turn an error message into a 'pattern' so similar errors group together:
    'Disk I/O error on /dev/sda1 sector 8812' -> 'disk i/o error on /dev/sdaN sector N'
    """
    s = msg.lower()
    s = re.sub(IP, "<ip>", s)
    s = re.sub(r"0x[0-9a-f]+", "N", s)
    s = re.sub(r"\d+", "N", s)
    s = re.sub(r"\s+", " ", s).strip()
    return f"{(service or 'unknown').lower()}: {s}"[:255]


def parse_line(line, default_year):
    """Parse ONE stripped, non-empty line -> event dict. Raises ParseError."""
    level = None
    m = ISO_RE.match(line)
    if m:
        try:
            event_time = datetime.strptime(m.group("ts").replace("T", " "), "%Y-%m-%d %H:%M:%S")
        except ValueError:
            raise ParseError("Invalid date/time")
        service, msg = m.group("service"), m.group("msg").strip()
        level = LEVEL_MAP[m.group("level").upper()]
    else:
        m = SYSLOG_RE.match(line)
        if not m:
            raise ParseError("Unrecognized log format")
        month = MONTHS.get(m.group("mon"))
        if month is None:
            raise ParseError("Invalid month name")
        try:
            h, mi, s = (int(x) for x in m.group("time").split(":"))
            event_time = datetime(default_year, month, int(m.group("day")), h, mi, s)
        except ValueError:
            raise ParseError("Invalid date/time")
        service, msg = m.group("service"), m.group("msg").strip()

    # --- classify the message -------------------------------------------
    type_code = user = ip = None
    severity = "INFO"
    for code, rx in AUTH_PATTERNS:
        hit = rx.search(msg)
        if hit:
            type_code = code
            groups = hit.groupdict()
            user, ip = groups.get("user"), groups.get("ip")
            severity = "INFO" if code == "LOGIN_SUCCESS" else "WARNING"
            break

    if type_code is None:
        severity = level or _guess_severity(msg)
        if severity in ("ERROR", "CRITICAL"):
            type_code = "SYSTEM_ERROR"
        elif severity == "WARNING":
            type_code = "SYSTEM_WARNING"
        else:
            type_code = "SYSTEM_INFO"

    if ip is not None:
        try:
            ipaddress.ip_address(ip)          # rejects things like 999.12.1.1
        except ValueError:
            raise ParseError("Invalid IP address")

    return {
        "event_time": event_time,
        "username": user[:64] if user else None,
        "ip_address": ip,
        "service": service[:64],
        "severity": severity,
        "type_code": type_code,
        "message": msg[:1000],
        "error_signature": make_signature(service, msg) if type_code == "SYSTEM_ERROR" else None,
    }


def parse_log(text, default_year):
    """
    Parse a whole file's text.

    Returns a dict:
      total_lines, blank_lines, events (list of dicts), rejected (list of dicts)

    Each event gets an `event_hash` = SHA-256 of (time | raw line | occurrence number).
    The occurrence number lets genuinely repeated identical lines in ONE file
    (e.g. two failures in the same second) be kept, while re-importing the same
    line from another file is still detected as a duplicate.
    """
    events, rejected = [], []
    seen = Counter()
    total = blank = 0
    for number, raw in enumerate(text.replace("\x00", "").splitlines(), start=1):
        total += 1
        line = raw.strip()
        if not line:
            blank += 1
            continue
        try:
            event = parse_line(line, default_year)
        except ParseError as exc:
            rejected.append({"line_number": number, "raw_line": line[:1000], "reason": str(exc)})
            continue
        except Exception as exc:                      # never crash on one bad line
            rejected.append({"line_number": number, "raw_line": line[:1000],
                             "reason": f"Unexpected error: {type(exc).__name__}"})
            continue
        key = (event["event_time"], line)
        seen[key] += 1
        digest = hashlib.sha256(
            f"{event['event_time'].isoformat()}|{line}|{seen[key]}".encode("utf-8")
        ).hexdigest()
        event["event_hash"] = digest
        event["line_number"] = number
        events.append(event)
    return {"total_lines": total, "blank_lines": blank, "events": events, "rejected": rejected}
