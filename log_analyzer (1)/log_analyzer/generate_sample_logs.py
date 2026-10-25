"""
Creates the two sample log files in sample_logs/ (deterministic, so you always
get the same demo data).   Run:  python generate_sample_logs.py

All IP addresses come from the documentation ranges (RFC 5737) and private
ranges, so they are safe fictional examples.
"""
import os
import random
from datetime import datetime, timedelta

rng = random.Random(42)
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sample_logs")
os.makedirs(OUT, exist_ok=True)

START = datetime(2026, 10, 18)
USERS = ["alice", "bob", "carol", "dave", "erin"]
INTERNAL = ["10.0.0.5", "10.0.0.9", "10.0.0.12", "10.0.0.21", "192.168.1.14"]


def sys_ts(dt):                      # "Oct 21 03:12:44"
    return f"{dt.strftime('%b')} {dt.day:2d} {dt.strftime('%H:%M:%S')}".replace("  ", " ")


def iso_ts(dt):
    return dt.strftime("%Y-%m-%d %H:%M:%S")


# =====================================================================
# sample_auth.log  (syslog / sshd style)
# =====================================================================
auth = []   # (datetime, text)


def ssh(dt, text, pid=None):
    pid = pid or rng.randint(1000, 9999)
    auth.append((dt, f"{sys_ts(dt)} server sshd[{pid}]: {text}"))


for day in range(6):                                  # normal working-hours logins
    for _ in range(rng.randint(8, 12)):
        dt = START + timedelta(days=day, hours=rng.randint(8, 17),
                               minutes=rng.randint(0, 59), seconds=rng.randint(0, 59))
        user, ip = rng.choice(USERS), rng.choice(INTERNAL)
        ssh(dt, f"Accepted password for {user} from {ip} port {rng.randint(40000, 60000)} ssh2")

for dt_off, user, ip in [(1, "bob", "10.0.0.9"), (2, "dave", "10.0.0.21"),     # harmless typos
                         (3, "erin", "192.168.1.14"), (4, "alice", "10.0.0.5"),
                         (4, "alice", "10.0.0.5")]:
    dt = START + timedelta(days=dt_off, hours=9, minutes=rng.randint(0, 59), seconds=rng.randint(0, 59))
    ssh(dt, f"Failed password for {user} from {ip} port {rng.randint(40000, 60000)} ssh2")

# Scenario 1: brute-force style burst, then a success from the same IP
attacker = "203.0.113.45"
t = START + timedelta(days=3, hours=3, minutes=12)
for user in ["root", "admin", "oracle", "test", "ubuntu", "root", "admin", "postgres", "root",
             "admin", "guest", "root", "admin", "user", "root", "admin", "root", "admin"]:
    t += timedelta(seconds=rng.randint(2, 9))
    prefix = "invalid user " if user in ("oracle", "test", "guest", "user", "postgres") else ""
    ssh(t, f"Failed password for {prefix}{user} from {attacker} port {rng.randint(40000, 60000)} ssh2")
t += timedelta(seconds=15)
ssh(t, f"Accepted password for admin from {attacker} port 51022 ssh2")

# Scenario 2: slow guessing of one account from another IP
t = START + timedelta(days=4, hours=14, minutes=5)
for _ in range(7):
    t += timedelta(minutes=rng.randint(1, 4))
    ssh(t, f"Failed password for root from 198.51.100.77 port {rng.randint(40000, 60000)} ssh2")

# Scenario 3: password guessing against a real user
t = START + timedelta(days=5, hours=22, minutes=40)
for _ in range(5):
    t += timedelta(seconds=rng.randint(20, 90))
    ssh(t, f"Failed password for carol from 192.0.2.88 port {rng.randint(40000, 60000)} ssh2")

auth.append((START + timedelta(hours=7), f"{sys_ts(START + timedelta(hours=7))} server sshd[812]: Server listening on 0.0.0.0 port 22."))
auth.append((START + timedelta(days=2, hours=1), f"{sys_ts(START + timedelta(days=2, hours=1))} server sshd[812]: Received signal 15; terminating."))
auth.append((START + timedelta(days=2, hours=1, minutes=1), f"{sys_ts(START + timedelta(days=2, hours=1, minutes=1))} server sshd[955]: Server listening on 0.0.0.0 port 22."))
auth.append((START + timedelta(days=4, hours=11), f"{sys_ts(START + timedelta(days=4, hours=11))} server sshd[2480]: error: maximum authentication attempts exceeded for root from 198.51.100.77 port 40111 ssh2"))
auth.sort(key=lambda x: x[0])
auth_lines = [text for _, text in auth]

# malformed lines inserted at fixed positions (parser must reject, not crash)
bad_auth = [
    "######## rotated by logrotate ########",
    "Oct 21 03:99:12 server sshd[2211]: Failed password for root from 203.0.113.45 port 22 ssh2",
    "Oct 21 04:00:00 server sshd[2211]: Failed password for root from 999.10.10.10 port 22 ssh2",
    "Oct 32 10:00:00 server sshd[1]: Accepted password for bob from 10.0.0.9 port 22 ssh2",
    "Oct 21 04:00",
    "",
    "this line is not a log entry at all",
]
for i, line in enumerate(bad_auth):
    auth_lines.insert(10 + i * 17, line)

with open(os.path.join(OUT, "sample_auth.log"), "w", encoding="utf-8") as fh:
    fh.write("\n".join(auth_lines) + "\n")

# =====================================================================
# sample_app.log  (ISO timestamp application log)
# =====================================================================
app = []


def log(dt, level, svc, msg):
    app.append((dt, f"{iso_ts(dt)} {level:<5} {svc}: {msg}"))


for day in range(6):
    base = START + timedelta(days=day)
    log(base + timedelta(hours=6), "INFO", "app", "Application started, version 2.4.1")
    for _ in range(rng.randint(5, 9)):
        dt = base + timedelta(hours=rng.randint(8, 17), minutes=rng.randint(0, 59), seconds=rng.randint(0, 59))
        user, ip = rng.choice(USERS), rng.choice(INTERNAL)
        log(dt, "INFO", "auth", f"User '{user}' login successful from {ip}")
    for _ in range(rng.randint(2, 4)):
        dt = base + timedelta(hours=rng.randint(8, 17), minutes=rng.randint(0, 59), seconds=rng.randint(0, 59))
        log(dt, "INFO", "web", f"GET /reports/{rng.randint(100, 999)} completed in {rng.randint(40, 900)}ms")

# repeated web-login failures from the same attacker IP as in the auth log
t = START + timedelta(days=3, hours=3, minutes=30)
for user in ["admin", "admin", "root", "manager", "admin", "support", "admin", "root"]:
    t += timedelta(seconds=rng.randint(3, 12))
    log(t, "WARN", "auth", f"Login failed for user '{user}' from 203.0.113.45")

for _ in range(4):
    dt = START + timedelta(days=rng.randint(1, 5), hours=rng.randint(8, 17), minutes=rng.randint(0, 59))
    log(dt, "WARN", "auth", f"Login failed for user '{rng.choice(['bob', 'dave'])}' from {rng.choice(INTERNAL)}")

for _ in range(9):                                     # frequent error #1
    dt = START + timedelta(days=rng.randint(0, 5), hours=rng.randint(0, 23), minutes=rng.randint(0, 59))
    log(dt, "ERROR", "db", f"Database connection timeout after {rng.choice([30, 30, 45, 60])}s (host=db01, attempt {rng.randint(1, 5)})")
for _ in range(5):                                     # frequent error #2
    dt = START + timedelta(days=rng.randint(0, 5), hours=rng.randint(0, 23), minutes=rng.randint(0, 59))
    log(dt, "ERROR", "kernel", f"Disk I/O error on /dev/sda1 sector {rng.randint(1000, 99999)}")
for _ in range(3):                                     # frequent error #3
    dt = START + timedelta(days=rng.randint(2, 5), hours=rng.randint(9, 18), minutes=rng.randint(0, 59))
    log(dt, "ERROR", "payment", f"Payment gateway returned HTTP 502 for order {rng.randint(10000, 99999)}")
for _ in range(2):                                     # below the threshold
    dt = START + timedelta(days=rng.randint(0, 5), hours=rng.randint(9, 18), minutes=rng.randint(0, 59))
    log(dt, "ERROR", "mail", f"Failed to send notification email to user id={rng.randint(1, 500)}")
for _ in range(4):
    dt = START + timedelta(days=rng.randint(0, 5), hours=rng.randint(0, 23), minutes=rng.randint(0, 59))
    log(dt, "WARN", "disk", f"Disk usage at {rng.randint(86, 95)}% on /var")
log(START + timedelta(days=4, hours=2, minutes=17), "CRITICAL", "kernel", "Kernel panic - not syncing: Out of memory")
app.sort(key=lambda x: x[0])
app_lines = [text for _, text in app]

bad_app = [
    "ERROR???",
    "2026-13-45 99:99:99 ERROR app: impossible date",
    "2026-10-20 10:00:00 INFO something without a service colon",
    "2026-10-20 10:01:00 ERROR app:",
    "Traceback (most recent call last):",
    "   File \"worker.py\", line 88, in run",
]
for i, line in enumerate(bad_app):
    app_lines.insert(15 + i * 11, line)

with open(os.path.join(OUT, "sample_app.log"), "w", encoding="utf-8") as fh:
    fh.write("\n".join(app_lines) + "\n")

print(f"sample_auth.log: {len(auth_lines)} lines   sample_app.log: {len(app_lines)} lines")
