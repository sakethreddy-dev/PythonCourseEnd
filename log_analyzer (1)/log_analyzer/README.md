# System Log Intelligence Analyzer

A Flask + MySQL website that reads system log files, extracts events with regular
expressions, stores them in MySQL, detects repeated login failures and frequent errors,
and shows everything on a blue-and-white security dashboard.

> **Important:** the "suspicious" and "needs investigation" labels are **rule-based
> indicators** (counts compared with thresholds). They are **not proof of a cyberattack**.

---

## 1. Run it (about 10 minutes)

**Prerequisites:** Python 3.9+, MySQL Server running, MySQL Workbench (optional but handy).

```bash
cd log_analyzer
pip install -r requirements.txt
```

1. Open `config.py` and set `DB_PASSWORD` to your MySQL root password
   (change `DB_USER` too if you don't use `root`).
2. Create the database + tables - **either** way works, and neither assumes anything exists:
   * `python init_db.py` - checks whether the database and each table exist, creates what is
     missing and prints what it did, **or**
   * In Workbench: *File → Open SQL Script → `schema.sql` → run (⚡)*.
3. Start the site: `python app.py`  (it also runs the same check on startup)
4. Open **http://127.0.0.1:5000**
5. Go to **Upload Logs**, download the two sample files from that page, and upload
   `sample_auth.log` and then `sample_app.log` with year **2026**.
6. Look at the Dashboard and Log Records pages.

Optional: `sample_data.sql` inserts 17 hand-written rows if you want data without uploading.

**Windows tip:** if `pip` is not found use `py -m pip install -r requirements.txt` and `py app.py`.

### What you should see with the two sample files
| Item | Expected |
|---|---|
| Records saved | 206 (100 from auth + 106 from app) |
| Rejected lines | 12 (6 per file) - listed with reasons on the import page |
| Suspicious IPs | `203.0.113.45` (18 + 8 failures, then a successful login), `198.51.100.77` (7), `192.0.2.88` (5) |
| Frequent errors | DB connection timeout (9), disk I/O error (5), payment gateway 502 (3) |
| Critical event | "Kernel panic" flagged |
| Upload same file again | Blocked: "already imported" |

(If your numbers differ slightly, that's fine - they are always computed from the database.)

---

## 2. Project structure

```
log_analyzer/
├── app.py                 Flask routes: dashboard, records, upload, rules
├── analysis.py            Detection rules (SQL) + dashboard/records queries
├── log_parser.py          Regex parser: lines -> structured events
├── db.py                  MySQL helpers + ensure_schema() (checks DB/tables first)
├── config.py              DB password, upload limits
├── init_db.py             One-off "create database and tables" script
├── schema.sql             Full schema (also runnable in Workbench)
├── sample_data.sql        Optional demo rows
├── sql_demo_queries.sql   15 annotated queries for your viva
├── generate_sample_logs.py  Re-creates the sample logs
├── sample_logs/           sample_auth.log, sample_app.log
├── templates/             HTML (Jinja2)
└── static/style.css       Blue/white theme + pure-CSS charts
```

## 3. How a file is processed

1. **Upload** - extension must be `.log`/`.txt`, size ≤ 10 MB.
2. **Whole-file duplicate check** - SHA-256 of the bytes; if it's already in `log_files`, nothing is imported.
3. **Parse each line** (`log_parser.py`):
   * `Oct 21 03:12:44 server sshd[2211]: Failed password for root from 203.0.113.45 port 52344 ssh2` (syslog; year comes from the upload form)
   * `2026-10-21 10:15:02 ERROR db: Database connection timeout after 30s` (ISO)
   * The message is matched against login patterns (`Accepted password…`, `Failed password…`, `Login failed for user '…'`, …) to get **username**, **IP** and **event type**; everything else becomes `SYSTEM_ERROR`, `SYSTEM_WARNING` or `SYSTEM_INFO` from the log level or keywords.
4. **Bad lines never crash the import.** A line is *rejected* (with a reason) if it matches no format, has an impossible date (`Feb 30`, `03:99:12`), or an invalid IP (`999.10.10.10`). Blank lines are skipped silently.
5. **Save** events with `INSERT IGNORE` (see duplicates below), store rejected lines, update counts.
6. **Re-run the analysis** - rebuild `investigation_flags` from the rules.
7. Show a result page: lines in file / saved / rejected / duplicates skipped.

## 4. Database tables

| Table | Purpose |
|---|---|
| `log_files` | One row per upload (name, SHA-256, line counts). `UNIQUE(file_sha256)` blocks re-uploading the same file. |
| `event_types` | Lookup: `LOGIN_SUCCESS`, `LOGIN_FAILED`, `SYSTEM_ERROR`, `SYSTEM_WARNING`, `SYSTEM_INFO`, each with a category (`AUTHENTICATION` / `SYSTEM`). |
| `log_events` | **Main table** - one row per parsed event (time, user, IP, service, severity, message, `error_signature`, `event_hash`). Indexed on time, IP, username, (type, time) and signature. |
| `rejected_lines` | Lines the parser refused, with line number and reason. |
| `detection_rules` | The 5 rules and their **thresholds** (editable on the Rules page). |
| `investigation_flags` | Which event was flagged by which rule and why. Rebuilt after each import/threshold change. |

Relationships: `log_events.file_id → log_files` (cascade delete), `log_events.type_id → event_types`,
`investigation_flags.event_id → log_events` (cascade), `investigation_flags.rule_code → detection_rules`,
`rejected_lines.file_id → log_files` (cascade).

SQL examples (SELECT, WHERE, INSERT, UPDATE, DELETE, GROUP BY/HAVING, aggregates, JOIN, LEFT JOIN, subquery,
EXPLAIN) are in **`sql_demo_queries.sql`**.

## 5. Preventing duplicate imports (two layers)

1. **File level:** `log_files.file_sha256` is `UNIQUE`; the same file is refused up front.
2. **Line level:** every event gets `event_hash = SHA-256(timestamp | raw line | occurrence number)` and
   `log_events.event_hash` is `UNIQUE`. Events are inserted with `INSERT IGNORE`, so a line that already
   exists (e.g. from an overlapping export) is silently skipped and counted under "duplicates".
   The *occurrence number* keeps two genuinely identical lines **inside one file** (two failures in the same second).

Limit: a single changed character in a line makes it a "new" line. That is the intended trade-off.

## 6. Detection rules and thresholds

Defaults live in `schema.sql` and can be edited on the **Rules** page (saving re-applies them).

| Rule | Default | Flags |
|---|---|---|
| `IP_FAILURES` | ≥ 5 | every failed login from an IP with ≥ 5 failures |
| `USER_FAILURES` | ≥ 5 | every failed login for an account with ≥ 5 failures |
| `SUCCESS_AFTER_FAILURES` | ≥ 5 | successful logins from an IP that has ≥ 5 failures |
| `FREQUENT_ERROR` | ≥ 3 | errors whose pattern (digits ignored) occurs ≥ 3 times |
| `CRITICAL_EVENT` | - | any CRITICAL/FATAL event |

Error patterns come from `error_signature`: `Disk I/O error on /dev/sda1 sector 8812` and
`... sector 90112` both become `kernel: disk i/o error on /dev/sdaN sector N` so they group together.

**Honest limitations (good to say in your viva):** rules count totals, not time windows
(a real tool would use "5 failures within 10 minutes"); IPv4 only; shared NAT/office IPs can look suspicious;
attackers using many IPs are not correlated. Extend `RULE_SQL` in `analysis.py` to add rules.

## 7. Everything is calculated, nothing is hard-coded

Every number on the dashboard comes from a query in `analysis.py` (`dashboard_data`) against MySQL.
Empty database → the dashboard says "No log records yet". Charts are plain HTML/CSS so no internet or
JavaScript library is needed.

## 8. Troubleshooting

| Problem | Fix |
|---|---|
| "Access denied for user" | Wrong `DB_PASSWORD`/`DB_USER` in `config.py`. |
| "Can't connect to MySQL server" | Start MySQL (Windows: Services → MySQL80). |
| `ModuleNotFoundError: mysql` | `pip install -r requirements.txt`. |
| "Authentication plugin caching_sha2_password" | `pip install --upgrade mysql-connector-python`. |
| All lines rejected | Wrong format - compare with the two formats above; set the right year. |

## 9. Viva cheat-sheet

* **Why Flask?** Small, readable, one file per concern; good for learning.
* **Why a lookup table `event_types`?** Normalisation + JOIN; avoids repeating strings and typos.
* **How do you avoid SQL injection?** All queries use `%s` placeholders; LIKE input is escaped.
* **Why `INSERT IGNORE` + UNIQUE hash?** The database itself enforces "no duplicates", even under concurrent uploads.
* **Is "suspicious" the same as "attack"?** No - threshold indicators for a human to review.
* **Where would you improve it?** Time windows, IPv6, GeoIP, user login, background processing for huge files.
