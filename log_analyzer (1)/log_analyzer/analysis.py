"""
Security analysis + all dashboard / records queries.

IMPORTANT: everything here is a RULE-BASED INDICATOR calculated from the
rows stored in MySQL. It is NOT proof of a cyberattack. A flagged event only
means "a human should look at this".
"""
from datetime import datetime

from db import execute, fetch_all, fetch_one

# ---------------------------------------------------------------------
# Detection rules. Each is one INSERT ... SELECT run against log_events.
# %(th)s is the threshold stored in the detection_rules table.
# ---------------------------------------------------------------------
_FAILED_IPS = """
    SELECT ev.ip_address, COUNT(*) AS cnt
    FROM log_events ev
    JOIN event_types et ON et.type_id = ev.type_id
    WHERE et.type_code = 'LOGIN_FAILED' AND ev.ip_address IS NOT NULL
    GROUP BY ev.ip_address
    HAVING COUNT(*) >= %(th)s
"""

RULE_SQL = {
    "IP_FAILURES": f"""
        INSERT IGNORE INTO investigation_flags (event_id, rule_code, reason)
        SELECT e.event_id, 'IP_FAILURES',
               CONCAT('IP ', e.ip_address, ' has ', x.cnt, ' failed logins')
        FROM log_events e
        JOIN event_types t ON t.type_id = e.type_id AND t.type_code = 'LOGIN_FAILED'
        JOIN ({_FAILED_IPS}) x ON x.ip_address = e.ip_address
    """,
    "USER_FAILURES": """
        INSERT IGNORE INTO investigation_flags (event_id, rule_code, reason)
        SELECT e.event_id, 'USER_FAILURES',
               CONCAT('Account ', e.username, ' has ', x.cnt, ' failed logins')
        FROM log_events e
        JOIN event_types t ON t.type_id = e.type_id AND t.type_code = 'LOGIN_FAILED'
        JOIN (
            SELECT ev.username, COUNT(*) AS cnt
            FROM log_events ev
            JOIN event_types et ON et.type_id = ev.type_id
            WHERE et.type_code = 'LOGIN_FAILED' AND ev.username IS NOT NULL
            GROUP BY ev.username
            HAVING COUNT(*) >= %(th)s
        ) x ON x.username = e.username
    """,
    "SUCCESS_AFTER_FAILURES": f"""
        INSERT IGNORE INTO investigation_flags (event_id, rule_code, reason)
        SELECT e.event_id, 'SUCCESS_AFTER_FAILURES',
               CONCAT('Successful login from IP ', e.ip_address,
                      ' which has ', x.cnt, ' failed logins')
        FROM log_events e
        JOIN event_types t ON t.type_id = e.type_id AND t.type_code = 'LOGIN_SUCCESS'
        JOIN ({_FAILED_IPS}) x ON x.ip_address = e.ip_address
    """,
    "FREQUENT_ERROR": """
        INSERT IGNORE INTO investigation_flags (event_id, rule_code, reason)
        SELECT e.event_id, 'FREQUENT_ERROR',
               CONCAT('Same error pattern seen ', x.cnt, ' times')
        FROM log_events e
        JOIN event_types t ON t.type_id = e.type_id AND t.type_code = 'SYSTEM_ERROR'
        JOIN (
            SELECT error_signature, COUNT(*) AS cnt
            FROM log_events
            WHERE error_signature IS NOT NULL
            GROUP BY error_signature
            HAVING COUNT(*) >= %(th)s
        ) x ON x.error_signature = e.error_signature
    """,
    "CRITICAL_EVENT": """
        INSERT IGNORE INTO investigation_flags (event_id, rule_code, reason)
        SELECT e.event_id, 'CRITICAL_EVENT', 'Event logged with CRITICAL severity'
        FROM log_events e
        WHERE e.severity = 'CRITICAL'
    """,
}


def get_rules(conn):
    return fetch_all(conn, "SELECT * FROM detection_rules ORDER BY rule_code")


def get_threshold(conn, code, default):
    row = fetch_one(conn, "SELECT threshold FROM detection_rules WHERE rule_code = %s", (code,))
    return int(row["threshold"]) if row else default


def recompute_flags(conn):
    """Rebuild investigation_flags from the current data + thresholds."""
    execute(conn, "DELETE FROM investigation_flags")
    for rule in get_rules(conn):
        if not rule["enabled"]:
            continue
        sql = RULE_SQL.get(rule["rule_code"])
        if sql:
            execute(conn, sql, {"th": int(rule["threshold"])})
    conn.commit()
    row = fetch_one(conn, "SELECT COUNT(DISTINCT event_id) AS n FROM investigation_flags")
    return int(row["n"])


# ---------------------------------------------------------------------
# Shared SELECT used by the dashboard and the records page
# ---------------------------------------------------------------------
EVENT_SELECT = """
    SELECT e.event_id, e.event_time, e.username, e.ip_address, e.service,
           e.severity, e.message, t.type_code, t.category,
           (SELECT GROUP_CONCAT(f.rule_code ORDER BY f.rule_code SEPARATOR ', ')
              FROM investigation_flags f WHERE f.event_id = e.event_id) AS flag_rules,
           (SELECT GROUP_CONCAT(f.reason ORDER BY f.rule_code SEPARATOR ' | ')
              FROM investigation_flags f WHERE f.event_id = e.event_id) AS flag_reasons
    FROM log_events e
    JOIN event_types t ON t.type_id = e.type_id
"""


def dashboard_data(conn):
    d = {}

    # --- headline numbers (aggregate functions + JOIN) ------------------
    s = fetch_one(conn, """
        SELECT COUNT(*) AS total,
               COALESCE(SUM(t.type_code = 'LOGIN_SUCCESS'), 0) AS success,
               COALESCE(SUM(t.type_code = 'LOGIN_FAILED'), 0)  AS failed,
               COALESCE(SUM(t.type_code = 'SYSTEM_ERROR'), 0)  AS errors,
               COALESCE(SUM(t.type_code = 'SYSTEM_WARNING'), 0) AS warnings,
               MIN(e.event_time) AS first_time, MAX(e.event_time) AS last_time
        FROM log_events e JOIN event_types t ON t.type_id = e.type_id
    """)
    d["stats"] = {k: (int(v) if k not in ("first_time", "last_time") and v is not None else v)
                  for k, v in s.items()}
    d["flagged_events"] = int(fetch_one(
        conn, "SELECT COUNT(DISTINCT event_id) AS n FROM investigation_flags")["n"])

    ip_th = get_threshold(conn, "IP_FAILURES", 5)
    err_th = get_threshold(conn, "FREQUENT_ERROR", 3)
    d["ip_threshold"], d["error_threshold"] = ip_th, err_th

    # --- suspicious IPs (GROUP BY + HAVING + correlated subquery) -------
    d["suspicious_ips"] = fetch_all(conn, """
        SELECT e.ip_address,
               COUNT(*) AS failures,
               COUNT(DISTINCT e.username) AS usernames_tried,
               MIN(e.event_time) AS first_seen,
               MAX(e.event_time) AS last_seen,
               (SELECT COUNT(*) FROM log_events s
                  JOIN event_types st ON st.type_id = s.type_id
                 WHERE st.type_code = 'LOGIN_SUCCESS'
                   AND s.ip_address = e.ip_address) AS successes
        FROM log_events e
        JOIN event_types t ON t.type_id = e.type_id
        WHERE t.type_code = 'LOGIN_FAILED' AND e.ip_address IS NOT NULL
        GROUP BY e.ip_address
        HAVING COUNT(*) >= %s
        ORDER BY failures DESC, last_seen DESC
        LIMIT 10
    """, (ip_th,))

    # --- accounts with repeated failures --------------------------------
    user_th = get_threshold(conn, "USER_FAILURES", 5)
    d["user_threshold"] = user_th
    d["failing_users"] = fetch_all(conn, """
        SELECT e.username, COUNT(*) AS failures,
               COUNT(DISTINCT e.ip_address) AS ips, MAX(e.event_time) AS last_seen
        FROM log_events e JOIN event_types t ON t.type_id = e.type_id
        WHERE t.type_code = 'LOGIN_FAILED' AND e.username IS NOT NULL
        GROUP BY e.username
        HAVING COUNT(*) >= %s
        ORDER BY failures DESC LIMIT 8
    """, (user_th,))

    # --- frequently occurring errors ------------------------------------
    d["frequent_errors"] = fetch_all(conn, """
        SELECT e.error_signature, COUNT(*) AS occurrences,
               MIN(e.event_time) AS first_seen, MAX(e.event_time) AS last_seen,
               MIN(e.message) AS example, MAX(e.severity) AS severity
        FROM log_events e
        WHERE e.error_signature IS NOT NULL
        GROUP BY e.error_signature
        ORDER BY occurrences DESC, last_seen DESC
        LIMIT 8
    """)

    # --- investigation summary by rule (LEFT JOIN) -----------------------
    d["rule_summary"] = fetch_all(conn, """
        SELECT r.rule_code, r.title, r.threshold, r.enabled,
               COUNT(f.flag_id) AS flagged
        FROM detection_rules r
        LEFT JOIN investigation_flags f ON f.rule_code = r.rule_code
        GROUP BY r.rule_code, r.title, r.threshold, r.enabled
        ORDER BY flagged DESC, r.rule_code
    """)

    d["flagged_recent"] = fetch_all(conn, EVENT_SELECT + """
        WHERE EXISTS (SELECT 1 FROM investigation_flags f WHERE f.event_id = e.event_id)
        ORDER BY e.event_time DESC, e.event_id DESC LIMIT 10
    """)
    d["recent"] = fetch_all(conn, EVENT_SELECT + """
        ORDER BY e.event_time DESC, e.event_id DESC LIMIT 10
    """)

    # --- daily activity for the chart ------------------------------------
    daily = fetch_all(conn, """
        SELECT DATE(e.event_time) AS day,
               SUM(t.type_code = 'LOGIN_SUCCESS') AS success,
               SUM(t.type_code = 'LOGIN_FAILED')  AS failed,
               SUM(t.type_code = 'SYSTEM_ERROR')  AS errors
        FROM log_events e JOIN event_types t ON t.type_id = e.type_id
        GROUP BY DATE(e.event_time)
        ORDER BY day DESC LIMIT 14
    """)
    daily.reverse()
    d["daily"] = [{"day": r["day"].strftime("%d %b"), "success": int(r["success"]),
                   "failed": int(r["failed"]), "errors": int(r["errors"])} for r in daily]

    d["imports"] = fetch_all(conn, """
        SELECT file_id, original_name, uploaded_at, parsed_lines, rejected_lines
        FROM log_files ORDER BY file_id DESC LIMIT 5
    """)
    return d


# ---------------------------------------------------------------------
# Records page: search + filters + pagination, all done in MySQL
# ---------------------------------------------------------------------
def _like(text):
    """Escape LIKE wildcards in user input and wrap with %...%."""
    text = text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{text}%"


def _valid_date(text):
    try:
        datetime.strptime(text, "%Y-%m-%d")
        return text
    except (TypeError, ValueError):
        return None


def search_records(conn, args, page, per_page):
    where, params = [], []

    q = (args.get("q") or "").strip()
    if q:
        where.append("(e.username LIKE %s OR e.ip_address LIKE %s "
                     "OR e.message LIKE %s OR e.service LIKE %s)")
        params += [_like(q)] * 4
    if args.get("event_type"):
        where.append("t.type_code = %s")
        params.append(args["event_type"])
    if args.get("category"):
        where.append("t.category = %s")
        params.append(args["category"])
    if args.get("severity"):
        where.append("e.severity = %s")
        params.append(args["severity"])
    ip = (args.get("ip") or "").strip()
    if ip:
        where.append("e.ip_address LIKE %s")
        params.append(_like(ip))
    user = (args.get("username") or "").strip()
    if user:
        where.append("e.username LIKE %s")
        params.append(_like(user))
    df, dt = _valid_date(args.get("date_from")), _valid_date(args.get("date_to"))
    if df:
        where.append("e.event_time >= %s")
        params.append(df)
    if dt:
        where.append("e.event_time < DATE_ADD(%s, INTERVAL 1 DAY)")
        params.append(dt)
    status = args.get("status")
    if status == "flagged":
        where.append("EXISTS (SELECT 1 FROM investigation_flags f WHERE f.event_id = e.event_id)")
    elif status == "clean":
        where.append("NOT EXISTS (SELECT 1 FROM investigation_flags f WHERE f.event_id = e.event_id)")
    if args.get("file_id", "").isdigit():
        where.append("e.file_id = %s")
        params.append(int(args["file_id"]))

    clause = (" WHERE " + " AND ".join(where)) if where else ""

    total = int(fetch_one(conn, """
        SELECT COUNT(*) AS n FROM log_events e
        JOIN event_types t ON t.type_id = e.type_id""" + clause, params)["n"])
    pages = max(1, -(-total // per_page))
    page = min(max(page, 1), pages)
    rows = fetch_all(
        conn,
        EVENT_SELECT + clause + " ORDER BY e.event_time DESC, e.event_id DESC LIMIT %s OFFSET %s",
        params + [per_page, (page - 1) * per_page],
    )
    return {"rows": rows, "total": total, "page": page, "pages": pages}
