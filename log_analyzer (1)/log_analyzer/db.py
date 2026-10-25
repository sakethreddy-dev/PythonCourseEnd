"""
Small database helper layer (MySQL via mysql-connector-python).

All SQL in this project uses %s placeholders (parameterised queries),
which protects against SQL injection.
"""
import os

import mysql.connector

from config import BASE_DIR, DB_CONFIG, DB_NAME

SCHEMA_FILE = os.path.join(BASE_DIR, "schema.sql")
EXPECTED_TABLES = (
    "log_files", "event_types", "log_events",
    "rejected_lines", "detection_rules", "investigation_flags",
)


def connect(use_db=True):
    """Open a new MySQL connection (optionally without selecting a database)."""
    cfg = dict(DB_CONFIG)
    if use_db:
        cfg["database"] = DB_NAME
    cfg["charset"] = "utf8mb4"
    cfg["autocommit"] = False
    return mysql.connector.connect(**cfg)


def fetch_all(conn, sql, params=None):
    """Run a SELECT and return a list of dicts."""
    cur = conn.cursor(dictionary=True)
    try:
        cur.execute(sql, params or ())
        return cur.fetchall()
    finally:
        cur.close()


def fetch_one(conn, sql, params=None):
    rows = fetch_all(conn, sql, params)
    return rows[0] if rows else None


def execute(conn, sql, params=None):
    """Run INSERT/UPDATE/DELETE. Returns (rows_affected, last_insert_id)."""
    cur = conn.cursor()
    try:
        cur.execute(sql, params or ())
        return cur.rowcount, cur.lastrowid
    finally:
        cur.close()


def execute_many(conn, sql, rows):
    """Bulk insert. Returns total rows actually affected."""
    if not rows:
        return 0
    cur = conn.cursor()
    try:
        cur.executemany(sql, rows)
        return cur.rowcount
    finally:
        cur.close()


def _load_statements(path):
    """Read schema.sql and split into single statements."""
    with open(path, encoding="utf-8") as fh:
        lines = [ln for ln in fh.read().splitlines() if not ln.strip().startswith("--")]
    statements = [s.strip() for s in "\n".join(lines).split(";")]
    return [s for s in statements if s]


def ensure_schema():
    """
    Make sure the database and all tables exist. NEVER assumes they do:
      1. connect to the MySQL server (no database selected)
      2. check SHOW DATABASES -> CREATE DATABASE only if missing
      3. check information_schema for the tables
      4. run schema.sql (idempotent) to create whatever is missing
    Returns a list of human-readable status messages.
    """
    messages = []
    conn = connect(use_db=False)
    try:
        cur = conn.cursor()
        cur.execute("SHOW DATABASES LIKE %s", (DB_NAME,))
        if cur.fetchone():
            messages.append(f"Database '{DB_NAME}' already exists.")
        else:
            cur.execute(
                f"CREATE DATABASE `{DB_NAME}` "
                "CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci"
            )
            messages.append(f"Database '{DB_NAME}' did not exist - created it.")
        cur.execute(f"USE `{DB_NAME}`")

        placeholders = ", ".join(["%s"] * len(EXPECTED_TABLES))
        cur.execute(
            "SELECT table_name FROM information_schema.tables "
            f"WHERE table_schema = %s AND table_name IN ({placeholders})",
            (DB_NAME, *EXPECTED_TABLES),
        )
        present = {row[0] for row in cur.fetchall()}
        missing = [t for t in EXPECTED_TABLES if t not in present]
        if missing:
            messages.append("Missing tables: " + ", ".join(missing) + " - creating them.")
        else:
            messages.append("All 6 tables already exist.")

        for stmt in _load_statements(SCHEMA_FILE):
            head = stmt.upper()
            # The database name comes from config.py, so skip these two here.
            if head.startswith("CREATE DATABASE") or head.startswith("USE "):
                continue
            cur.execute(stmt)
        conn.commit()
        if missing:
            messages.append("Schema created and reference data inserted.")
        cur.close()
    finally:
        conn.close()
    return messages
