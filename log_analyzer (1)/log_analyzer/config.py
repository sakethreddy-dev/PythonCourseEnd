"""
Settings for the System Log Intelligence Analyzer.

>>> The only thing you MUST change is DB_PASSWORD (your MySQL root password). <<<

You can also set environment variables (DB_HOST, DB_USER, DB_PASSWORD ...)
instead of editing this file.
"""
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# --- MySQL connection ------------------------------------------------
DB_CONFIG = {
    "host": os.getenv("DB_HOST", "localhost"),
    "port": int(os.getenv("DB_PORT", "3306")),
    "user": os.getenv("DB_USER", "root"),
    "password": os.getenv("DB_PASSWORD", "root"),   # <-- CHANGE ME
}
DB_NAME = os.getenv("DB_NAME", "log_analyzer")

# --- Flask / upload settings -----------------------------------------
SECRET_KEY = os.getenv("SECRET_KEY", "college-project-secret-change-me")
MAX_UPLOAD_MB = 10
ALLOWED_EXTENSIONS = {".txt", ".log"}
RECORDS_PER_PAGE = 20

# Max rejected lines stored per file (so a garbage file cannot fill the DB)
MAX_REJECTED_STORED = 500

# NOTE: Investigation THRESHOLDS are NOT here. They live in the MySQL table
# `detection_rules` (defaults are in schema.sql) and can be edited on the
# website's "Rules" page.
