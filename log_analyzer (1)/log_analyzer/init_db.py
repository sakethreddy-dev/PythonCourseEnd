"""
Run this once:   python init_db.py

It checks whether the MySQL database and tables exist, creates whatever is
missing, and tells you what it did. (You can instead run schema.sql in
MySQL Workbench - the result is identical.)
"""
import sys

import mysql.connector

from db import ensure_schema

if __name__ == "__main__":
    try:
        for line in ensure_schema():
            print(" -", line)
        print("Database is ready.")
    except mysql.connector.Error as exc:
        print("Could not set up MySQL:", exc)
        print("Check DB_USER / DB_PASSWORD in config.py and that MySQL is running.")
        sys.exit(1)
