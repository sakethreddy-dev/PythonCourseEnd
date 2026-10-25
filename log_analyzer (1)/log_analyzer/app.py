"""
System Log Intelligence Analyzer - Flask web application.

Run:  python app.py      then open  http://127.0.0.1:5000
"""
import hashlib
import os
from datetime import datetime

import mysql.connector
from flask import (Flask, flash, g, redirect, render_template, request,
                   send_from_directory, url_for)
from werkzeug.utils import secure_filename

import analysis
import config
import db
from log_parser import parse_log

app = Flask(__name__)
app.config["SECRET_KEY"] = config.SECRET_KEY
app.config["MAX_CONTENT_LENGTH"] = config.MAX_UPLOAD_MB * 1024 * 1024

SAMPLE_DIR = os.path.join(config.BASE_DIR, "sample_logs")


# ---------------------------------------------------------------------
# One MySQL connection per request
# ---------------------------------------------------------------------
def get_conn():
    if "conn" not in g:
        g.conn = db.connect()
    return g.conn


@app.teardown_appcontext
def close_conn(_exc):
    conn = g.pop("conn", None)
    if conn is not None:
        conn.close()


@app.errorhandler(mysql.connector.Error)
def handle_db_error(exc):
    return render_template("error.html", title="Database problem", message=str(exc),
                           hint="Is MySQL running? Check DB_USER / DB_PASSWORD in config.py, "
                                "then run: python init_db.py"), 500


@app.errorhandler(413)
def too_large(_exc):
    flash(f"File is too large (limit {config.MAX_UPLOAD_MB} MB).", "danger")
    return redirect(url_for("upload"))


@app.template_filter("dt")
def fmt_dt(value):
    return value.strftime("%Y-%m-%d %H:%M:%S") if value else "-"


@app.context_processor
def helpers():
    def page_url(page):
        args = request.args.to_dict()
        args["page"] = page
        return url_for("records", **args)
    return {"page_url": page_url, "now_year": datetime.now().year}


# ---------------------------------------------------------------------
# Pages
# ---------------------------------------------------------------------
@app.route("/")
def dashboard():
    data = analysis.dashboard_data(get_conn())
    return render_template("dashboard.html", d=data)


@app.route("/records")
def records():
    conn = get_conn()
    page = request.args.get("page", "1")
    page = int(page) if page.isdigit() else 1
    result = analysis.search_records(conn, request.args, page, config.RECORDS_PER_PAGE)
    types = db.fetch_all(conn, "SELECT type_code FROM event_types ORDER BY type_id")
    return render_template("records.html", r=result, types=types, f=request.args)


@app.route("/upload", methods=["GET", "POST"])
def upload():
    conn = get_conn()
    if request.method == "POST":
        return handle_upload(conn)
    history = db.fetch_all(conn, """
        SELECT file_id, original_name, uploaded_at, total_lines, parsed_lines,
               rejected_lines, duplicate_events
        FROM log_files ORDER BY file_id DESC LIMIT 10""")
    return render_template("upload.html", history=history, year=datetime.now().year)


def handle_upload(conn):
    file = request.files.get("logfile")
    if not file or not file.filename:
        flash("Please choose a log file first.", "danger")
        return redirect(url_for("upload"))

    name = secure_filename(file.filename) or "uploaded.log"
    if os.path.splitext(name)[1].lower() not in config.ALLOWED_EXTENSIONS:
        flash("Only .txt and .log files are allowed.", "danger")
        return redirect(url_for("upload"))

    year_text = request.form.get("year", "")
    year = int(year_text) if year_text.isdigit() and 1990 <= int(year_text) <= 2100 \
        else datetime.now().year

    raw = file.read()
    if not raw.strip():
        flash("That file is empty.", "danger")
        return redirect(url_for("upload"))

    # --- duplicate protection #1: the whole file -----------------------
    file_hash = hashlib.sha256(raw).hexdigest()
    existing = db.fetch_one(conn, "SELECT file_id, original_name FROM log_files "
                                  "WHERE file_sha256 = %s", (file_hash,))
    if existing:
        flash(f"This exact file was already imported as '{existing['original_name']}'. "
              "Nothing was added.", "warning")
        return redirect(url_for("import_detail", file_id=existing["file_id"]))

    text = raw.decode("utf-8", errors="replace")
    result = parse_log(text, year)

    # --- save: file row, events, rejected lines ------------------------
    _, file_id = db.execute(conn, """
        INSERT INTO log_files (original_name, file_sha256, file_size, total_lines)
        VALUES (%s, %s, %s, %s)""", (name, file_hash, len(raw), result["total_lines"]))

    type_ids = {r["type_code"]: r["type_id"]
                for r in db.fetch_all(conn, "SELECT type_id, type_code FROM event_types")}
    rows = [(file_id, type_ids[e["type_code"]], e["event_time"], e["username"],
             e["ip_address"], e["service"], e["severity"], e["message"],
             e["error_signature"], e["event_hash"], e["line_number"])
            for e in result["events"]]

    # --- duplicate protection #2: INSERT IGNORE + UNIQUE(event_hash) ----
    inserted = 0
    for start in range(0, len(rows), 500):
        batch = rows[start:start + 500]
        inserted += db.execute_many(conn, """
            INSERT IGNORE INTO log_events
              (file_id, type_id, event_time, username, ip_address, service,
               severity, message, error_signature, event_hash, line_number)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""", batch)
    duplicates = len(rows) - inserted

    db.execute_many(conn, """
        INSERT INTO rejected_lines (file_id, line_number, raw_line, reason)
        VALUES (%s, %s, %s, %s)""",
        [(file_id, r["line_number"], r["raw_line"], r["reason"])
         for r in result["rejected"][:config.MAX_REJECTED_STORED]])

    db.execute(conn, """
        UPDATE log_files SET parsed_lines = %s, rejected_lines = %s, duplicate_events = %s
        WHERE file_id = %s""", (inserted, len(result["rejected"]), duplicates, file_id))
    conn.commit()

    flagged = analysis.recompute_flags(conn)

    flash(f"Processing complete: {inserted} records saved, "
          f"{len(result['rejected'])} lines rejected, {duplicates} duplicates skipped. "
          f"{flagged} events are now marked for investigation.", "success")
    return redirect(url_for("import_detail", file_id=file_id))


@app.route("/import/<int:file_id>")
def import_detail(file_id):
    conn = get_conn()
    info = db.fetch_one(conn, "SELECT * FROM log_files WHERE file_id = %s", (file_id,))
    if not info:
        return render_template("error.html", title="Not found",
                               message="That import does not exist.", hint=""), 404
    rejected = db.fetch_all(conn, """
        SELECT line_number, raw_line, reason FROM rejected_lines
        WHERE file_id = %s ORDER BY line_number LIMIT 100""", (file_id,))
    by_type = db.fetch_all(conn, """
        SELECT t.type_code, t.category, COUNT(*) AS n
        FROM log_events e JOIN event_types t ON t.type_id = e.type_id
        WHERE e.file_id = %s GROUP BY t.type_code, t.category ORDER BY n DESC""", (file_id,))
    return render_template("import_detail.html", info=info, rejected=rejected, by_type=by_type)


@app.route("/rules", methods=["GET", "POST"])
def rules():
    conn = get_conn()
    if request.method == "POST":
        for rule in analysis.get_rules(conn):
            code = rule["rule_code"]
            value = request.form.get(f"threshold_{code}", "")
            if value.isdigit() and 1 <= int(value) <= 100000:
                db.execute(conn, "UPDATE detection_rules SET threshold = %s, enabled = %s "
                                 "WHERE rule_code = %s",
                           (int(value), 1 if request.form.get(f"enabled_{code}") else 0, code))
        conn.commit()
        flagged = analysis.recompute_flags(conn)
        flash(f"Rules saved and re-applied. {flagged} events are marked for investigation.",
              "success")
        return redirect(url_for("rules"))
    return render_template("rules.html", rules=analysis.get_rules(conn))


@app.route("/recompute", methods=["POST"])
def recompute():
    flagged = analysis.recompute_flags(get_conn())
    flash(f"Analysis re-run. {flagged} events are marked for investigation.", "success")
    return redirect(request.referrer or url_for("dashboard"))


@app.route("/sample/<path:filename>")
def sample_file(filename):
    """Lets you download the sample logs from the Upload page."""
    return send_from_directory(SAMPLE_DIR, filename, as_attachment=True)


if __name__ == "__main__":
    try:
        for message in db.ensure_schema():
            print("[setup]", message)
    except mysql.connector.Error as exc:
        print("[setup] Could not prepare MySQL:", exc)
        print("[setup] Fix config.py (DB_PASSWORD) and restart. The site will show an error until then.")
    app.run(debug=True)
