from flask import (
    Flask, render_template, request,
    redirect, url_for, flash, session
)
import sqlite3
import uuid
from datetime import datetime
from functools import wraps

app = Flask(__name__)

# Change these before any real deployment
app.secret_key = "change-this-secret-key-before-deployment"

DATABASE = "cyberguard.db"

# Demo administrator credentials
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin123"


def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db_connection()

    conn.execute("""
        CREATE TABLE IF NOT EXISTS incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id TEXT UNIQUE NOT NULL,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'Pending',
            created_at TEXT NOT NULL
        )
    """)

    conn.commit()
    conn.close()


# Protect admin pages
def admin_required(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        if not session.get("admin_logged_in"):
            return redirect(url_for("admin_login"))
        return function(*args, **kwargs)
    return wrapper


# Homepage
@app.route("/")
def home():
    return render_template("index.html")


# Submit incident
@app.route("/submit", methods=["POST"])
def submit():
    title = request.form.get("title", "").strip()
    description = request.form.get("description", "").strip()

    if not title or not description:
        flash("Please fill in all incident details.", "error")
        return redirect(url_for("home"))

    case_id = "CG-" + uuid.uuid4().hex[:8].upper()

    conn = get_db_connection()

    try:
        conn.execute("""
            INSERT INTO incidents
            (case_id, title, description, status, created_at)
            VALUES (?, ?, ?, ?, ?)
        """, (
            case_id,
            title,
            description,
            "Pending",
            datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ))
        conn.commit()

    except sqlite3.Error as error:
        print("Database error:", error)
        flash("Unable to submit report.", "error")
        return redirect(url_for("home"))

    finally:
        conn.close()

    return render_template("success.html", case_id=case_id)


# Track case
@app.route("/track", methods=["GET", "POST"])
def track():
    case_id = request.form.get("case_id", "").strip().upper()

    if not case_id:
        flash("Please enter your Case ID.", "error")
        return redirect(url_for("home"))

    conn = get_db_connection()

    try:
        incident = conn.execute(
            "SELECT * FROM incidents WHERE case_id = ?",
            (case_id,)
        ).fetchone()
    finally:
        conn.close()

    if incident:
        return render_template("track.html", incident=incident)

    flash("Case ID not found.", "error")
    return redirect(url_for("home"))


# Admin login page
@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():

    if session.get("admin_logged_in"):
        return redirect(url_for("admin_dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        if (username == ADMIN_USERNAME and
                password == ADMIN_PASSWORD):

            session.clear()
            session["admin_logged_in"] = True
            return redirect(url_for("admin_dashboard"))

        flash("Invalid username or password.", "error")

    return render_template("admin_login.html")


# Admin dashboard
@app.route("/admin")
@admin_required
def admin_dashboard():

    conn = get_db_connection()

    try:
        incidents = conn.execute("""
            SELECT * FROM incidents
            ORDER BY id DESC
        """).fetchall()

        total = conn.execute(
            "SELECT COUNT(*) FROM incidents"
        ).fetchone()[0]

        pending = conn.execute(
            "SELECT COUNT(*) FROM incidents WHERE status = 'Pending'"
        ).fetchone()[0]

        investigating = conn.execute(
            "SELECT COUNT(*) FROM incidents WHERE status = 'Investigating'"
        ).fetchone()[0]

        resolved = conn.execute(
            "SELECT COUNT(*) FROM incidents WHERE status = 'Resolved'"
        ).fetchone()[0]

    finally:
        conn.close()

    return render_template(
        "admin.html",
        incidents=incidents,
        total=total,
        pending=pending,
        investigating=investigating,
        resolved=resolved
    )


# Update case status
@app.route("/admin/update/<case_id>", methods=["POST"])
@admin_required
def update_status(case_id):

    status = request.form.get("status", "")

    allowed_statuses = [
        "Pending",
        "Investigating",
        "Resolved"
    ]

    if status not in allowed_statuses:
        flash("Invalid case status.", "error")
        return redirect(url_for("admin_dashboard"))

    conn = get_db_connection()

    try:
        result = conn.execute("""
            UPDATE incidents
            SET status = ?
            WHERE case_id = ?
        """, (status, case_id))

        conn.commit()

        if result.rowcount == 0:
            flash("Case not found.", "error")
        else:
            flash("Case status updated successfully!", "success")

    finally:
        conn.close()

    return redirect(url_for("admin_dashboard"))


# Admin logout
@app.route("/admin/logout")
@admin_required
def admin_logout():
    session.clear()
    return redirect(url_for("home"))


if __name__ == "__main__":
    init_db()
    app.run(debug=True)