"""
CYBERGUARD – OBSIDIAN PULSE
Cyber Incident Reporting and Digital Forensic Management Platform
Tagline: REPORT. TRACK. INVESTIGATE. RESOLVE.
"""

import os
import sqlite3
import uuid
from datetime import datetime
from functools import wraps

from flask import (
    Flask, render_template, request,
    redirect, url_for, flash, session, jsonify
)
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# Disable static cache in development to ensure immediate stylesheet and asset updates
app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 0

# Security configuration
app.secret_key = os.environ.get(
    "FLASK_SECRET_KEY",
    "cyberguard-obsidian-pulse-secure-key-2026"
)

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=(
        os.environ.get("FLASK_ENV") == "production"
    )
)

@app.after_request
def add_header(response):
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "-1"
    return response

DATABASE = "cyberguard.db"

# Fallback administrator credentials
DEFAULT_ADMIN_USER = os.environ.get("ADMIN_USERNAME", "admin")
DEFAULT_ADMIN_PASS = os.environ.get("ADMIN_PASSWORD", "admin123")


# Database connection helper
def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


# Initialize and migrate database safely
def init_db():
    conn = get_db_connection()
    try:
        # Create users table
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                full_name TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'user',
                created_at TEXT NOT NULL
            )
        """)

        # Create base incidents table if not present
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

        # Inspect columns in incidents table for migrations
        cursor = conn.cursor()
        cursor.execute("PRAGMA table_info(incidents)")
        columns = [col[1] for col in cursor.fetchall()]

        # Perform safe non-destructive schema additions
        if "user_id" not in columns:
            conn.execute("ALTER TABLE incidents ADD COLUMN user_id INTEGER")
        if "category" not in columns:
            conn.execute("ALTER TABLE incidents ADD COLUMN category TEXT DEFAULT 'Other'")
        if "incident_date" not in columns:
            conn.execute("ALTER TABLE incidents ADD COLUMN incident_date TEXT")
        if "supporting_info" not in columns:
            conn.execute("ALTER TABLE incidents ADD COLUMN supporting_info TEXT")
        if "investigation_notes" not in columns:
            conn.execute("ALTER TABLE incidents ADD COLUMN investigation_notes TEXT")
        if "resolution" not in columns:
            conn.execute("ALTER TABLE incidents ADD COLUMN resolution TEXT")
        if "updated_at" not in columns:
            conn.execute("ALTER TABLE incidents ADD COLUMN updated_at TEXT")

        # Seed or verify default admin user
        admin = conn.execute(
            "SELECT * FROM users WHERE role = 'admin' LIMIT 1"
        ).fetchone()

        if not admin:
            conn.execute("""
                INSERT INTO users (username, email, full_name, password_hash, role, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                DEFAULT_ADMIN_USER,
                "admin@cyberguard.sec",
                "Lead Security Administrator",
                generate_password_hash(DEFAULT_ADMIN_PASS),
                "admin",
                datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            ))

        conn.commit()
    finally:
        conn.close()


# Context processor to expose session identity cleanly in templates
@app.context_processor
def inject_auth_state():
    return {
        "current_user": session.get("username"),
        "current_full_name": session.get("full_name"),
        "is_authenticated": bool(session.get("user_id")),
        "is_admin": bool(session.get("is_admin") or session.get("admin_logged_in")),
        "current_year": datetime.now().year,
        "cache_buster": int(datetime.now().timestamp())
    }


# Authorization Decorators
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get("user_id") and not session.get("admin_logged_in"):
            flash("Please sign in to access your user dashboard.", "error")
            return redirect(url_for("login", next=request.url))
        return f(*args, **kwargs)
    return decorated_function


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not (session.get("is_admin") or session.get("admin_logged_in")):
            flash("Administrator authentication required.", "error")
            return redirect(url_for("admin_login"))
        return f(*args, **kwargs)
    return decorated_function


# ==============================================================================
# Public & Landing Routes
# ==============================================================================

@app.route("/")
def home():
    conn = get_db_connection()
    try:
        total_reports = conn.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
        resolved_reports = conn.execute(
            "SELECT COUNT(*) FROM incidents WHERE status = 'Resolved'"
        ).fetchone()[0]
        active_investigations = conn.execute(
            "SELECT COUNT(*) FROM incidents WHERE status = 'Investigating'"
        ).fetchone()[0]
    except Exception:
        total_reports = 0
        resolved_reports = 0
        active_investigations = 0
    finally:
        conn.close()

    return render_template(
        "index.html",
        total_reports=total_reports,
        resolved_reports=resolved_reports,
        active_investigations=active_investigations
    )


# ==============================================================================
# User Authentication Routes
# ==============================================================================

@app.route("/register", methods=["GET", "POST"])
def register():
    if session.get("user_id"):
        return redirect(url_for("user_dashboard"))

    if request.method == "POST":
        full_name = request.form.get("full_name", "").strip()
        username = request.form.get("username", "").strip().lower()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not full_name or not username or not email or not password:
            flash("Please fill in all registration fields.", "error")
            return render_template("register.html")

        if len(password) < 6:
            flash("Password must be at least 6 characters long.", "error")
            return render_template("register.html")

        if password != confirm_password:
            flash("Passwords do not match.", "error")
            return render_template("register.html")

        conn = get_db_connection()
        try:
            existing = conn.execute("""
                SELECT id FROM users WHERE username = ? OR email = ?
            """, (username, email)).fetchone()

            if existing:
                flash("Username or email is already registered. Please sign in.", "error")
                return render_template("register.html")

            cursor = conn.execute("""
                INSERT INTO users (username, email, full_name, password_hash, role, created_at)
                VALUES (?, ?, ?, ?, 'user', ?)
            """, (
                username,
                email,
                full_name,
                generate_password_hash(password),
                datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            ))
            conn.commit()

            # Automatically authenticate registered user
            session.clear()
            session["user_id"] = cursor.lastrowid
            session["username"] = username
            session["full_name"] = full_name
            session["is_admin"] = False

            flash(f"Account registered successfully! Welcome to CyberGuard, {full_name}.", "success")
            return redirect(url_for("user_dashboard"))

        except sqlite3.Error as e:
            print("Registration database error:", e)
            flash("An error occurred during registration. Please try again.", "error")
        finally:
            conn.close()

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("user_id"):
        return redirect(url_for("user_dashboard"))
    if session.get("admin_logged_in"):
        return redirect(url_for("admin_dashboard"))

    if request.method == "POST":
        identifier = request.form.get("identifier", "").strip().lower()
        password = request.form.get("password", "")

        if not identifier or not password:
            flash("Please enter your username/email and password.", "error")
            return render_template("login.html")

        conn = get_db_connection()
        try:
            user = conn.execute("""
                SELECT * FROM users
                WHERE username = ? OR email = ?
            """, (identifier, identifier)).fetchone()

            if user and check_password_hash(user["password_hash"], password):
                session.clear()
                session["user_id"] = user["id"]
                session["username"] = user["username"]
                session["full_name"] = user["full_name"]
                session["is_admin"] = (user["role"] == "admin")

                if user["role"] == "admin":
                    session["admin_logged_in"] = True
                    flash(f"Welcome back, Administrator {user['full_name']}.", "success")
                    return redirect(url_for("admin_dashboard"))

                flash(f"Welcome back, {user['full_name']}!", "success")
                next_url = request.args.get("next")
                return redirect(next_url if next_url else url_for("user_dashboard"))

            flash("Invalid username/email or password.", "error")

        finally:
            conn.close()

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been signed out safely.", "success")
    return redirect(url_for("home"))


@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    user_id = session.get("user_id")
    conn = get_db_connection()

    try:
        user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()

        if request.method == "POST":
            full_name = request.form.get("full_name", "").strip()
            new_password = request.form.get("new_password", "")

            if not full_name:
                flash("Full name cannot be blank.", "error")
                return render_template("profile.html", user=user)

            if new_password:
                if len(new_password) < 6:
                    flash("New password must be at least 6 characters.", "error")
                    return render_template("profile.html", user=user)
                
                conn.execute("""
                    UPDATE users SET full_name = ?, password_hash = ? WHERE id = ?
                """, (full_name, generate_password_hash(new_password), user_id))
            else:
                conn.execute("""
                    UPDATE users SET full_name = ? WHERE id = ?
                """, (full_name, user_id))

            conn.commit()
            session["full_name"] = full_name
            flash("Profile updated successfully.", "success")
            return redirect(url_for("profile"))

        return render_template("profile.html", user=user)

    finally:
        conn.close()


# ==============================================================================
# User Dashboard
# ==============================================================================

@app.route("/dashboard")
@login_required
def user_dashboard():
    user_id = session.get("user_id")
    conn = get_db_connection()

    try:
        # Fetch complaints submitted by this user
        incidents = conn.execute("""
            SELECT * FROM incidents
            WHERE user_id = ?
            ORDER BY id DESC
        """, (user_id,)).fetchall()

        total = len(incidents)
        pending = sum(1 for i in incidents if i["status"] == "Pending")
        investigating = sum(1 for i in incidents if i["status"] == "Investigating")
        resolved = sum(1 for i in incidents if i["status"] == "Resolved")

        return render_template(
            "dashboard.html",
            incidents=incidents,
            total=total,
            pending=pending,
            investigating=investigating,
            resolved=resolved
        )

    finally:
        conn.close()


# ==============================================================================
# Incident Reporting & Submission
# ==============================================================================

@app.route("/report", methods=["GET"])
def report():
    return render_template("report.html")


@app.route("/submit", methods=["POST"])
def submit():
    title = request.form.get("title", "").strip()
    category = request.form.get("category", "Other").strip()
    incident_date = request.form.get("incident_date", "").strip()
    description = request.form.get("description", "").strip()
    supporting_info = request.form.get("supporting_info", "").strip()

    if not title or not description:
        flash("Please provide both an incident title and description.", "error")
        return redirect(url_for("report") if request.referrer and "report" in request.referrer else url_for("home"))

    if len(title) > 200 or len(description) > 10000:
        flash("Incident details exceed allowed character limits.", "error")
        return redirect(url_for("home"))

    case_id = "CG-" + uuid.uuid4().hex[:8].upper()
    user_id = session.get("user_id")
    created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    conn = get_db_connection()
    try:
        conn.execute("""
            INSERT INTO incidents (
                case_id, user_id, title, category,
                incident_date, description, supporting_info,
                status, created_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, 'Pending', ?, ?)
        """, (
            case_id,
            user_id,
            title,
            category,
            incident_date or created_at[:10],
            description,
            supporting_info,
            created_at,
            created_at
        ))
        conn.commit()

    except sqlite3.Error as error:
        print("Database submission error:", error)
        flash("Unable to record incident report. Please try again.", "error")
        return redirect(url_for("home"))
    finally:
        conn.close()

    return render_template("success.html", case_id=case_id)


@app.route("/success/<case_id>")
def success(case_id):
    return render_template("success.html", case_id=case_id)


# ==============================================================================
# Complaint Tracking
# ==============================================================================

@app.route("/track", methods=["GET", "POST"])
def track():
    case_id = request.values.get("case_id", "").strip().upper()

    if not case_id:
        if request.method == "POST":
            flash("Please enter your complaint reference ID.", "error")
            return redirect(url_for("home"))
        return render_template("track.html", incident=None)

    conn = get_db_connection()
    try:
        incident = conn.execute("""
            SELECT * FROM incidents WHERE case_id = ?
        """, (case_id,)).fetchone()

    except sqlite3.Error as error:
        print("Database error in track:", error)
        flash("Unable to query incident details.", "error")
        return redirect(url_for("home"))
    finally:
        conn.close()

    if incident:
        return render_template("track.html", incident=incident)

    flash(f"Complaint reference ID '{case_id}' was not found in the registry.", "error")
    return render_template("track.html", incident=None, query_id=case_id)


# ==============================================================================
# Admin Authentication & Command Center
# ==============================================================================

@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if session.get("is_admin") or session.get("admin_logged_in"):
        return redirect(url_for("admin_dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        conn = get_db_connection()
        try:
            user = conn.execute("""
                SELECT * FROM users
                WHERE (username = ? OR email = ?) AND role = 'admin'
            """, (username, username)).fetchone()

            # Check database admin or fallback credentials
            valid_db = user and check_password_hash(user["password_hash"], password)
            valid_fallback = (
                username.lower() == DEFAULT_ADMIN_USER.lower() and
                password == DEFAULT_ADMIN_PASS
            )

            if valid_db or valid_fallback:
                session.clear()
                session["user_id"] = user["id"] if user else 1
                session["username"] = user["username"] if user else DEFAULT_ADMIN_USER
                session["full_name"] = user["full_name"] if user else "Lead Security Administrator"
                session["is_admin"] = True
                session["admin_logged_in"] = True

                flash("Administrator command console authenticated.", "success")
                return redirect(url_for("admin_dashboard"))

            flash("Invalid administrator credentials or unauthorized role.", "error")

        finally:
            conn.close()

    return render_template("admin_login.html")


@app.route("/admin")
@admin_required
def admin_dashboard():
    conn = get_db_connection()
    try:
        incidents = conn.execute("""
            SELECT incidents.*, users.username as reporter_username, users.email as reporter_email
            FROM incidents
            LEFT JOIN users ON incidents.user_id = users.id
            ORDER BY incidents.id DESC
        """).fetchall()

        total = len(incidents)
        pending = sum(1 for i in incidents if i["status"] == "Pending")
        investigating = sum(1 for i in incidents if i["status"] == "Investigating")
        resolved = sum(1 for i in incidents if i["status"] == "Resolved")

        # Dynamic category statistics from stored data
        category_rows = conn.execute("""
            SELECT category, COUNT(*) as count
            FROM incidents
            GROUP BY category
            ORDER BY count DESC
        """).fetchall()

        categories = {row["category"] or "Other": row["count"] for row in category_rows}

    finally:
        conn.close()

    return render_template(
        "admin.html",
        incidents=incidents,
        total=total,
        pending=pending,
        investigating=investigating,
        resolved=resolved,
        categories=categories
    )


@app.route("/admin/case/<case_id>", methods=["GET", "POST"])
@admin_required
def admin_case_detail(case_id):
    conn = get_db_connection()
    try:
        incident = conn.execute("""
            SELECT incidents.*, users.username as reporter_username, users.email as reporter_email, users.full_name as reporter_name
            FROM incidents
            LEFT JOIN users ON incidents.user_id = users.id
            WHERE incidents.case_id = ?
        """, (case_id,)).fetchone()

        if not incident:
            flash("Case not found.", "error")
            return redirect(url_for("admin_dashboard"))

        if request.method == "POST":
            status = request.form.get("status", incident["status"])
            investigation_notes = request.form.get("investigation_notes", "")
            resolution = request.form.get("resolution", "")

            conn.execute("""
                UPDATE incidents
                SET status = ?, investigation_notes = ?, resolution = ?, updated_at = ?
                WHERE case_id = ?
            """, (
                status,
                investigation_notes,
                resolution,
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                case_id
            ))
            conn.commit()
            flash(f"Case {case_id} updated successfully.", "success")
            return redirect(url_for("admin_dashboard"))

        return render_template("case_detail.html", incident=incident)

    finally:
        conn.close()


@app.route("/admin/update/<case_id>", methods=["POST"])
@admin_required
def update_status(case_id):
    status = request.form.get("status", "").strip()
    investigation_notes = request.form.get("investigation_notes", "")
    resolution = request.form.get("resolution", "")

    allowed_statuses = ["Pending", "Investigating", "Resolved"]
    if status not in allowed_statuses:
        flash("Invalid case status specified.", "error")
        return redirect(url_for("admin_dashboard"))

    conn = get_db_connection()
    try:
        updated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        if investigation_notes or resolution:
            conn.execute("""
                UPDATE incidents
                SET status = ?, investigation_notes = COALESCE(?, investigation_notes),
                    resolution = COALESCE(?, resolution), updated_at = ?
                WHERE case_id = ?
            """, (status, investigation_notes, resolution, updated_at, case_id))
        else:
            conn.execute("""
                UPDATE incidents
                SET status = ?, updated_at = ?
                WHERE case_id = ?
            """, (status, updated_at, case_id))

        conn.commit()
        flash(f"Status for case {case_id} updated to {status}.", "success")

    except sqlite3.Error as error:
        print("Database update error:", error)
        flash("Unable to update case status.", "error")
    finally:
        conn.close()

    return redirect(url_for("admin_dashboard"))


@app.route("/admin/logout")
@admin_required
def admin_logout():
    session.clear()
    flash("Administrator console session terminated safely.", "success")
    return redirect(url_for("home"))


# Run application server
if __name__ == "__main__":
    init_db()
    app.run(
        debug=os.environ.get("FLASK_DEBUG") == "1",
        host="0.0.0.0",
        port=5000
    )
