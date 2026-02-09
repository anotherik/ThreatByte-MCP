from flask import Blueprint, render_template, request, redirect, url_for, session, flash, current_app
from werkzeug.security import generate_password_hash, check_password_hash
import os
from datetime import datetime, timedelta

from .db import get_db
from .auth import login_required, get_current_user

ui_bp = Blueprint("ui", __name__)


@ui_bp.route("/")
def index():
    if session.get("user_id"):
        return redirect(url_for("ui.dashboard"))
    return render_template("index.html")


@ui_bp.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm", "")

        if not username or not email or not password:
            return render_template("signup.html", error="All fields are required")
        if password != confirm:
            return render_template("signup.html", error="Passwords do not match")

        db = get_db()
        existing = db.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
        if existing:
            return render_template("signup.html", error="Username already exists")

        db.execute(
            "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
            (username, email, generate_password_hash(password)),
        )
        db.commit()
        flash("Account created. Please log in.")
        return redirect(url_for("ui.login"))

    return render_template("signup.html")


@ui_bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not username or not password:
            return render_template("login.html", error="Please provide username and password")

        db = get_db()
        user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        if not user or not check_password_hash(user["password_hash"], password):
            return render_template("login.html", error="Invalid username or password")

        session.clear()
        session["user_id"] = user["id"]
        return redirect(url_for("ui.dashboard"))

    return render_template("login.html")


@ui_bp.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("ui.index"))


@ui_bp.route("/dashboard")
@login_required
def dashboard():
    db = get_db()
    user = get_current_user()
    cases = db.execute(
        "SELECT id, title, severity, created_at FROM cases WHERE owner_id = ? ORDER BY created_at DESC",
        (user["id"],),
    ).fetchall()
    severity_rows = db.execute(
        "SELECT severity, COUNT(*) as count FROM cases GROUP BY severity"
    ).fetchall()
    severity_counts = {row["severity"]: row["count"] for row in severity_rows}
    total_cases = sum(severity_counts.values())
    high_count = severity_counts.get("high", 0)
    medium_count = severity_counts.get("medium", 0)
    low_count = severity_counts.get("low", 0)

    today = datetime.utcnow().date()
    days = [(today - timedelta(days=i)) for i in range(4, -1, -1)]
    day_labels = [d.strftime("%a") for d in days]
    day_keys = [d.strftime("%Y-%m-%d") for d in days]
    volume_rows = db.execute(
        "SELECT DATE(created_at) as day, COUNT(*) as count "
        "FROM cases WHERE DATE(created_at) >= DATE(?) GROUP BY day ORDER BY day",
        (days[0].strftime("%Y-%m-%d"),),
    ).fetchall()
    volume_map = {row["day"]: row["count"] for row in volume_rows}
    volume_counts = [volume_map.get(day, 0) for day in day_keys]
    volume_series = [
        {"label": label, "count": count} for label, count in zip(day_labels, volume_counts)
    ]

    recent_alerts = db.execute(
        "SELECT id, title, severity, created_at FROM cases ORDER BY created_at DESC LIMIT 5"
    ).fetchall()

    return render_template(
        "dashboard.html",
        user=user,
        cases=cases,
        total_cases=total_cases,
        high_count=high_count,
        medium_count=medium_count,
        low_count=low_count,
        day_labels=day_labels,
        volume_counts=volume_counts,
        volume_series=volume_series,
        recent_alerts=recent_alerts,
    )


@ui_bp.route("/cases/<int:case_id>")
@login_required
def case_view(case_id):
    db = get_db()
    user = get_current_user()
    case = db.execute(
        "SELECT id, title, severity, owner_id, created_at FROM cases WHERE id = ? AND owner_id = ?",
        (case_id, user["id"]),
    ).fetchone()
    if not case:
        flash("Case not found")
        return redirect(url_for("ui.dashboard"))

    notes = db.execute(
        "SELECT id, content, created_at, author_id FROM notes WHERE case_id = ? ORDER BY created_at DESC",
        (case_id,),
    ).fetchall()
    files = db.execute(
        "SELECT id, filename, original_name, uploaded_at, owner_id FROM files WHERE case_id = ? ORDER BY uploaded_at DESC",
        (case_id,),
    ).fetchall()

    return render_template("case.html", user=user, case=case, notes=notes, files=files)


@ui_bp.route("/profile")
@login_required
def profile():
    user = get_current_user()
    return render_template("profile.html", user=user)


@ui_bp.route("/profile/update", methods=["POST"])
@login_required
def profile_update():
    email = request.form.get("email", "").strip()
    user = get_current_user()
    db = get_db()
    db.execute("UPDATE users SET email = ? WHERE id = ?", (email, user["id"]))
    db.commit()
    flash("Profile updated")
    return redirect(url_for("ui.profile"))


@ui_bp.route("/indicators")
@login_required
def indicators():
    user = get_current_user()
    return render_template("indicators.html", user=user)


@ui_bp.route("/summary/<int:case_id>")
@login_required
def case_summary(case_id):
    user = get_current_user()
    return render_template("summary.html", user=user, case_id=case_id)


@ui_bp.route("/agent-logs")
@login_required
def agent_logs():
    user = get_current_user()
    db = get_db()
    logs = db.execute(
        "SELECT id, case_id, request_json, response_json, created_at "
        "FROM agent_logs ORDER BY id DESC LIMIT 50"
    ).fetchall()
    return render_template("agent_logs.html", user=user, logs=logs)


@ui_bp.route("/mcp-docs")
@login_required
def mcp_docs():
    user = get_current_user()
    return render_template("mcp_docs.html", user=user)


@ui_bp.route("/agent-tools")
@login_required
def agent_tools():
    user = get_current_user()
    return render_template("agent_tools.html", user=user)
