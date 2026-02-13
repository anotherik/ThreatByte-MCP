from flask import Blueprint, render_template, request, redirect, url_for, session, flash, current_app, Response
from werkzeug.security import generate_password_hash, check_password_hash
import os
from datetime import datetime, timedelta
import httpx
import json

from .db import get_db
from .auth import login_required, get_current_user

ui_bp = Blueprint("ui", __name__)
MCP_PROTOCOL_VERSION = "2025-11-25"


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
        "SELECT id, title, severity, status, created_at FROM cases WHERE owner_id = ? ORDER BY created_at DESC",
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
        "SELECT id, title, severity, status, created_at FROM cases ORDER BY created_at DESC LIMIT 5"
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
        "SELECT id, title, severity, status, owner_id, created_at FROM cases WHERE id = ?",
        (case_id,),
    ).fetchone()
    if not case:
        flash("Case not found")
        return redirect(url_for("ui.dashboard"))
    if case["owner_id"] != user["id"]:
        flash("You do not have permission to view this case.")
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


@ui_bp.route("/mcp-proxy", methods=["POST"])
@login_required
def mcp_proxy():
    user = get_current_user()
    target = current_app.config["MCP_SERVER_URL"]
    payload = request.get_data()
    wants_stream = request.args.get("stream") in {"1", "true", "yes"} or "text/event-stream" in request.headers.get("Accept", "")
    accept = "application/json, text/event-stream"
    headers = {
        "Content-Type": "application/json",
        "Accept": accept,
        "MCP-Protocol-Version": MCP_PROTOCOL_VERSION,
        "X-TBMCP-Token": current_app.config["MCP_SERVER_TOKEN"],
        "X-TBMCP-User": str(user["id"]),
    }

    def _extract_sse_json_from_bytes(raw):
        if not raw:
            return None
        last = None
        if isinstance(raw, str):
            raw = raw.encode("utf-8", errors="ignore")
        for line in raw.splitlines():
            if not line.startswith(b"data: "):
                continue
            chunk = line[6:].strip()
            if not chunk:
                continue
            try:
                last = json.loads(chunk.decode("utf-8", errors="ignore"))
            except Exception:
                continue
        return last

    def _normalize_tool_result(data):
        if not isinstance(data, dict):
            return data
        result = data.get("result")
        if not isinstance(result, dict):
            return data
        if result.get("isError") is True and isinstance(result.get("content"), list):
            first = result["content"][0] if result["content"] else {}
            if isinstance(first, dict) and first.get("type") == "text":
                message = first.get("text", "MCP tool error")
                data.pop("result", None)
                data["error"] = {"code": -32001, "message": message}
                return data
        content = result.get("content")
        if not isinstance(content, list) or not content:
            return data
        first = content[0]
        if isinstance(first, dict) and first.get("type") == "text":
            text = first.get("text", "")
            try:
                parsed = json.loads(text)
                data["result"] = parsed
            except Exception:
                data["result"] = {"ok": True, "output": text}
        return data

    if wants_stream:
        try:
            payload_json = json.loads(payload or b"{}")
        except Exception:
            payload_json = {}
        params = payload_json.get("params") or {}
        tool_name = params.get("name")

        def stream_text_response(rpc_id, base_result, key, text, chunk_size=200):
            total = text or ""
            offset = 0
            while offset < len(total):
                chunk = total[offset:offset + chunk_size]
                offset += chunk_size
                payload = {
                    "jsonrpc": "2.0",
                    "id": rpc_id,
                    "result": {**base_result, "partial": True, "delta": chunk},
                }
                yield f"event: message\ndata: {json.dumps(payload)}\n\n"
            final_payload = {
                "jsonrpc": "2.0",
                "id": rpc_id,
                "result": {**base_result, key: total, "partial": False},
            }
            yield f"event: message\ndata: {json.dumps(final_payload)}\n\n"

        def stream():
            data = None
            resp = httpx.post(target, headers=headers, content=payload, timeout=None)
            content_type = resp.headers.get("content-type", "")
            if "text/event-stream" in content_type:
                data = _extract_sse_json_from_bytes(resp.content)
            else:
                try:
                    data = resp.json()
                except Exception:
                    data = None

            if not isinstance(data, dict):
                error_payload = {
                    "jsonrpc": "2.0",
                    "id": payload_json.get("id"),
                    "error": {"code": -32603, "message": "Invalid MCP response"},
                }
                yield f"event: message\ndata: {json.dumps(error_payload)}\n\n"
                return

            data = _normalize_tool_result(data)

            if "error" in data:
                yield f"event: message\ndata: {json.dumps(data)}\n\n"
                return

            result = data.get("result") or {}
            if tool_name in {"agent.summarize_case", "agent.run_task"}:
                key = "summary" if tool_name == "agent.summarize_case" else "result"
                text = result.get(key, "")
                base = dict(result)
                base.pop(key, None)
                base.pop("partial", None)
                base.pop("delta", None)
                yield from stream_text_response(data.get("id"), base, key, text)
                return

            yield f"event: message\ndata: {json.dumps(data)}\n\n"

        return Response(stream(), mimetype="text/event-stream")

    resp = httpx.post(target, headers=headers, content=payload, timeout=20.0)
    content_type = resp.headers.get("content-type", "")
    if "text/event-stream" in content_type:
        data = _extract_sse_json_from_bytes(resp.content)
        if data is None:
            error_payload = {
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32603, "message": "Empty MCP response"},
            }
            return Response(json.dumps(error_payload), status=200, content_type="application/json")
        data = _normalize_tool_result(data)
        return Response(json.dumps(data), status=200, content_type="application/json")
    return Response(resp.content, status=resp.status_code, content_type=resp.headers.get("content-type", "application/json"))
