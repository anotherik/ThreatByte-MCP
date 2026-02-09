from functools import wraps
from flask import session, redirect, url_for
from .db import get_db


def get_current_user():
    user_id = session.get("user_id")
    if not user_id:
        return None
    db = get_db()
    return db.execute("SELECT id, username, email FROM users WHERE id = ?", (user_id,)).fetchone()


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(url_for("ui.login"))
        return view(*args, **kwargs)

    return wrapped
