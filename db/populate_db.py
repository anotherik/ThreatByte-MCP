import argparse
import os
import random
import sqlite3
import string
import sys
from datetime import datetime, timedelta

from werkzeug.security import generate_password_hash

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DB_PATH = os.path.join(BASE_DIR, "db", "threatbyte_mcp.db")
UPLOAD_DIR = os.path.join(BASE_DIR, "app", "uploads")

sys.path.insert(0, BASE_DIR)


def _rand_text(prefix, length=8):
    alphabet = string.ascii_lowercase + string.digits
    return f"{prefix}_{''.join(random.choice(alphabet) for _ in range(length))}"


def _rand_sentence(words=8):
    vocab = [
        "alert",
        "suspicious",
        "endpoint",
        "telemetry",
        "credential",
        "phishing",
        "lateral",
        "movement",
        "beacon",
        "exfil",
        "triage",
        "contain",
    ]
    return " ".join(random.choice(vocab) for _ in range(words)).capitalize() + "."


def _rand_datetime(days_back=30):
    now = datetime.utcnow()
    delta = timedelta(days=random.randint(0, days_back), hours=random.randint(0, 23))
    return (now - delta).strftime("%Y-%m-%d %H:%M:%S")


def ensure_db():
    from db.create_db_tables import main as create_tables

    # Always run schema creation to ensure new tables exist
    create_tables()


def populate(users, cases, notes, files):
    ensure_db()
    os.makedirs(UPLOAD_DIR, exist_ok=True)

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    user_ids = []
    for i in range(users):
        username = _rand_text("user")
        email = f"{username}@example.com"
        password_hash = generate_password_hash("Password123!")
        cur.execute(
            "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
            (username, email, password_hash),
        )
        user_ids.append(cur.lastrowid)

    case_ids = []
    severities = ["low", "medium", "high"]
    for _ in range(cases):
        owner_id = random.choice(user_ids)
        title = _rand_sentence(words=4)
        severity = random.choice(severities)
        created_at = _rand_datetime()
        cur.execute(
            "INSERT INTO cases (title, severity, owner_id, created_at) VALUES (?, ?, ?, ?)",
            (title, severity, owner_id, created_at),
        )
        case_ids.append((cur.lastrowid, owner_id))

    for _ in range(notes):
        case_id, owner_id = random.choice(case_ids)
        content = _rand_sentence(words=random.randint(6, 12))
        created_at = _rand_datetime()
        cur.execute(
            "INSERT INTO notes (case_id, content, author_id, created_at) VALUES (?, ?, ?, ?)",
            (case_id, content, owner_id, created_at),
        )

    for _ in range(files):
        case_id, owner_id = random.choice(case_ids)
        filename = _rand_text("artifact", 6) + ".txt"
        original_name = filename
        uploaded_at = _rand_datetime()
        content = _rand_sentence(words=10)
        with open(os.path.join(UPLOAD_DIR, filename), "w", encoding="utf-8") as f:
            f.write(content + "\n")
        cur.execute(
            "INSERT INTO files (case_id, filename, original_name, owner_id, uploaded_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (case_id, filename, original_name, owner_id, uploaded_at),
        )

    conn.commit()
    conn.close()


def parse_args():
    parser = argparse.ArgumentParser(description="Populate ThreatByte-MCP with random data")
    parser.add_argument("--users", type=int, default=5)
    parser.add_argument("--cases", type=int, default=10)
    parser.add_argument("--notes", type=int, default=20)
    parser.add_argument("--files", type=int, default=10)
    return parser.parse_args()


def main():
    args = parse_args()
    populate(args.users, args.cases, args.notes, args.files)
    print("Database populated with random data.")


if __name__ == "__main__":
    main()
