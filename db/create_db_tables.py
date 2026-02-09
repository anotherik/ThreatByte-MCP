import os
import sqlite3

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DB_PATH = os.path.join(BASE_DIR, "db", "threatbyte_mcp.db")


def main():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    cur.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT NOT NULL,
            password_hash TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS cases (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            severity TEXT NOT NULL,
            owner_id INTEGER NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id INTEGER NOT NULL,
            content TEXT NOT NULL,
            author_id INTEGER NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id INTEGER NOT NULL,
            filename TEXT NOT NULL,
            original_name TEXT NOT NULL,
            owner_id INTEGER NOT NULL,
            uploaded_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS indicators (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            indicator TEXT NOT NULL,
            indicator_type TEXT NOT NULL,
            description TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS agent_contexts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id INTEGER NOT NULL,
            prompt TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS agent_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id INTEGER NOT NULL,
            request_json TEXT NOT NULL,
            response_json TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS mcp_tools (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            description TEXT NOT NULL,
            response_template TEXT NOT NULL,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        """
    )

    # Ensure new columns exist for tool registry extensions
    def ensure_column(table, column, col_type):
        cur.execute(f"PRAGMA table_info({table})")
        cols = {row[1] for row in cur.fetchall()}
        if column not in cols:
            cur.execute(f"ALTER TABLE {table} ADD COLUMN {column} {col_type}")

    ensure_column("mcp_tools", "tool_type", "TEXT")
    ensure_column("mcp_tools", "config_json", "TEXT")

    cur.execute("SELECT COUNT(*) FROM indicators")
    count = cur.fetchone()[0]
    if count == 0:
        cur.executemany(
            "INSERT INTO indicators (indicator, indicator_type, description) VALUES (?, ?, ?)",
            [
                ("198.51.100.10", "ip", "Suspicious outbound traffic"),
                ("malicious.example", "domain", "Known phishing domain"),
                ("44d88612fea8a8f36de82e1278abb02f", "hash", "EICAR test file"),
                ("203.0.113.77", "ip", "Credential stuffing source"),
                ("login-update.example", "domain", "Lookalike login portal"),
                ("payroll-secure.example", "domain", "Spoofed payroll site"),
                ("185.199.109.153", "ip", "C2 callback host"),
                ("f3c5e8a1b2d4f6a7c8e9d0b1a2c3d4e5", "hash", "Suspicious loader"),
                ("a1b2c3d4e5f60718293a4b5c6d7e8f90", "hash", "Known ransomware sample"),
                ("mail-gateway-alert.example", "domain", "Email lure infrastructure"),
                ("45.142.122.10", "ip", "Brute-force attempts"),
                ("cdn-assets-secure.example", "domain", "Phishing kit assets"),
                ("9f86d081884c7d659a2feaa0c55ad015", "hash", "Weak hash collision sample"),
            ],
        )

    conn.commit()
    conn.close()
    print(f"Database initialized at {DB_PATH}")


if __name__ == "__main__":
    main()
