import sqlite3

def init_db():
    conn = sqlite3.connect("logs.db")
    c = conn.cursor()

    c.execute("""
    CREATE TABLE IF NOT EXISTS logs (
        timestamp TEXT,
        level TEXT,
        message TEXT,
        ip TEXT,
        threat TEXT
    )
    """)

    conn.commit()
    conn.close()


def insert_log(data):
    conn = sqlite3.connect("logs.db")
    c = conn.cursor()

    c.execute("""
    INSERT INTO logs VALUES (?, ?, ?, ?, ?)
    """, (data["timestamp"], data["level"], data["message"], data["ip"], data["threat"]))

    conn.commit()
    conn.close()


def fetch_logs():
    conn = sqlite3.connect("logs.db")
    c = conn.cursor()

    c.execute("SELECT * FROM logs")
    rows = c.fetchall()

    conn.close()
    return rows