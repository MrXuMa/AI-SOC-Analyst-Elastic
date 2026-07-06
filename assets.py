import os
import sqlite3

DB_FILE = os.path.join(os.path.dirname(__file__), "assets.db")

ASSET_COLUMNS = ("hostname", "ip", "role", "owner", "criticality")

# Homelab asset inventory — used for alert enrichment context
SEED_ASSETS = [
    ("siem-core", "100.96.150.2", "siem", "tfink", "high"),
    ("fink", "100.123.111.89", "endpoint", "tfink", "high"),
    ("tylers-macbook-pro", "100.105.202.108", "endpoint", "tfink", "high"),
]


def _row_to_dict(row):
    if row is None:
        return None
    return dict(zip(ASSET_COLUMNS, row))


def _ensure_db():
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS assets (
                hostname TEXT PRIMARY KEY,
                ip TEXT NOT NULL,
                role TEXT NOT NULL,
                owner TEXT NOT NULL,
                criticality TEXT NOT NULL
            )
        """)
        cursor.execute("SELECT COUNT(*) FROM assets")
        if cursor.fetchone()[0] == 0:
            cursor.executemany("""
                INSERT INTO assets (hostname, ip, role, owner, criticality)
                VALUES (?, ?, ?, ?, ?)
            """, SEED_ASSETS)
        conn.commit()


def create_table():
    _ensure_db()
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM assets")
            rows = cursor.fetchall()
            print("Table 'assets' ready.")
            print("\n--- DATABASE CONTENT ---")
            for row in rows:
                print(
                    f"hostname: {row[0]} | ip: {row[1]} | role: {row[2]} | "
                    f"owner: {row[3]} | crit: {row[4]}"
                )
    except sqlite3.Error as e:
        print(f"An error occurred with SQLite: {e}")


def lookup_asset(hostname=None, ip=None):
    _ensure_db()

    if hostname:
        hostname = hostname.lower()
        query = "SELECT hostname, ip, role, owner, criticality FROM assets WHERE hostname = ?"
        params = (hostname,)
    elif ip:
        query = "SELECT hostname, ip, role, owner, criticality FROM assets WHERE ip = ?"
        params = (ip,)
    else:
        return None

    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            return _row_to_dict(cursor.fetchone())
    except sqlite3.Error as e:
        print(f"An error occurred with SQLite: {e}")
        return None


if __name__ == "__main__":
    create_table()
    print(lookup_asset(hostname="workstation-01"))
    print(lookup_asset(ip="10.0.0.50"))
    print(lookup_asset(hostname="siem-host"))
    print(lookup_asset(hostname="unknown"))
