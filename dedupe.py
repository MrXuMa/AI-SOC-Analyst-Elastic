import hashlib
import sqlite3
import time
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent / "dedupe.db"
DEDUPE_WINDOW_SECONDS = 3600

def _get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS incidents (
            incident_key TEXT PRIMARY KEY,
            alert_id TEXT,
            first_seen REAL,
            last_seen REAL,
            occurrence_count INTEGER,
            primary_technique_id TEXT
        )
    """)
    return conn

def build_incident_key(alert_summary: dict) -> str:
    host = alert_summary.get("host_name_normalized") or ""
    executable = (alert_summary.get("process") or {}).get("executable") or ""
    file_hash = (alert_summary.get("file") or {}).get("hash_sha256") or ""
    rule_id = alert_summary.get("rule_id") or ""
    destination_ip = (alert_summary.get("network") or {}).get("destination_ip") or ""

    # Fall back to destination IP when there's no file hash to key on, so distinct
    # network-only alerts (e.g. different malicious IPs) under the same host+rule
    # aren't incorrectly collapsed into one incident.
    network_component = destination_ip if not file_hash else ""

    raw_key = f"{host}|{executable}|{file_hash}|{rule_id}|{network_component}"
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()

def is_duplicate(alert_summary: dict) -> bool:
    """Return True if this incident was already delivered within the dedupe window."""
    key = build_incident_key(alert_summary)
    now = time.time()

    conn = _get_conn()
    try:
        row = conn.execute(
            "SELECT last_seen FROM incidents WHERE incident_key = ?",
            (key,),
        ).fetchone()

        if row is None:
            return False

        last_seen = row[0]
        return (now - last_seen) < DEDUPE_WINDOW_SECONDS
    finally:
        conn.close()

def mark_incident_seen(alert_summary: dict, technique_id: str | None = None) -> None:
    """Record delivery only after Discord post succeeds."""
    key = build_incident_key(alert_summary)
    now = time.time()
    alert_id = alert_summary.get("id")

    conn = _get_conn()
    try:
        row = conn.execute(
            "SELECT occurrence_count FROM incidents WHERE incident_key = ?",
            (key,),
        ).fetchone()

        if row is None:
            conn.execute(
                "INSERT INTO incidents "
                "(incident_key, alert_id, first_seen, last_seen, occurrence_count, primary_technique_id) "
                "VALUES (?, ?, ?, ?, 1, ?)",
                (key, alert_id, now, now, technique_id),
            )
        else:
            conn.execute(
                "UPDATE incidents SET alert_id = ?, last_seen = ?, occurrence_count = ?, "
                "primary_technique_id = ? WHERE incident_key = ?",
                (alert_id, now, row[0] + 1, technique_id, key),
            )
        conn.commit()
    finally:
        conn.close()
