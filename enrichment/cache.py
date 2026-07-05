import json
import sqlite3
import time
from pathlib import Path

CACHE_DB_PATH = Path(__file__).resolve().parent.parent / "enrichment_cache.db"

def _get_conn():
    conn = sqlite3.connect(CACHE_DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS enrichment_cache (
            source TEXT NOT NULL,
            cache_key TEXT NOT NULL,
            result_json TEXT NOT NULL,
            cached_at REAL NOT NULL,
            PRIMARY KEY (source, cache_key)        
        )
    """)
    return conn

def get(source: str,cache_key: str, ttl_seconds:int):
    conn = _get_conn()
    try:
        row = conn.execute(
            "SELECT result_json, cached_at FROM enrichment_cache WHERE source = ? AND cache_key = ?",
            (source, cache_key),
        ).fetchone()
        if row is None:
            return None
        result_json, cached_at = row
        if time.time() - cached_at > ttl_seconds:
            return None
        return json.loads(result_json)
    finally:
        conn.close()

def set(source: str,cache_key: str, result: dict):
    conn = _get_conn()
    try:
        conn.execute(
            "INSERT OR REPLACE INTO enrichment_cache (source, cache_key, result_json, cached_at) VALUES (?,?,?,?)",
            (source, cache_key, json.dumps(result), time.time()),
        )
        conn.commit()
    finally:
        conn.close()