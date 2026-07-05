import base64
import re
import threading
import time

import requests

_SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")

import config
from enrichment import cache

VT_BASE_URL = "https://www.virustotal.com/api/v3"
CACHE_TTL_SECONDS = 24 * 60 * 60  # 24 hours
SOURCE = "virustotal"

_MIN_SECONDS_BETWEEN_REQUESTS = 60 / 4  # free tier: 4 requests/minute
_rate_limit_lock = threading.Lock()
_last_request_time = 0.0


def _rate_limit():
    global _last_request_time
    with _rate_limit_lock:
        now = time.monotonic()
        wait = _MIN_SECONDS_BETWEEN_REQUESTS - (now - _last_request_time)
        if wait > 0:
            time.sleep(wait)
        _last_request_time = time.monotonic()


def _normalize(data):
    attributes = data.get("attributes", {})
    stats = attributes.get("last_analysis_stats", {})
    return {
        "found": True,
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
        "reputation": attributes.get("reputation"),
        "permalink": f"https://www.virustotal.com/gui/{data.get('type', 'search')}/{data.get('id', '')}",
        "ai_insight": _extract_ai_insight(attributes),  # <-- new line
    }


_NOT_FOUND = {
    "found": False, "malicious": 0, "suspicious": 0,
    "harmless": 0, "undetected": 0, "reputation": None, "permalink": None,
}


def _query(endpoint, cache_key):
    cached = cache.get(SOURCE, cache_key, CACHE_TTL_SECONDS)
    if cached is not None:
        return cached

    _rate_limit()
    headers = {"x-apikey": config.VIRUSTOTAL_API_KEY}
    try:
        response = requests.get(f"{VT_BASE_URL}/{endpoint}", headers=headers, timeout=15)
    except requests.RequestException as e:
        return {"found": False, "error": str(e)}

    if response.status_code == 404:
        result = _NOT_FOUND
    elif response.status_code == 200:
        result = _normalize(response.json().get("data", {}))
    else:
        result = {"found": False, "error": f"VT returned HTTP {response.status_code}"}

    cache.set(SOURCE, cache_key, result)
    return result


def lookup_hash(sha256_hash):
    if not sha256_hash or not _SHA256_RE.match(sha256_hash):
        return None
    return _query(f"files/{sha256_hash.lower()}", f"hash:{sha256_hash.lower()}")


def lookup_ip(ip_address):
    if not ip_address:
        return None
    return _query(f"ip_addresses/{ip_address}", f"ip:{ip_address}")


def lookup_domain(domain):
    if not domain:
        return None
    return _query(f"domains/{domain}", f"domain:{domain.lower()}")


def lookup_url(url):
    if not url:
        return None
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    return _query(f"urls/{url_id}", f"url:{url}")

def _extract_ai_insight(attributes):
    ai_results = attributes.get("crowdsourced_ai_results") or []
    if not ai_results:
        return None

    code_insight = next(
        (r for r in ai_results if (r.get("source") or "").lower() == "code insight"),
        ai_results[0],
    )
    return {
        "source": code_insight.get("source"),
        "summary": code_insight.get("analysis"),
        "verdict": code_insight.get("verdict"),
    }