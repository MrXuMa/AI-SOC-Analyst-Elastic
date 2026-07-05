import requests

import config
from enrichment import cache

ABUSEIPDB_BASE_URL = "https://api.abuseipdb.com/api/v2/check"
CACHE_TTL_SECONDS = 12 * 60 * 60
SOURCE = "abuseipdb"


def lookup_ip(ip_address):
    if not ip_address or not config.ABUSEIPDB_API_KEY:
        return None

    cache_key = f"ip:{ip_address}"
    cached = cache.get(SOURCE, cache_key, CACHE_TTL_SECONDS)
    if cached is not None:
        return cached

    headers = {"Key": config.ABUSEIPDB_API_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip_address, "maxAgeInDays": 90}

    try:
        response = requests.get(ABUSEIPDB_BASE_URL, headers=headers, params=params, timeout=15)
    except requests.RequestException as e:
        return {"found": False, "error": str(e)}

    if response.status_code != 200:
        result = {"found": False, "error": f"AbuseIPDB returned HTTP {response.status_code}"}
    else:
        data = response.json().get("data", {})
        result = {
            "found": True,
            "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
            "total_reports": data.get("totalReports", 0),
            "country_code": data.get("countryCode"),
            "isp": data.get("isp"),
            "is_whitelisted": data.get("isWhitelisted"),
            "permalink": f"https://www.abuseipdb.com/check/{ip_address}",
        }

    cache.set(SOURCE, cache_key, result)
    return result
