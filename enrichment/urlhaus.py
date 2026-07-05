import requests

import config
from enrichment import cache

URLHAUS_URL = "https://urlhaus-api.abuse.ch/v1/url/"
CACHE_TTL_SECONDS = 24 * 60 * 60
SOURCE = "urlhaus"


def lookup_url(url):
    if not url or not config.ABUSE_CH_AUTH_KEY:
        return None

    cache_key = f"url:{url}"
    cached = cache.get(SOURCE, cache_key, CACHE_TTL_SECONDS)
    if cached is not None:
        return cached

    headers = {"Auth-Key": config.ABUSE_CH_AUTH_KEY}
    data = {"url": url}

    try:
        response = requests.post(URLHAUS_URL, headers=headers, data=data, timeout=15)
    except requests.RequestException as e:
        return {"found": False, "error": str(e)}

    if response.status_code != 200:
        result = {"found": False, "error": f"URLhaus returned HTTP {response.status_code}"}
    else:
        body = response.json()
        if body.get("query_status") != "ok":
            result = {"found": False}
        else:
            result = {
                "found": True,
                "url_status": body.get("url_status"),
                "threat": body.get("threat"),
                "host": body.get("host"),
                "date_added": body.get("date_added"),
                "tags": body.get("tags") or [],
                "permalink": body.get("urlhaus_reference"),
            }

    cache.set(SOURCE, cache_key, result)
    return result
