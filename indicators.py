import ipaddress
from urllib.parse import urlparse


def _is_public_ip(ip_str):
    """Skip private/loopback/link-local IPs - no point enriching your own LAN."""
    if not ip_str:
        return False
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved)


def _is_safe_enrichment_url(url):
    """Only enrich http(s) URLs with a public host — avoids leaking internal URLs to TI APIs."""
    try:
        parsed = urlparse(url)
    except ValueError:
        return False
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return False
    host = parsed.hostname.strip("[]")
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return True
    return _is_public_ip(host)


def extract_indicators(alert_summary):
    """Scan an alert_summary (from fetch_alert.build_summary) and return a
    normalized list of indicators worth enriching:
    [{"type": "hash"|"ip"|"url", "value": ..., "role": ...}, ...]
    """
    indicators = []
    seen_hashes = set()

    file_hash = (alert_summary.get("file") or {}).get("hash_sha256")
    if file_hash:
        indicators.append({"type": "hash", "value": file_hash, "role": "file"})
        seen_hashes.add(file_hash.lower())

    process_hash = (alert_summary.get("process") or {}).get("hash_sha256")
    if process_hash and process_hash.lower() not in seen_hashes:
        indicators.append({"type": "hash", "value": process_hash, "role": "process"})
        seen_hashes.add(process_hash.lower())

    network = alert_summary.get("network") or {}
    for role, key in (("source", "source_ip"), ("destination", "destination_ip")):
        ip = network.get(key)
        if _is_public_ip(ip):
            indicators.append({"type": "ip", "value": ip, "role": role})

    download_url = (alert_summary.get("enrichment_hints") or {}).get("download_url")
    if download_url and _is_safe_enrichment_url(download_url):
        indicators.append({"type": "url", "value": download_url, "role": "download_url"})

    return indicators
