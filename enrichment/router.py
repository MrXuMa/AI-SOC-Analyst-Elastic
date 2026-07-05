from enrichment import abuseipdb, malwarebazaar, urlhaus, virustotal

_LOOKUPS = {
    "hash": [
        ("virustotal", virustotal.lookup_hash),
        ("malwarebazaar", malwarebazaar.lookup_hash),
    ],
    "ip": [
        ("virustotal", virustotal.lookup_ip),
        ("abuseipdb", abuseipdb.lookup_ip),
    ],
    "url": [
        ("virustotal", virustotal.lookup_url),
        ("urlhaus", urlhaus.lookup_url),
    ],
}


def gather_enrichment(indicators):
    """Given a list of indicators from indicators.extract_indicators(), call
    the appropriate enrichment lookups for each and return an annotated list."""
    enriched = []
    for indicator in indicators:
        result = dict(indicator)
        for source_name, lookup_fn in _LOOKUPS.get(indicator["type"], []):
            result[source_name] = lookup_fn(indicator["value"])
        enriched.append(result)
    return {"indicators": enriched}
