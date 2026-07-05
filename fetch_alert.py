#!/usr/bin/env python3

import json
import re
import ssl
import urllib.request
import urllib.error
import base64
from datetime import datetime, timezone
import mitre_attack

import config
from assets import lookup_asset

ALERTS_INDEX = ".internal.alerts-security.alerts-default-*"
ENRICHMENT_VERSION = "1.0"
EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"


def safe_get(obj, *keys, default=None):
    for key in keys:
        if not isinstance(obj, dict):
            return default
        obj = obj.get(key)
    return default if obj is None else obj


def pick_primary_ip(ips):
    if not ips:
        return None
    if isinstance(ips, str):
        return ips
    for ip in ips:
        if ip.startswith("192.168."):
            return ip
    return ips[0]


def extract_download_url(command_line):
    if not command_line:
        return None
    match = re.search(r"https?://\S+", command_line)
    return match.group(0) if match else None


def build_enrichment_hints(file_hash, command_line):
    file_hash = (file_hash or "").lower()
    download_url = extract_download_url(command_line)
    known_eicar = file_hash == EICAR_SHA256
    return {
        "file_hash_known_eicar": known_eicar,
        "download_url": download_url,
        "likely_test_activity": known_eicar or (
            download_url is not None and "eicar" in download_url.lower()
        ),
    }


def _run_search(payload):
    context = ssl.create_default_context(cafile=config.CA_CERT)
    url = f"{config.ELASTIC_URL}/{ALERTS_INDEX}/_search"

    json_data = json.dumps(payload).encode("utf-8")
    credentials = f"{config.ELASTIC_USER}:{config.ELASTIC_PASSWORD}".encode("utf-8")
    base64_credentials = base64.b64encode(credentials).decode("utf-8")

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Basic {base64_credentials}",
    }

    req = urllib.request.Request(url, data=json_data, headers=headers, method="POST")

    try:
        with urllib.request.urlopen(req, context=context) as response:
            if response.status == 200:
                return json.loads(response.read().decode("utf-8"))
            print(f"Server returned status: {response.status}")
            return None
    except urllib.error.HTTPError as e:
        print(f"HTTP Error: {e.code} - {e.reason}")
        return None
    except urllib.error.URLError as e:
        print(f"URL Error: {e.reason}")
        return None


def fetch_latest_alert():
    """Fetch the single most recent alert (raw ES hit dict), or None."""
    response = _run_search({
        "size": 1,
        "sort": [{"@timestamp": "desc"}],
    })
    hits = safe_get(response, "hits", "hits", default=[])
    return hits[0] if hits else None


def fetch_new_alerts(since_iso, max_alerts=100):
    """Fetch alerts with @timestamp > since_iso, oldest first.

    since_iso: ISO-8601 timestamp string, e.g. datetime.now(timezone.utc).isoformat()
    Returns a list of raw Elasticsearch hit dicts (possibly empty).
    """
    response = _run_search({
        "size": max_alerts,
        "sort": [{"@timestamp": "asc"}],
        "query": {
            "range": {
                "@timestamp": {"gt": since_iso}
            }
        },
    })
    return safe_get(response, "hits", "hits", default=[])


def build_summary(hit):
    """Transform one raw Elasticsearch alert hit into the flat enrichment schema.
    Pure aside from the local assets.py SQLite lookup."""
    source = hit.get("_source") or {}
    host = source.get("host") or {}
    process = source.get("process") or {}
    parent = process.get("parent") or {}
    file = source.get("file") or {}
    file_ext = file.get("Ext") or {}
    malware = file_ext.get("malware_classification") or {}
    event = source.get("event") or {}
    command_line = process.get("command_line")
    file_hash = safe_get(file, "hash", "sha256")

    host_name = host.get("hostname")
    primary_ip = pick_primary_ip(host.get("ip"))
    host_name_normalized = (host_name or host.get("name") or "").lower() or None
    asset = lookup_asset(hostname=host_name_normalized, ip=primary_ip)

    return {
        "enrichment_version": ENRICHMENT_VERSION,
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "id": hit.get("_id"),
        "alert_uuid": source.get("kibana.alert.uuid"),
        "rule_id": source.get("kibana.alert.rule.rule_id"),
        "rule_uuid": source.get("kibana.alert.rule.uuid"),
        "time": source.get("@timestamp"),
        "alert_name": source.get("kibana.alert.rule.name"),
        "alert_risk": source.get("kibana.alert.risk_score"),
        "alert_severity": source.get("kibana.alert.severity"),
        "workflow_status": source.get("kibana.alert.workflow_status"),
        "alert_status": source.get("kibana.alert.status"),
        "reason": source.get("kibana.alert.reason"),
        "kibana_url": source.get("kibana.alert.url"),
        "host_name": host_name,
        "host_name_normalized": host_name_normalized,
        "primary_ip": primary_ip,
        "host_os": safe_get(host, "os", "full"),
        "host_arch": host.get("architecture"),
        "user_name": safe_get(source, "user", "name") or safe_get(process, "Ext", "user"),
        "event": {
            "code": event.get("code"),
            "action": event.get("action"),
            "outcome": event.get("outcome"),
            "categories": event.get("category"),
            "types": event.get("type"),
        },
        "network": {
            "source_ip": pick_primary_ip(safe_get(source, "source", "ip")),
            "source_port": safe_get(source, "source", "port"),
            "destination_ip": pick_primary_ip(safe_get(source, "destination", "ip")),
            "destination_port": safe_get(source, "destination", "port"),
        },
        "process": {
            "name": process.get("name"),
            "pid": process.get("pid"),
            "command_line": command_line,
            "executable": process.get("executable"),
            "hash_sha256": safe_get(process, "hash", "sha256"),
        },
        "parent_process": {
            "name": parent.get("name"),
            "pid": parent.get("pid"),
            "command_line": parent.get("command_line"),
            "executable": parent.get("executable"),
            "user": safe_get(parent, "Ext", "user"),
        },
        "file": {
            "owner": file.get("owner"),
            "path": file.get("path"),
            "name": file.get("name"),
            "hash_sha256": file_hash,
        },
        "file_response": {
            "quarantined": file_ext.get("quarantine_result"),
            "quarantine_result": file_ext.get("quarantine_result"),
            "quarantine_path": file_ext.get("quarantine_path"),
            "malware_model": malware.get("identifier"),
            "malware_score": malware.get("score"),
            "malware_threshold": malware.get("threshold"),
        },
        "trust": {
            "process_signed": safe_get(process, "code_signature", "trusted"),
            "process_signer": safe_get(process, "code_signature", "signing_id"),
            "file_signed": safe_get(file, "code_signature", "exists"),
        },
        "agent_id": safe_get(source, "agent", "id"),
        "defend_policy": safe_get(source, "Endpoint", "policy", "applied", "name"),
        "asset": asset,
        "elastic_attack_tags": mitre_attack.extract_elastic_attack_tags(source),
        "enrichment_hints": build_enrichment_hints(file_hash, command_line),
    }


def alert_summary():
    """CLI helper: print a summary of the single latest alert."""
    hit = fetch_latest_alert()
    if not hit:
        print("No alerts found.")
        return
    print(json.dumps(build_summary(hit), indent=4))


if __name__ == "__main__":
    alert_summary()