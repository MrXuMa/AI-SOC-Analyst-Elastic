#!/usr/bin/env python3

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

import config
import dedupe
import indicators
from enrichment.router import gather_enrichment
from fetch_alert import build_summary, fetch_new_alerts
from triage.claude_agent import triage_alert

STATE_PATH = Path(__file__).resolve().parent / "poller_state.json"
MAX_ALERTS_PER_BATCH = 100


def load_checkpoint() -> str:
    if STATE_PATH.exists():
        return json.loads(STATE_PATH.read_text())["last_timestamp"]
    now = datetime.now(timezone.utc).isoformat()
    save_checkpoint(now)
    return now


def save_checkpoint(timestamp: str) -> None:
    STATE_PATH.write_text(json.dumps({"last_timestamp": timestamp}))


def _primary_technique_id(triage_result):
    tags = triage_result.get("mitre_attack") or []
    return tags[0]["technique_id"] if tags else None


def process_alert(hit):
    summary = build_summary(hit)

    if dedupe.is_duplicate(summary):
        print(f"[skip] duplicate incident: {summary.get('alert_name')} on {summary.get('host_name')}")
        return None

    alert_indicators = indicators.extract_indicators(summary)
    enrichment = gather_enrichment(alert_indicators)
    triage_result = triage_alert(summary, enrichment)
    dedupe.record_technique(summary, _primary_technique_id(triage_result))

    return summary, enrichment, triage_result


def process_batch(since_iso, max_alerts=MAX_ALERTS_PER_BATCH):
    hits = fetch_new_alerts(since_iso, max_alerts=max_alerts)
    results = [r for r in (process_alert(hit) for hit in hits) if r is not None]

    new_checkpoint = hits[-1]["_source"]["@timestamp"] if hits else since_iso
    hit_cap = len(hits) == max_alerts
    return new_checkpoint, results, hit_cap


def _print_result(alert_summary, enrichment, triage_result):
    print(json.dumps(
        {"alert": alert_summary, "enrichment": enrichment, "triage": triage_result},
        indent=2,
        default=str,
    ))


def run_dry_run():
    since_iso = load_checkpoint()
    _, results, _ = process_batch(since_iso)
    if not results:
        print("No new (non-duplicate) alerts to triage.")
    for result in results:
        _print_result(*result)


def run_replay(path):
    raw = json.loads(Path(path).read_text())
    hits = raw.get("hits", {}).get("hits", [])
    if not hits:
        print(f"No alerts found in {path}.")
        return
    result = process_alert(hits[0])
    if result is None:
        print("Replay alert was treated as a duplicate (already processed "
              "recently within the dedupe window) - nothing to show.")
        return
    _print_result(*result)


def run_live():
    from discord_bot.bot import bot
    bot.run(config.DISCORD_BOT_TOKEN)


def main():
    parser = argparse.ArgumentParser(description="AI SOC triage poller")
    parser.add_argument("--dry-run", action="store_true", help="Print triage results instead of posting to Discord")
    parser.add_argument("--replay", metavar="FILE", help="Replay a single saved alert JSON file instead of querying live Elasticsearch")
    args = parser.parse_args()

    if args.replay:
        run_replay(args.replay)
    elif args.dry_run:
        run_dry_run()
    else:
        run_live()


if __name__ == "__main__":
    main()
