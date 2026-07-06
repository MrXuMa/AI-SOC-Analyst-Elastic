import asyncio
import re
from urllib.parse import urlparse

import discord
from discord.ext import tasks

import config
import dedupe
import poller

_MITRE_TECHNIQUE_ID = re.compile(r"^T\d{4}(?:\.\d{3})?$")


def _safe_http_url(url):
    if not url or not isinstance(url, str):
        return None
    try:
        parsed = urlparse(url.strip())
    except ValueError:
        return None
    if parsed.scheme in ("http", "https") and parsed.netloc:
        return url.strip()
    return None

VERDICT_COLORS = {
    "malicious": discord.Color.red(),
    "suspicious": discord.Color.orange(),
    "benign": discord.Color.green(),
    "needs_review": discord.Color.light_grey(),
}

VERDICT_EMOJI = {
    "malicious": "\U0001F534",
    "suspicious": "\U0001F7E0",
    "benign": "\U0001F7E2",
    "needs_review": "\u26AA",
}

ENRICHMENT_STATUS_EMOJI = {
    "malicious": "\U0001F534",
    "suspicious": "\U0001F7E0",
    "benign": "\U0001F7E2",
    "skipped": "\u26AA",
    "error": "\u26AB",
}

_ENRICHMENT_SOURCES = (
    ("virustotal", "VirusTotal"),
    ("abuseipdb", "AbuseIPDB"),
    ("malwarebazaar", "MalwareBazaar"),
    ("urlhaus", "URLhaus"),
)

intents = discord.Intents.default()
bot = discord.Client(intents=intents)


@tasks.loop(seconds=config.POLL_INTERVAL_SECONDS)
async def poll_task():
    """Runs the sync fetch/dedupe/enrich/triage pipeline in a background
    thread (so blocking calls like VirusTotal's rate-limit sleeps never
    stall Discord's gateway heartbeat), then delivers results here on the
    event loop. Drains the backlog immediately if a batch came back full."""
    hit_cap = True
    while hit_cap:
        since_iso = poller.load_checkpoint()
        new_checkpoint, results, hit_cap = await asyncio.to_thread(poller.process_batch, since_iso)

        all_sent = True
        for alert_summary, enrichment, triage_result in results:
            try:
                await send_triage_result(alert_summary, triage_result, enrichment)
            except Exception as exc:
                print(
                    f"[error] Discord send failed for {alert_summary.get('alert_name')} "
                    f"on {alert_summary.get('host_name')}: {exc}",
                    flush=True,
                )
                all_sent = False
                break
            tags = triage_result.get("mitre_attack") or []
            technique_id = tags[0]["technique_id"] if tags else None
            dedupe.mark_incident_seen(alert_summary, technique_id)
            print(
                f"[sent] Discord: {alert_summary.get('alert_name')} "
                f"on {alert_summary.get('host_name')} "
                f"({triage_result.get('verdict')})",
                flush=True,
            )

        if all_sent or not results:
            poller.save_checkpoint(new_checkpoint)

        if hit_cap:
            print("Batch hit the alert cap - draining backlog immediately.")


@bot.event
async def on_ready():
    print(f"Discord bot logged in as {bot.user}", flush=True)
    if not poll_task.is_running():
        poll_task.start()


def _classify_enrichment(source: str, data) -> tuple[str, str]:
    """Return (status, detail) where status is malicious|suspicious|benign|skipped|error."""
    if data is None:
        return "skipped", "Not checked"

    if data.get("error"):
        return "error", str(data["error"])[:120]

    if source == "virustotal":
        if not data.get("found"):
            return "benign", "Not found in VirusTotal"
        malicious = data.get("malicious", 0) or 0
        suspicious = data.get("suspicious", 0) or 0
        if malicious > 0:
            return "malicious", f"{malicious} malicious, {suspicious} suspicious vendor hits"
        if suspicious > 0:
            return "suspicious", f"{suspicious} suspicious vendor hits"
        harmless = data.get("harmless", 0) or 0
        undetected = data.get("undetected", 0) or 0
        return "benign", f"0 malicious ({harmless} harmless, {undetected} undetected)"

    if source == "abuseipdb":
        if not data.get("found"):
            return "benign", "Not reported in AbuseIPDB"
        score = data.get("abuse_confidence_score", 0) or 0
        reports = data.get("total_reports", 0) or 0
        if score >= 75:
            return "malicious", f"Abuse score {score}% ({reports} reports)"
        if score >= 25:
            return "suspicious", f"Abuse score {score}% ({reports} reports)"
        return "benign", f"Abuse score {score}% ({reports} reports)"

    if source == "malwarebazaar":
        if not data.get("found"):
            return "benign", "Not listed in MalwareBazaar"
        signature = data.get("signature") or "unknown malware"
        return "malicious", f"Known sample: {signature}"

    if source == "urlhaus":
        if not data.get("found"):
            return "benign", "Not listed in URLhaus"
        threat = data.get("threat") or data.get("url_status") or "malicious URL"
        return "malicious", f"Listed: {threat}"

    return "skipped", "Unknown source"


def _format_enrichment_findings(enrichment) -> str | None:
    if not enrichment:
        return None

    indicators = enrichment.get("indicators") or []
    if not indicators:
        return None

    blocks = []
    for indicator in indicators:
        ind_type = indicator.get("type", "?")
        value = indicator.get("value", "")
        role = indicator.get("role")
        label = f"**{ind_type}**"
        if role:
            label += f" ({role})"
        if len(value) > 20:
            value = f"{value[:12]}...{value[-8:]}"
        label += f" `{value}`"

        source_lines = []
        for source_key, source_name in _ENRICHMENT_SOURCES:
            status, detail = _classify_enrichment(source_key, indicator.get(source_key))
            emoji = ENRICHMENT_STATUS_EMOJI.get(status, "\u26AA")
            status_label = status.replace("_", " ").title()
            source_lines.append(f"{emoji} **{source_name}**: {status_label} — {detail}")

        blocks.append(label + "\n" + "\n".join(source_lines))

    text = "\n\n".join(blocks)
    return text[:1024] if len(text) > 1024 else text


def build_embed(alert_summary, triage_result, enrichment=None):
    verdict = triage_result.get("verdict", "needs_review")
    color = VERDICT_COLORS.get(verdict, discord.Color.light_grey())
    emoji = VERDICT_EMOJI.get(verdict, "\u26AA")

    embed = discord.Embed(
        title=f"{emoji} {alert_summary.get('alert_name', 'Unknown Alert')}",
        description=triage_result.get("summary", ""),
        color=color,
    )

    embed.add_field(name="Verdict", value=f"{verdict} ({triage_result.get('confidence', 0):.0%} confidence)", inline=True)
    host_display = (
        alert_summary.get("host_name")
        or alert_summary.get("host_name_normalized")
        or "unknown"
    )
    asset = alert_summary.get("asset") or {}
    if asset.get("owner"):
        host_display = f"{host_display} ({asset['owner']}, {asset.get('criticality', '?')} crit)"
    embed.add_field(name="Host", value=host_display, inline=True)
    embed.add_field(name="Severity", value=alert_summary.get("alert_severity") or "unknown", inline=True)

    process = alert_summary.get("process") or {}
    if process.get("executable"):
        embed.add_field(name="Process", value=f"`{process.get('executable')}`", inline=False)
    if process.get("command_line"):
        embed.add_field(name="Command Line", value=f"```{process.get('command_line')[:500]}```", inline=False)

    file_info = alert_summary.get("file") or {}
    if file_info.get("hash_sha256"):
        embed.add_field(name="File Hash (SHA256)", value=f"`{file_info.get('hash_sha256')}`", inline=False)

    mitre_tags = triage_result.get("mitre_attack") or []
    if mitre_tags:
        lines = []
        for tag in mitre_tags:
            technique_id = tag.get("technique_id", "?")
            technique_name = tag.get("technique_name", "?")
            if _MITRE_TECHNIQUE_ID.match(technique_id or ""):
                url = f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}/"
                lines.append(f"[{technique_id} - {technique_name}]({url}) ({tag.get('tactic', '?')}, {tag.get('source', '?')})")
            else:
                lines.append(f"{technique_id} - {technique_name} ({tag.get('tactic', '?')}, {tag.get('source', '?')})")
        embed.add_field(name="MITRE ATT&CK", value="\n".join(lines), inline=False)
    else:
        embed.add_field(name="MITRE ATT&CK", value="Not mapped", inline=False)

    actions = triage_result.get("recommended_actions") or []
    if actions:
        embed.add_field(name="Recommended Actions", value="\n".join(f"- {a}" for a in actions), inline=False)

    enrichment_text = _format_enrichment_findings(enrichment)
    if enrichment_text:
        embed.add_field(name="Enrichment Findings", value=enrichment_text, inline=False)
    else:
        embed.add_field(
            name="Enrichment Findings",
            value="No indicators were enriched (no hash, IP, or URL in alert).",
            inline=False,
        )

    kibana_url = _safe_http_url(alert_summary.get("kibana_url"))
    if kibana_url:
        embed.add_field(name="Kibana", value=f"[View alert]({kibana_url})", inline=False)

    embed.set_footer(text=f"Alert ID: {alert_summary.get('id', 'unknown')}")
    return embed


async def send_triage_result(alert_summary, triage_result, enrichment=None):
    channel = bot.get_channel(config.DISCORD_CHANNEL_ID)
    if channel is None:
        channel = await bot.fetch_channel(config.DISCORD_CHANNEL_ID)
    embed = build_embed(alert_summary, triage_result, enrichment)
    await channel.send(embed=embed)