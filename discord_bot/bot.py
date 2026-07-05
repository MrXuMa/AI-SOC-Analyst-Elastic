import asyncio
import re
from urllib.parse import urlparse

import discord
from discord.ext import tasks

import config
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

        for alert_summary, _enrichment, triage_result in results:
            await send_triage_result(alert_summary, triage_result)

        poller.save_checkpoint(new_checkpoint)

        if hit_cap:
            print("Batch hit the alert cap - draining backlog immediately.")


@bot.event
async def on_ready():
    print(f"Discord bot logged in as {bot.user}", flush=True)
    if not poll_task.is_running():
        poll_task.start()


def build_embed(alert_summary, triage_result):
    verdict = triage_result.get("verdict", "needs_review")
    color = VERDICT_COLORS.get(verdict, discord.Color.light_grey())
    emoji = VERDICT_EMOJI.get(verdict, "\u26AA")

    embed = discord.Embed(
        title=f"{emoji} {alert_summary.get('alert_name', 'Unknown Alert')}",
        description=triage_result.get("summary", ""),
        color=color,
    )

    embed.add_field(name="Verdict", value=f"{verdict} ({triage_result.get('confidence', 0):.0%} confidence)", inline=True)
    embed.add_field(name="Host", value=alert_summary.get("host_name") or "unknown", inline=True)
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

    kibana_url = _safe_http_url(alert_summary.get("kibana_url"))
    if kibana_url:
        embed.add_field(name="Kibana", value=f"[View alert]({kibana_url})", inline=False)

    embed.set_footer(text=f"Alert ID: {alert_summary.get('id', 'unknown')}")
    return embed


async def send_triage_result(alert_summary, triage_result):
    channel = bot.get_channel(config.DISCORD_CHANNEL_ID)
    if channel is None:
        channel = await bot.fetch_channel(config.DISCORD_CHANNEL_ID)
    embed = build_embed(alert_summary, triage_result)
    await channel.send(embed=embed)