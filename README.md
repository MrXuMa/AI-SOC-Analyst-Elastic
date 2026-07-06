# AI Analyst — Elastic SOC Triage + Discord

Polls Elasticsearch Security alerts, enriches IOCs (VirusTotal, AbuseIPDB, MalwareBazaar, URLhaus), triages with Anthropic Claude, and posts color-coded summaries to Discord with MITRE ATT&CK mapping.

Works with any Elastic Security deployment — bring your own Elasticsearch credentials and API keys.

## Prerequisites

- Elastic Security alerts index reachable (default: `https://localhost:9200`)
- Python 3.12+
- API keys in `.env` (see below)

## Setup

```bash
git clone <your-repo-url> ai-analyst
cd ai-analyst
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
chmod 600 .env
# Edit .env with your keys and Elasticsearch settings
python assets.py   # optional: inspect example asset inventory
```

### Required `.env` variables

| Variable | Purpose |
|----------|---------|
| `VIRUSTOTAL_API_KEY` | Hash/IP/URL lookups ([VirusTotal](https://www.virustotal.com/gui/my-apikey)) |
| `ANTHROPIC_API_KEY` | Claude triage ([Anthropic Console](https://console.anthropic.com/)) |
| `DISCORD_BOT_TOKEN` | Bot token ([Discord Developer Portal](https://discord.com/developers/applications)) |
| `DISCORD_CHANNEL_ID` | Numeric channel ID for alert posts |

### Elasticsearch credentials

Pick one approach:

**Option A — direct credentials** (any Elastic deployment):

| Variable | Purpose |
|----------|---------|
| `ELASTIC_PASSWORD` | Elasticsearch `elastic` user password |
| `ELASTIC_CA_CERT` | Path to CA cert for TLS verification |

**Option B — local stack directory** (convenience for homelab setups):

| Variable | Purpose |
|----------|---------|
| `SIEM_STACK_DIR` | Directory containing `.env` (`ELASTIC_PASSWORD`) and `certs/ca/ca.crt` |

If neither is set, the app looks for `~/siem-stack` as a fallback when that directory exists.

### Optional `.env` variables

| Variable | Purpose |
|----------|---------|
| `ELASTIC_URL` | Default: `https://localhost:9200` |
| `ELASTIC_USER` | Default: `elastic` |
| `ABUSEIPDB_API_KEY` | IP reputation ([AbuseIPDB](https://www.abuseipdb.com/account/api)) |
| `ABUSE_CH_AUTH_KEY` | MalwareBazaar + URLhaus ([abuse.ch](https://auth.abuse.ch/)) |
| `ANTHROPIC_MODEL` | Default: `claude-haiku-4-5-20251001` |
| `POLL_INTERVAL_SECONDS` | Default: `60` |

### Discord bot permissions

Create a bot, enable **Message Content Intent** if needed, invite with `Send Messages` and `Embed Links`. Paste the target channel ID into `DISCORD_CHANNEL_ID`.

## Usage

```bash
source venv/bin/activate

# Test full pipeline on a saved alert JSON export (no live ES, no Discord)
python poller.py --replay /path/to/alert.json --dry-run

# One-shot live fetch; print results, do not post to Discord
python poller.py --dry-run

# Live mode: Discord bot + continuous polling
python poller.py
```

On first live/dry-run start, `poller_state.json` seeds to **now** so historical alerts are not reprocessed. Use `--replay` for testing saved alerts.

## systemd (persistent service)

Generate a unit file from the template (replace paths and user):

```bash
INSTALL_DIR="$(pwd)"
USER="$(whoami)"

# System service (requires sudo)
sed -e "s|@INSTALL_DIR@|$INSTALL_DIR|g" -e "s|@USER@|$USER|g" \
  ai-analyst.service.example | sudo tee /etc/systemd/system/ai-analyst.service
sudo systemctl daemon-reload
sudo systemctl enable --now ai-analyst.service

# User service (no sudo)
mkdir -p ~/.config/systemd/user
sed -e "s|@INSTALL_DIR@|$INSTALL_DIR|g" \
  ai-analyst.user.service.example > ~/.config/systemd/user/ai-analyst.service
systemctl --user daemon-reload
systemctl --user enable --now ai-analyst.service
```

Check logs:

```bash
journalctl -u ai-analyst.service -f          # system service
journalctl --user -u ai-analyst.service -f   # user service
```

## Project layout

| Path | Role |
|------|------|
| `poller.py` | Entrypoint: fetch → dedupe → enrich → triage → Discord |
| `fetch_alert.py` | Elasticsearch query + `build_summary()` |
| `indicators.py` | Extract hashes, public IPs, URLs from alerts |
| `enrichment/` | VirusTotal, AbuseIPDB, MalwareBazaar, URLhaus + cache |
| `triage/claude_agent.py` | Claude structured triage |
| `discord_bot/bot.py` | Rich embeds + background poll loop |
| `assets.py` | Host inventory lookup (edit `SEED_ASSETS` for your environment) |
| `dedupe.db` | Incident deduplication (gitignored, created at runtime) |
| `enrichment_cache.db` | API result cache (gitignored) |
| `poller_state.json` | Last-processed alert timestamp (gitignored) |