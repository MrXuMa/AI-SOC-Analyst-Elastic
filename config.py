import os
from pathlib import Path

from dotenv import load_dotenv

AI_ANALYST_DIR = Path(__file__).resolve().parent

load_dotenv(AI_ANALYST_DIR / ".env")


def _optional_siem_stack_dir() -> Path | None:
    if path := os.environ.get("SIEM_STACK_DIR"):
        return Path(path)
    default = Path.home() / "siem-stack"
    if default.is_dir():
        return default
    return None


def _load_elastic_password() -> str:
    if password := os.environ.get("ELASTIC_PASSWORD"):
        return password

    siem_stack_dir = _optional_siem_stack_dir()
    if siem_stack_dir is not None:
        env_path = siem_stack_dir / ".env"
        with open(env_path) as f:
            for line in f:
                line = line.strip()
                if line.startswith("ELASTIC_PASSWORD="):
                    return line.split("=", 1)[1]
        raise RuntimeError(f"ELASTIC_PASSWORD not found in {env_path}")

    raise RuntimeError(
        "Set ELASTIC_PASSWORD in .env, or set SIEM_STACK_DIR to a stack directory "
        "that contains .env with ELASTIC_PASSWORD"
    )


def _resolve_ca_cert() -> str:
    if cert := os.environ.get("ELASTIC_CA_CERT"):
        return cert

    siem_stack_dir = _optional_siem_stack_dir()
    if siem_stack_dir is not None:
        return str(siem_stack_dir / "certs" / "ca" / "ca.crt")

    raise RuntimeError(
        "Set ELASTIC_CA_CERT in .env, or set SIEM_STACK_DIR to a stack directory "
        "that contains certs/ca/ca.crt"
    )


def _require(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"{name} is not set")
    return value


# Elasticsearch
ELASTIC_URL = os.environ.get("ELASTIC_URL", "https://localhost:9200")
ELASTIC_USER = os.environ.get("ELASTIC_USER", "elastic")
ELASTIC_PASSWORD = _load_elastic_password()
CA_CERT = _resolve_ca_cert()
# Enrichment APIs
VIRUSTOTAL_API_KEY = _require("VIRUSTOTAL_API_KEY")
ABUSEIPDB_API_KEY = os.environ.get("ABUSEIPDB_API_KEY")  # optional
ABUSE_CH_AUTH_KEY = os.environ.get("ABUSE_CH_AUTH_KEY")  # optional
# Triage
ANTHROPIC_API_KEY = _require("ANTHROPIC_API_KEY")
ANTHROPIC_MODEL = os.environ.get("ANTHROPIC_MODEL", "claude-haiku-4-5-20251001")
# Discord
DISCORD_BOT_TOKEN = _require("DISCORD_BOT_TOKEN")
DISCORD_CHANNEL_ID = int(_require("DISCORD_CHANNEL_ID"))
# Polling
POLL_INTERVAL_SECONDS = int(os.environ.get("POLL_INTERVAL_SECONDS", "60"))
