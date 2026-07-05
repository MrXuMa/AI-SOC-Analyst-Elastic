import json

import anthropic

import config

TRIAGE_TOOL = {
    "name": "submit_triage",
    "description": "Submit the SOC triage result for this alert.",
    "input_schema": {
        "type": "object",
        "properties": {
            "verdict":{
                "type": "string",
                "enum": ["malicious", "suspicious", "benign", "needs_review"],
            },
            "confidence": {
                "type": "number",
                "description": "0.0 to 1.0 confidence in the verdict",
            },
            "summary": {
                "type": "string",
                "description": "2-4 sentence plain-English summary of what happened",
            },
            "recommended_actions": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Concrete next steps a SOC analyst should take",
            },
            "reasoning": {
                "type": "string",
                "description": "Brief explanation of why this verdict was reached",
            },
            "mitre_attack": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "tactic": {"type": "string"},
                        "technique_id": {"type": "string"},
                        "technique_name": {"type": "string"},
                        "source": {"type": "string", "enum": ["elastic", "inferred"]},
                    },
                    "required": ["tactic", "technique_id", "technique_name", "source"],
                },
            },
        },
        "required": ["verdict", "confidence", "summary", "recommended_actions", "reasoning", "mitre_attack"],
    },
}

SYSTEM_PROMPT = """You are a SOC (Security Operations Center) triage assistant for a homelab Elastic SIEM. You will be given a structured summary of a single Elastic Defend/Security alert, plus threat-intel enrichment results (VirusTotal, AbuseIPDB, MalwareBazaar, URLhaus) for any relevant indicators (file hashes, IPs, URLs).
Your job is to call the submit_triage tool with:
- verdict: your overall assessment (malicious, suspicious, benign, or needs_review if you don't have enough information)
- confidence: how confident you are (0.0-1.0)
- summary: a short, plain-English explanation of what happened, written for a human who will read it in Discord
- recommended_actions: concrete next steps (e.g. "isolate host", "no action needed - known test file", "block IP at firewall")
- reasoning: why you reached this verdict, referencing specific enrichment data points
- mitre_attack: MITRE ATT&CK tactic/technique mapping for this alert
For mitre_attack: if the alert JSON already includes non-empty elastic_attack_tags, use those directly and set source="elastic" for each entry. If elastic_attack_tags is empty, infer the most likely tactic(s)/technique(s) yourself from the alert's process, command line, and file details, and set source="inferred". Only include a technique_id you are reasonably confident is a real, correctly-formatted MITRE ATT&CK technique ID (e.g. T1059.001). If you cannot confidently map to a specific technique, return an empty mitre_attack list rather than guessing.
Known test/benign patterns to recognize: EICAR test files and eicar.org URLs are industry-standard antivirus test signatures, not real malware - alerts about them should generally be verdict="benign" with high confidence unless other indicators suggest otherwise.
"""

def _build_user_message(alert_summary, enrichment):
    payload = {"alert": alert_summary, "enrichment": enrichment}
    return json.dumps(payload, indent=2, default=str)

def triage_alert(alert_summary, enrichment):
    client = anthropic.Anthropic(api_key=config.ANTHROPIC_API_KEY)

    message = client.messages.create(
        model=config.ANTHROPIC_MODEL,
        max_tokens=1024,
        system=SYSTEM_PROMPT,
        tools=[TRIAGE_TOOL],
        tool_choice={"type": "tool", "name": "submit_triage"},
        messages=[
            {"role": "user", "content": _build_user_message(alert_summary, enrichment)},
        ],
    )

    for block in message.content:
        if block.type == "tool_use" and block.name == "submit_triage":
            return block.input

    raise RuntimeError("No tool use found in response")