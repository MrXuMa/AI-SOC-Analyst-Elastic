def extract_elastic_attack_tags(source):
    threat_entries = source.get("kibana.alert.rule.threat") or []
    tags = []
    for entry in threat_entries:
        tactic = entry.get("tactic") or {}
        for technique in entry.get("technique") or []:
            subtechniques = technique.get("subtechnique") or []
            if subtechniques:
                for sub in subtechniques:
                    tags.append({
                        "tactic": tactic.get("name"),
                        "tactic_id": tactic.get("id"),
                        "technique_id": sub.get("id"),
                        "technique_name": sub.get("name"),
                        "source": "elastic",
                    })

            else:
                tags.append({
                    "tactic": tactic.get("name"),
                    "tactic_id": tactic.get("id"),
                    "technique_id": technique.get("id"),
                    "technique_name": technique.get("name"),
                    "source": "elastic",
                })

    return tags