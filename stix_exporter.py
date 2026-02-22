"""Export IOCs and threat findings in STIX 2.1 JSON format.

STIX (Structured Threat Information Expression) is the industry standard
for sharing cyber threat intelligence. This module generates valid STIX 2.1
bundles that can be imported into SIEM/SOAR platforms like Splunk, QRadar,
Sentinel, MISP, and OpenCTI.
"""

import uuid
import json
from datetime import datetime, timezone


def _stix_id(stype):
    return f"{stype}--{uuid.uuid4()}"


def _now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def generate_stix_bundle(report_dict):
    """Generate a STIX 2.1 Bundle from a PhishGuard analysis report.

    Returns a Python dict representing the full STIX bundle, ready to be
    serialized as JSON.
    """
    now = _now_iso()
    objects = []

    # --- Identity: the analysis tool ---
    identity_id = _stix_id("identity")
    objects.append({
        "type": "identity",
        "spec_version": "2.1",
        "id": identity_id,
        "created": now,
        "modified": now,
        "name": "PhishGuard Phishing Analyzer",
        "identity_class": "system",
        "description": "Automated phishing email analysis tool",
    })

    # --- Observed Data: the email itself ---
    headers = report_dict.get("headers", {})
    score = report_dict.get("score", {})
    iocs = report_dict.get("iocs", {})

    indicator_ids = []

    # --- Email Address indicators ---
    for email_addr in iocs.get("email_addresses", []):
        ind_id = _stix_id("indicator")
        indicator_ids.append(ind_id)
        objects.append({
            "type": "indicator",
            "spec_version": "2.1",
            "id": ind_id,
            "created": now,
            "modified": now,
            "name": f"Phishing email address: {email_addr}",
            "description": f"Email address extracted from analyzed phishing email (report: {report_dict.get('report_id', 'N/A')})",
            "indicator_types": ["malicious-activity"],
            "pattern": f"[email-addr:value = '{email_addr}']",
            "pattern_type": "stix",
            "valid_from": now,
            "created_by_ref": identity_id,
        })

    # --- IP Address indicators ---
    for ip in iocs.get("ip_addresses", []):
        ind_id = _stix_id("indicator")
        indicator_ids.append(ind_id)
        objects.append({
            "type": "indicator",
            "spec_version": "2.1",
            "id": ind_id,
            "created": now,
            "modified": now,
            "name": f"Suspicious IP: {ip}",
            "description": f"IP address observed in phishing email routing or body content",
            "indicator_types": ["malicious-activity"],
            "pattern": f"[ipv4-addr:value = '{ip}']",
            "pattern_type": "stix",
            "valid_from": now,
            "created_by_ref": identity_id,
        })

    # --- Domain indicators ---
    for domain in iocs.get("domains", []):
        ind_id = _stix_id("indicator")
        indicator_ids.append(ind_id)
        objects.append({
            "type": "indicator",
            "spec_version": "2.1",
            "id": ind_id,
            "created": now,
            "modified": now,
            "name": f"Phishing domain: {domain}",
            "description": f"Domain extracted from URLs in phishing email",
            "indicator_types": ["malicious-activity"],
            "pattern": f"[domain-name:value = '{domain}']",
            "pattern_type": "stix",
            "valid_from": now,
            "created_by_ref": identity_id,
        })

    # --- URL indicators ---
    for url in iocs.get("urls", []):
        ind_id = _stix_id("indicator")
        indicator_ids.append(ind_id)
        # Escape single quotes in URL for STIX pattern
        safe_url = url.replace("'", "\\'")
        objects.append({
            "type": "indicator",
            "spec_version": "2.1",
            "id": ind_id,
            "created": now,
            "modified": now,
            "name": f"Phishing URL: {url[:80]}",
            "description": f"URL found in phishing email body",
            "indicator_types": ["malicious-activity"],
            "pattern": f"[url:value = '{safe_url}']",
            "pattern_type": "stix",
            "valid_from": now,
            "created_by_ref": identity_id,
        })

    # --- File hash indicators ---
    for fh in iocs.get("file_hashes", []):
        ind_id = _stix_id("indicator")
        indicator_ids.append(ind_id)
        sha256 = fh.get("sha256", "")
        md5 = fh.get("md5", "")
        fname = fh.get("filename", "unknown")
        patterns = []
        if sha256:
            patterns.append(f"file:hashes.'SHA-256' = '{sha256}'")
        if md5:
            patterns.append(f"file:hashes.MD5 = '{md5}'")
        pattern_str = " OR ".join(f"[{p}]" for p in patterns) if patterns else "[file:name = 'unknown']"

        objects.append({
            "type": "indicator",
            "spec_version": "2.1",
            "id": ind_id,
            "created": now,
            "modified": now,
            "name": f"Malicious attachment: {fname}",
            "description": f"File attachment from phishing email",
            "indicator_types": ["malicious-activity"],
            "pattern": pattern_str,
            "pattern_type": "stix",
            "valid_from": now,
            "created_by_ref": identity_id,
        })

    # --- Malware SDO (if malware hashes matched) ---
    malware_ids = []
    for att in report_dict.get("attachments", []):
        if att.get("malware_match"):
            mal_id = _stix_id("malware")
            malware_ids.append(mal_id)
            objects.append({
                "type": "malware",
                "spec_version": "2.1",
                "id": mal_id,
                "created": now,
                "modified": now,
                "name": att["malware_match"],
                "description": f"Malware family: {att.get('malware_family', 'Unknown')}",
                "malware_types": ["trojan"],
                "is_family": False,
                "created_by_ref": identity_id,
            })

    # --- Attack Pattern (from MITRE mappings) ---
    mitre_mappings = report_dict.get("mitre_mappings", [])
    attack_pattern_ids = []
    for m in mitre_mappings:
        ap_id = _stix_id("attack-pattern")
        attack_pattern_ids.append(ap_id)
        objects.append({
            "type": "attack-pattern",
            "spec_version": "2.1",
            "id": ap_id,
            "created": now,
            "modified": now,
            "name": m.get("technique", ""),
            "description": m.get("description", ""),
            "external_references": [{
                "source_name": "mitre-attack",
                "external_id": m.get("technique_id", ""),
                "url": f"https://attack.mitre.org/techniques/{m.get('technique_id', '').replace('.', '/')}/",
            }],
            "created_by_ref": identity_id,
        })

    # --- Report SDO tying everything together ---
    report_id = _stix_id("report")
    all_refs = indicator_ids + malware_ids + attack_pattern_ids + [identity_id]
    threat_level = score.get("level", "clean")
    objects.append({
        "type": "report",
        "spec_version": "2.1",
        "id": report_id,
        "created": now,
        "modified": now,
        "name": f"PhishGuard Analysis: {report_dict.get('filename', 'Unknown')}",
        "description": (
            f"Automated phishing analysis report. "
            f"Threat level: {threat_level.upper()}. "
            f"Score: {score.get('total', 0)}/100. "
            f"From: {headers.get('from_address', 'N/A')}. "
            f"Subject: {headers.get('subject', 'N/A')}."
        ),
        "report_types": ["threat-report"],
        "published": now,
        "object_refs": all_refs,
        "created_by_ref": identity_id,
        "labels": [f"threat-level:{threat_level}"],
    })

    # --- Relationships ---
    for ind_id in indicator_ids:
        for mal_id in malware_ids:
            objects.append({
                "type": "relationship",
                "spec_version": "2.1",
                "id": _stix_id("relationship"),
                "created": now,
                "modified": now,
                "relationship_type": "indicates",
                "source_ref": ind_id,
                "target_ref": mal_id,
                "created_by_ref": identity_id,
            })
    for ind_id in indicator_ids:
        for ap_id in attack_pattern_ids:
            objects.append({
                "type": "relationship",
                "spec_version": "2.1",
                "id": _stix_id("relationship"),
                "created": now,
                "modified": now,
                "relationship_type": "indicates",
                "source_ref": ind_id,
                "target_ref": ap_id,
                "created_by_ref": identity_id,
            })

    bundle = {
        "type": "bundle",
        "id": _stix_id("bundle"),
        "objects": objects,
    }

    return bundle


def stix_to_json(bundle):
    """Serialize a STIX bundle to a JSON string."""
    return json.dumps(bundle, indent=2)
