"""Maps phishing analysis findings to MITRE ATT&CK techniques.

Each detected indicator is associated with the specific technique, tactic,
and a description of how the finding relates to the ATT&CK framework.
This gives SOC analysts an immediate operational reference.
"""

# Mapping keyed by internal finding category
TECHNIQUE_MAP = {
    # --- Initial Access (TA0001) ---
    "spf_fail": {
        "technique_id": "T1566.001",
        "technique": "Phishing: Spearphishing Attachment",
        "tactic": "Initial Access",
        "description": "SPF failure indicates the sender IP is not authorized, consistent with spoofed phishing emails.",
    },
    "spf_softfail": {
        "technique_id": "T1566.001",
        "technique": "Phishing: Spearphishing Attachment",
        "tactic": "Initial Access",
        "description": "SPF softfail suggests possible sender spoofing.",
    },
    "dkim_fail": {
        "technique_id": "T1566.001",
        "technique": "Phishing: Spearphishing Attachment",
        "tactic": "Initial Access",
        "description": "DKIM failure means the message was altered in transit or the signature is forged.",
    },
    "dmarc_fail": {
        "technique_id": "T1566.001",
        "technique": "Phishing: Spearphishing Attachment",
        "tactic": "Initial Access",
        "description": "DMARC failure confirms the email does not align with the domain's published policy.",
    },
    "display_name_spoofing": {
        "technique_id": "T1566.001",
        "technique": "Phishing: Spearphishing Attachment",
        "tactic": "Initial Access",
        "description": "Display name impersonates a trusted brand to deceive the recipient.",
    },
    "reply_to_mismatch": {
        "technique_id": "T1566.001",
        "technique": "Phishing: Spearphishing Attachment",
        "tactic": "Initial Access",
        "description": "Reply-To domain differs from sender, routing replies to an attacker-controlled address.",
    },
    "header_forgery": {
        "technique_id": "T1566.001",
        "technique": "Phishing: Spearphishing Attachment",
        "tactic": "Initial Access",
        "description": "Forged email headers indicate deliberate manipulation to bypass security controls.",
    },

    # --- Spearphishing Link (T1566.002) ---
    "known_phishing_url": {
        "technique_id": "T1566.002",
        "technique": "Phishing: Spearphishing Link",
        "tactic": "Initial Access",
        "description": "URL matches a known phishing domain from threat intelligence.",
    },
    "suspicious_url": {
        "technique_id": "T1566.002",
        "technique": "Phishing: Spearphishing Link",
        "tactic": "Initial Access",
        "description": "URL exhibits suspicious characteristics (TLD, subdomains, or structure).",
    },
    "url_redirect_chain": {
        "technique_id": "T1566.002",
        "technique": "Phishing: Spearphishing Link",
        "tactic": "Initial Access",
        "description": "Multiple redirects obscure the true destination, a common phishing evasion technique.",
    },

    # --- Resource Development (TA0042) ---
    "homoglyph": {
        "technique_id": "T1583.001",
        "technique": "Acquire Infrastructure: Domains",
        "tactic": "Resource Development",
        "description": "Domain uses character substitution (typosquatting) to impersonate a legitimate brand.",
    },
    "url_shortened": {
        "technique_id": "T1608.005",
        "technique": "Stage Capabilities: Link Target",
        "tactic": "Resource Development",
        "description": "Shortened URL hides the true destination from the recipient and email filters.",
    },
    "ip_based_url": {
        "technique_id": "T1583.003",
        "technique": "Acquire Infrastructure: Virtual Private Server",
        "tactic": "Resource Development",
        "description": "URL uses a raw IP address instead of a domain, suggesting temporary infrastructure.",
    },
    "nxdomain_sender": {
        "technique_id": "T1583.001",
        "technique": "Acquire Infrastructure: Domains",
        "tactic": "Resource Development",
        "description": "Sender domain does not exist (NXDOMAIN), indicating a disposable or fake domain.",
    },

    # --- Execution (TA0002) ---
    "executable_attachment": {
        "technique_id": "T1204.002",
        "technique": "User Execution: Malicious File",
        "tactic": "Execution",
        "description": "Executable attachment delivered via email for the victim to run.",
    },
    "macro_attachment": {
        "technique_id": "T1204.002",
        "technique": "User Execution: Malicious File",
        "tactic": "Execution",
        "description": "Macro-enabled document can execute code when macros are enabled by the victim.",
    },
    "malware_hash": {
        "technique_id": "T1204.002",
        "technique": "User Execution: Malicious File",
        "tactic": "Execution",
        "description": "File hash matches a known malware sample in threat intelligence databases.",
    },
    "vt_detection": {
        "technique_id": "T1204.002",
        "technique": "User Execution: Malicious File",
        "tactic": "Execution",
        "description": "Multiple antivirus engines on VirusTotal flag this file as malicious.",
    },
    "javascript_in_email": {
        "technique_id": "T1059.007",
        "technique": "Command and Scripting Interpreter: JavaScript",
        "tactic": "Execution",
        "description": "JavaScript embedded in the email HTML body can execute client-side code.",
    },

    # --- Credential Access (TA0006) ---
    "credential_harvesting": {
        "technique_id": "T1056.003",
        "technique": "Input Capture: Web Portal Capture",
        "tactic": "Credential Access",
        "description": "External form action in email body designed to harvest credentials.",
    },

    # --- Defense Evasion (TA0005) ---
    "hidden_text": {
        "technique_id": "T1027",
        "technique": "Obfuscated Files or Information",
        "tactic": "Defense Evasion",
        "description": "Hidden text in HTML body used to evade content-based email filters.",
    },
    "extension_mismatch": {
        "technique_id": "T1036.007",
        "technique": "Masquerading: Double File Extension",
        "tactic": "Defense Evasion",
        "description": "File extension does not match the actual file type, designed to trick users.",
    },
    "content_type_mismatch": {
        "technique_id": "T1036",
        "technique": "Masquerading",
        "tactic": "Defense Evasion",
        "description": "Declared Content-Type disagrees with detected file type based on magic bytes.",
    },
    "high_entropy": {
        "technique_id": "T1027.002",
        "technique": "Obfuscated Files or Information: Software Packing",
        "tactic": "Defense Evasion",
        "description": "High Shannon entropy suggests the file is packed, encrypted, or obfuscated.",
    },
    "suspicious_mailer": {
        "technique_id": "T1036",
        "technique": "Masquerading",
        "tactic": "Defense Evasion",
        "description": "X-Mailer header indicates a tool commonly used for phishing campaigns.",
    },

    # --- Collection (TA0009) ---
    "urgency_language": {
        "technique_id": "T1598",
        "technique": "Phishing for Information",
        "tactic": "Reconnaissance",
        "description": "Social engineering language creates urgency to pressure the victim into acting.",
    },

    # --- Command and Control (TA0011) ---
    "threat_intel_ip": {
        "technique_id": "T1071.001",
        "technique": "Application Layer Protocol: Web Protocols",
        "tactic": "Command and Control",
        "description": "IP address found in threat intelligence feeds associated with C2 infrastructure.",
    },
}


def map_findings_to_mitre(score_breakdown):
    """Given a score breakdown list, return MITRE ATT&CK mappings for each finding.

    Returns a list of dicts, each with: technique_id, technique, tactic,
    description, and the original finding reason/points.
    """
    mappings = []
    seen_techniques = set()

    for item in score_breakdown:
        reason = item.get("reason", "").lower()
        category = item.get("category", "")
        matched_key = _match_reason(reason, category)

        if matched_key and matched_key in TECHNIQUE_MAP:
            t = TECHNIQUE_MAP[matched_key]
            # Deduplicate by technique_id
            if t["technique_id"] not in seen_techniques:
                seen_techniques.add(t["technique_id"])
                mappings.append({
                    "technique_id": t["technique_id"],
                    "technique": t["technique"],
                    "tactic": t["tactic"],
                    "description": t["description"],
                    "finding": item.get("reason", ""),
                    "points": item.get("points", 0),
                })

    return mappings


def _match_reason(reason, category):
    """Map a scoring reason string to a TECHNIQUE_MAP key."""
    # Header-related
    if "spf" in reason and "fail" in reason and "soft" not in reason:
        return "spf_fail"
    if "spf" in reason and "softfail" in reason:
        return "spf_softfail"
    if "dkim" in reason and ("fail" in reason or "invalid" in reason):
        return "dkim_fail"
    if "dmarc" in reason and "fail" in reason:
        return "dmarc_fail"
    if "display name" in reason and "spoof" in reason:
        return "display_name_spoofing"
    if "reply-to" in reason and "mismatch" in reason:
        return "reply_to_mismatch"
    if "forged" in reason or ("suspicious" in reason and "header" in reason):
        return "header_forgery"
    if "nxdomain" in reason or "does not exist" in reason:
        return "nxdomain_sender"
    if "no email authentication" in reason or "spf/dkim/dmarc all absent" in reason:
        return "header_forgery"
    if "x-mailer" in reason:
        return "suspicious_mailer"

    # URL-related
    if "known phishing" in reason:
        return "known_phishing_url"
    if "typosquatting" in reason or "character substitution" in reason or "homoglyph" in reason:
        return "homoglyph"
    if "redirect" in reason:
        return "url_redirect_chain"
    if "shortened" in reason:
        return "url_shortened"
    if "ip-based" in reason or "raw ip" in reason:
        return "ip_based_url"
    if "suspicious tld" in reason:
        return "suspicious_url"

    # Attachment-related
    if "malware hash" in reason or "local hash match" in reason:
        return "malware_hash"
    if "virustotal" in reason:
        return "vt_detection"
    if "executable" in reason:
        return "executable_attachment"
    if "macro" in reason:
        return "macro_attachment"
    if "type mismatch" in reason and category == "attachments":
        return "extension_mismatch"
    if "content-type mismatch" in reason:
        return "content_type_mismatch"
    if "entropy" in reason:
        return "high_entropy"

    # Body-related
    if "urgency" in reason:
        return "urgency_language"
    if "javascript" in reason:
        return "javascript_in_email"
    if "form" in reason and "external" in reason:
        return "credential_harvesting"
    if "hidden text" in reason:
        return "hidden_text"

    # IP-related
    if "threat intel" in reason:
        return "threat_intel_ip"

    return None


def get_attack_summary(mappings):
    """Generate a high-level ATT&CK kill chain summary from the mappings."""
    if not mappings:
        return {"kill_chain_phases": [], "technique_count": 0, "tactic_coverage": []}

    tactics_seen = []
    kill_chain_order = [
        "Reconnaissance", "Resource Development", "Initial Access",
        "Execution", "Defense Evasion", "Credential Access",
        "Command and Control",
    ]
    for tactic in kill_chain_order:
        if any(m["tactic"] == tactic for m in mappings):
            tactics_seen.append(tactic)

    return {
        "kill_chain_phases": tactics_seen,
        "technique_count": len(mappings),
        "tactic_coverage": tactics_seen,
    }
