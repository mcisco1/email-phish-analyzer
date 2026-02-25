"""Maps phishing analysis findings to MITRE ATT&CK techniques.

Each detected indicator is associated with the specific technique/sub-technique,
tactic, description, detection recommendation, and kill chain phase.
This gives SOC analysts an immediate operational reference.

Covers 40+ mappings across 10 tactics with sub-technique precision.
"""

# Mapping keyed by internal finding category
TECHNIQUE_MAP = {
    # =====================================================================
    # Reconnaissance (TA0043)
    # =====================================================================
    "urgency_language": {
        "technique_id": "T1598.003",
        "technique": "Phishing for Information: Spearphishing Link",
        "tactic": "Reconnaissance",
        "kill_chain_phase": "Reconnaissance",
        "description": "Social engineering language creates urgency to pressure the victim into revealing information or credentials.",
        "detection": "Train users to recognize urgency-based manipulation. Deploy email content inspection rules for common phishing phrases. Monitor for emails with high urgency language scores.",
    },
    "nlp_social_engineering": {
        "technique_id": "T1598",
        "technique": "Phishing for Information",
        "tactic": "Reconnaissance",
        "kill_chain_phase": "Reconnaissance",
        "description": "NLP analysis detected social engineering patterns: manipulation language, impersonation, or threat-based persuasion techniques.",
        "detection": "Deploy NLP-based content analysis on inbound emails. Monitor for emails with high social engineering scores. Train users on social engineering tactics.",
    },

    # =====================================================================
    # Resource Development (TA0042)
    # =====================================================================
    "homoglyph": {
        "technique_id": "T1583.001",
        "technique": "Acquire Infrastructure: Domains",
        "tactic": "Resource Development",
        "kill_chain_phase": "Weaponization",
        "description": "Domain uses character substitution (typosquatting) to impersonate a legitimate brand.",
        "detection": "Monitor for newly registered domains similar to your organization. Deploy homoglyph detection in email gateway. Use DNS monitoring for look-alike domains.",
    },
    "idn_homograph": {
        "technique_id": "T1583.001",
        "technique": "Acquire Infrastructure: Domains",
        "tactic": "Resource Development",
        "kill_chain_phase": "Weaponization",
        "description": "IDN homograph attack using Cyrillic, Greek, or other Unicode look-alike characters to impersonate a legitimate domain. The domain appears identical visually but resolves differently.",
        "detection": "Enable IDN display policies in browsers and email clients. Block punycode domains that mix scripts. Monitor for xn-- prefixed domains in email URLs.",
    },
    "url_shortened": {
        "technique_id": "T1608.005",
        "technique": "Stage Capabilities: Link Target",
        "tactic": "Resource Development",
        "kill_chain_phase": "Weaponization",
        "description": "Shortened URL hides the true destination from the recipient and email filters.",
        "detection": "Expand shortened URLs at the email gateway before delivery. Block or quarantine emails with shortened URLs from untrusted senders.",
    },
    "ip_based_url": {
        "technique_id": "T1583.003",
        "technique": "Acquire Infrastructure: Virtual Private Server",
        "tactic": "Resource Development",
        "kill_chain_phase": "Weaponization",
        "description": "URL uses a raw IP address instead of a domain, suggesting temporary attacker infrastructure.",
        "detection": "Block or flag emails containing IP-based URLs. Monitor outbound connections to IP-only destinations.",
    },
    "nxdomain_sender": {
        "technique_id": "T1585.002",
        "technique": "Establish Accounts: Email Accounts",
        "tactic": "Resource Development",
        "kill_chain_phase": "Weaponization",
        "description": "Sender domain does not exist (NXDOMAIN), indicating a disposable or fake domain used for a phishing campaign.",
        "detection": "Reject emails from domains that fail DNS resolution. Implement SPF/DKIM/DMARC enforcement.",
    },
    "brand_impersonation": {
        "technique_id": "T1583.001",
        "technique": "Acquire Infrastructure: Domains",
        "tactic": "Resource Development",
        "kill_chain_phase": "Weaponization",
        "description": "HTML similarity analysis detected brand impersonation — the page structure closely mimics a known brand login page (Google, Microsoft, Apple, banks).",
        "detection": "Deploy HTML similarity scanning on URLs in inbound emails. Compare landing pages against known brand templates. Monitor for credential-harvesting pages cloning your organization.",
    },

    # =====================================================================
    # Initial Access (TA0001)
    # =====================================================================
    "spf_fail": {
        "technique_id": "T1566.001",
        "technique": "Phishing: Spearphishing Attachment",
        "tactic": "Initial Access",
        "kill_chain_phase": "Delivery",
        "description": "SPF failure indicates the sender IP is not authorized to send for this domain, consistent with spoofed phishing emails.",
        "detection": "Enforce SPF hard fail (-all) policy. Configure email gateway to reject SPF failures. Monitor SPF authentication results in email logs.",
    },
    "spf_softfail": {
        "technique_id": "T1566.001",
        "technique": "Phishing: Spearphishing Attachment",
        "tactic": "Initial Access",
        "kill_chain_phase": "Delivery",
        "description": "SPF softfail suggests possible sender spoofing — the sender IP is not explicitly authorized.",
        "detection": "Upgrade SPF policy from ~all to -all. Quarantine emails with SPF softfail from unknown domains.",
    },
    "dkim_fail": {
        "technique_id": "T1566.001",
        "technique": "Phishing: Spearphishing Attachment",
        "tactic": "Initial Access",
        "kill_chain_phase": "Delivery",
        "description": "DKIM failure means the message was altered in transit or the signature is forged.",
        "detection": "Enforce DKIM verification at the email gateway. Monitor for DKIM failures from domains that normally pass. Alert on headers with invalid DKIM signatures.",
    },
    "dmarc_fail": {
        "technique_id": "T1566.001",
        "technique": "Phishing: Spearphishing Attachment",
        "tactic": "Initial Access",
        "kill_chain_phase": "Delivery",
        "description": "DMARC failure confirms the email does not align with the domain's published authentication policy.",
        "detection": "Set DMARC policy to p=reject. Monitor DMARC aggregate reports for unauthorized senders. Alert on DMARC failures from high-value domains.",
    },
    "display_name_spoofing": {
        "technique_id": "T1566.001",
        "technique": "Phishing: Spearphishing Attachment",
        "tactic": "Initial Access",
        "kill_chain_phase": "Delivery",
        "description": "Display name impersonates a trusted brand or executive to deceive the recipient into trusting the message.",
        "detection": "Implement display name impersonation detection rules. Flag emails where the display name matches an internal executive but the domain is external.",
    },
    "reply_to_mismatch": {
        "technique_id": "T1566.001",
        "technique": "Phishing: Spearphishing Attachment",
        "tactic": "Initial Access",
        "kill_chain_phase": "Delivery",
        "description": "Reply-To domain differs from sender, routing replies to an attacker-controlled address.",
        "detection": "Flag emails where Reply-To domain differs from From domain. Alert when Reply-To uses a free email provider while From uses a corporate domain.",
    },
    "header_forgery": {
        "technique_id": "T1566.001",
        "technique": "Phishing: Spearphishing Attachment",
        "tactic": "Initial Access",
        "kill_chain_phase": "Delivery",
        "description": "Forged email headers indicate deliberate manipulation to bypass security controls.",
        "detection": "Deploy header analysis at the email gateway. Monitor for inconsistencies between Received headers and declared sender information.",
    },
    "known_phishing_url": {
        "technique_id": "T1566.002",
        "technique": "Phishing: Spearphishing Link",
        "tactic": "Initial Access",
        "kill_chain_phase": "Delivery",
        "description": "URL matches a known phishing domain from threat intelligence feeds.",
        "detection": "Integrate threat intelligence feeds (PhishTank, URLhaus) into email gateway. Block known phishing URLs at the proxy/firewall level. Deploy URL rewriting and time-of-click analysis.",
    },
    "suspicious_url": {
        "technique_id": "T1566.002",
        "technique": "Phishing: Spearphishing Link",
        "tactic": "Initial Access",
        "kill_chain_phase": "Delivery",
        "description": "URL exhibits suspicious characteristics (suspicious TLD, excessive subdomains, or anomalous structure).",
        "detection": "Deploy URL analysis at the email gateway. Monitor for emails containing URLs with suspicious TLDs or excessive subdomains.",
    },
    "url_redirect_chain": {
        "technique_id": "T1566.002",
        "technique": "Phishing: Spearphishing Link",
        "tactic": "Initial Access",
        "kill_chain_phase": "Delivery",
        "description": "Multiple redirects obscure the true destination, a common phishing evasion technique to bypass URL reputation checks.",
        "detection": "Follow redirect chains to final destination before evaluating reputation. Deploy time-of-click URL analysis that follows redirects.",
    },
    "intermediate_phishing_domain": {
        "technique_id": "T1566.002",
        "technique": "Phishing: Spearphishing Link",
        "tactic": "Initial Access",
        "kill_chain_phase": "Delivery",
        "description": "An intermediate redirect hop passes through a known phishing or suspicious domain, indicating multi-stage phishing infrastructure.",
        "detection": "Analyze all domains in redirect chains, not just the initial and final URLs. Block intermediate redirectors known to be associated with phishing.",
    },
    "spearphishing_service": {
        "technique_id": "T1566.003",
        "technique": "Phishing: Spearphishing via Service",
        "tactic": "Initial Access",
        "kill_chain_phase": "Delivery",
        "description": "Email uses a third-party service (file sharing, cloud storage) to deliver phishing content, bypassing email gateway URL checks.",
        "detection": "Inspect links to cloud storage and file sharing services. Monitor for unusual sharing activity from external accounts.",
    },
    "iframe_attack": {
        "technique_id": "T1189",
        "technique": "Drive-by Compromise",
        "tactic": "Initial Access",
        "kill_chain_phase": "Delivery",
        "description": "External iframe embeds malicious content from a different domain, enabling drive-by attacks or content injection.",
        "detection": "Block external iframes in sandboxed email rendering. Monitor for pages that load cross-origin iframes immediately after email click-through.",
    },

    # =====================================================================
    # Execution (TA0002)
    # =====================================================================
    "executable_attachment": {
        "technique_id": "T1204.002",
        "technique": "User Execution: Malicious File",
        "tactic": "Execution",
        "kill_chain_phase": "Installation",
        "description": "Executable attachment delivered via email for the victim to run.",
        "detection": "Block executable file types at the email gateway. Quarantine emails with executable attachments. Deploy endpoint detection for unsigned executable launches from email clients.",
    },
    "macro_attachment": {
        "technique_id": "T1204.002",
        "technique": "User Execution: Malicious File",
        "tactic": "Execution",
        "kill_chain_phase": "Installation",
        "description": "Macro-enabled document can execute code when macros are enabled by the victim.",
        "detection": "Disable macros by default via Group Policy. Block macro-enabled file types at the email gateway. Deploy ASR rules to prevent Office applications from creating child processes.",
    },
    "malware_hash": {
        "technique_id": "T1204.002",
        "technique": "User Execution: Malicious File",
        "tactic": "Execution",
        "kill_chain_phase": "Installation",
        "description": "File hash matches a known malware sample in threat intelligence databases.",
        "detection": "Integrate file hash checking into email gateway and endpoint protection. Submit unknown file hashes to threat intelligence platforms (VirusTotal, MISP).",
    },
    "vt_detection": {
        "technique_id": "T1204.002",
        "technique": "User Execution: Malicious File",
        "tactic": "Execution",
        "kill_chain_phase": "Installation",
        "description": "Multiple antivirus engines on VirusTotal flag this file as malicious.",
        "detection": "Deploy multi-engine AV scanning on email attachments. Submit suspicious files to sandbox detonation services. Block files with multiple AV detections.",
    },
    "javascript_in_email": {
        "technique_id": "T1059.007",
        "technique": "Command and Scripting Interpreter: JavaScript",
        "tactic": "Execution",
        "kill_chain_phase": "Installation",
        "description": "JavaScript embedded in the email HTML body can execute client-side code in vulnerable email clients.",
        "detection": "Strip JavaScript from HTML emails at the gateway. Deploy Content Security Policy headers. Monitor for JavaScript execution originating from email client processes.",
    },
    "js_redirect": {
        "technique_id": "T1204.001",
        "technique": "User Execution: Malicious Link",
        "tactic": "Execution",
        "kill_chain_phase": "Exploitation",
        "description": "JavaScript-based redirect detected during browser detonation, which evades static URL analysis and email gateway scanning.",
        "detection": "Deploy browser-based URL detonation that executes JavaScript. Compare static redirect destination with JS-rendered final URL. Alert on URL domain changes after JS execution.",
    },
    "meta_refresh": {
        "technique_id": "T1204.001",
        "technique": "User Execution: Malicious Link",
        "tactic": "Execution",
        "kill_chain_phase": "Exploitation",
        "description": "HTML meta refresh tag redirects the user after page load, bypassing URL filters that only inspect the initial URL.",
        "detection": "Parse HTML content for meta refresh tags during URL analysis. Follow meta refresh redirects to final destination before reputation check.",
    },

    # =====================================================================
    # Persistence (TA0003)
    # =====================================================================
    "yara_embedded_exe": {
        "technique_id": "T1137.001",
        "technique": "Office Application Startup: Office Template Macros",
        "tactic": "Persistence",
        "kill_chain_phase": "Installation",
        "description": "YARA rules detected embedded executable content within a document, which may establish persistence via Office startup.",
        "detection": "Scan documents for embedded PE headers. Monitor Office template directories for modifications. Deploy ASR rules to prevent Office from launching executables.",
    },

    # =====================================================================
    # Defense Evasion (TA0005)
    # =====================================================================
    "hidden_text": {
        "technique_id": "T1027.006",
        "technique": "Obfuscated Files or Information: HTML Smuggling",
        "tactic": "Defense Evasion",
        "kill_chain_phase": "Delivery",
        "description": "Hidden text in HTML body used to evade content-based email filters by making the visible content differ from the parseable content.",
        "detection": "Compare visible text rendering against raw HTML content. Flag emails where hidden elements contain different text than displayed.",
    },
    "extension_mismatch": {
        "technique_id": "T1036.007",
        "technique": "Masquerading: Double File Extension",
        "tactic": "Defense Evasion",
        "kill_chain_phase": "Delivery",
        "description": "File extension does not match the actual file type (e.g., invoice.pdf.exe), designed to trick users into executing malicious files.",
        "detection": "Verify file types by magic bytes, not just extension. Block double-extension files at the email gateway. Show file extensions by default on endpoints.",
    },
    "content_type_mismatch": {
        "technique_id": "T1036.008",
        "technique": "Masquerading: Masquerade File Type",
        "tactic": "Defense Evasion",
        "kill_chain_phase": "Delivery",
        "description": "Declared Content-Type disagrees with detected file type based on magic bytes, indicating potential masquerading.",
        "detection": "Perform magic byte detection on all attachments regardless of declared MIME type. Alert on Content-Type mismatches.",
    },
    "high_entropy": {
        "technique_id": "T1027.002",
        "technique": "Obfuscated Files or Information: Software Packing",
        "tactic": "Defense Evasion",
        "kill_chain_phase": "Delivery",
        "description": "High Shannon entropy suggests the file is packed, encrypted, or obfuscated to evade static analysis.",
        "detection": "Flag files with entropy above 7.5 for additional scrutiny. Submit high-entropy files to sandbox detonation. Monitor for packed executables launched from temp directories.",
    },
    "suspicious_mailer": {
        "technique_id": "T1036.005",
        "technique": "Masquerading: Match Legitimate Name or Location",
        "tactic": "Defense Evasion",
        "kill_chain_phase": "Delivery",
        "description": "X-Mailer header indicates a tool commonly used for phishing campaigns (GoPhish, King Phisher, etc.).",
        "detection": "Monitor X-Mailer headers for known phishing frameworks. Alert on emails sent from tools associated with social engineering.",
    },

    # =====================================================================
    # Credential Access (TA0006)
    # =====================================================================
    "credential_harvesting": {
        "technique_id": "T1056.003",
        "technique": "Input Capture: Web Portal Capture",
        "tactic": "Credential Access",
        "kill_chain_phase": "Exploitation",
        "description": "External form action in email body designed to capture credentials submitted by the victim.",
        "detection": "Inspect form actions in HTML emails for external URLs. Block emails with forms that POST to external domains. Train users to check URL bars before entering credentials.",
    },
    "browser_credential_form": {
        "technique_id": "T1056.003",
        "technique": "Input Capture: Web Portal Capture",
        "tactic": "Credential Access",
        "kill_chain_phase": "Exploitation",
        "description": "Headless browser detonation detected a credential harvesting form with password input fields on the landing page.",
        "detection": "Deploy browser-based URL detonation that inspects rendered page content. Alert on landing pages with password fields that don't match the expected domain.",
    },
    "credential_phishing_page": {
        "technique_id": "T1556.006",
        "technique": "Modify Authentication Process: Multi-Factor Authentication Interception",
        "tactic": "Credential Access",
        "kill_chain_phase": "Exploitation",
        "description": "Landing page mimics a legitimate login portal and may intercept MFA tokens using real-time phishing proxies (evilginx, modlishka).",
        "detection": "Deploy FIDO2/WebAuthn for MFA to prevent token interception. Monitor for real-time phishing proxy indicators. Alert on login pages served from non-corporate domains.",
    },

    # =====================================================================
    # Discovery (TA0007)
    # =====================================================================
    "email_harvesting": {
        "technique_id": "T1589.002",
        "technique": "Gather Victim Identity Information: Email Addresses",
        "tactic": "Reconnaissance",
        "kill_chain_phase": "Reconnaissance",
        "description": "Email targeting pattern suggests prior reconnaissance to gather victim email addresses.",
        "detection": "Monitor for targeted phishing against specific individuals or roles. Deploy email address harvesting detection on public-facing web properties.",
    },

    # =====================================================================
    # Command and Control (TA0011)
    # =====================================================================
    "threat_intel_ip": {
        "technique_id": "T1071.001",
        "technique": "Application Layer Protocol: Web Protocols",
        "tactic": "Command and Control",
        "kill_chain_phase": "C2",
        "description": "IP address found in threat intelligence feeds associated with C2 infrastructure.",
        "detection": "Deploy IP reputation checking at the firewall/proxy level. Block connections to known C2 IPs. Monitor for beaconing patterns to flagged IP addresses.",
    },
    "threat_intel_feed_hit": {
        "technique_id": "T1071.001",
        "technique": "Application Layer Protocol: Web Protocols",
        "tactic": "Command and Control",
        "kill_chain_phase": "C2",
        "description": "IOC (IP, domain, or URL) flagged by one or more external threat intelligence feeds (AbuseIPDB, URLhaus, PhishTank, AlienVault OTX).",
        "detection": "Integrate multiple threat intelligence feeds into SIEM correlation rules. Deploy automated IOC blocking at network perimeter. Monitor for connections to threat-intel-flagged destinations.",
    },

    # =====================================================================
    # YARA-specific findings
    # =====================================================================
    "yara_phishing": {
        "technique_id": "T1566.001",
        "technique": "Phishing: Spearphishing Attachment",
        "tactic": "Initial Access",
        "kill_chain_phase": "Delivery",
        "description": "YARA rules matched phishing patterns (credential harvesting HTML, brand impersonation, data exfiltration) in the attachment.",
        "detection": "Deploy YARA rule scanning on email attachments. Update rules regularly from threat intelligence sources. Quarantine attachments that match phishing YARA signatures.",
    },
    "yara_macro": {
        "technique_id": "T1204.002",
        "technique": "User Execution: Malicious File",
        "tactic": "Execution",
        "kill_chain_phase": "Installation",
        "description": "YARA rules detected malicious macro patterns with auto-execution triggers or download capabilities.",
        "detection": "Block macro-enabled documents from external senders. Deploy YARA scanning for VBA patterns. Monitor for Office processes spawning cmd.exe or PowerShell.",
    },
    "yara_exploit": {
        "technique_id": "T1203",
        "technique": "Exploitation for Client Execution",
        "tactic": "Execution",
        "kill_chain_phase": "Exploitation",
        "description": "YARA rules identified exploit patterns (PDF JavaScript, RTF OLE objects, embedded shellcode) in the attachment.",
        "detection": "Deploy exploit detection rules on email attachments. Keep document viewers patched. Use application sandboxing for document rendering.",
    },
    "yara_script": {
        "technique_id": "T1059.001",
        "technique": "Command and Scripting Interpreter: PowerShell",
        "tactic": "Execution",
        "kill_chain_phase": "Installation",
        "description": "YARA rules detected suspicious scripting patterns (PowerShell commands, WScript execution, ActiveX controls) in the attachment.",
        "detection": "Enable PowerShell script block logging. Deploy AMSI for script content inspection. Block PowerShell execution from Office processes via ASR rules.",
    },
    "yara_evasion": {
        "technique_id": "T1027.010",
        "technique": "Obfuscated Files or Information: Command Obfuscation",
        "tactic": "Defense Evasion",
        "kill_chain_phase": "Delivery",
        "description": "YARA rules detected evasion techniques — obfuscated JavaScript, encoded payloads, or anti-analysis patterns.",
        "detection": "Deploy content deobfuscation at the email gateway. Monitor for Base64/hex-encoded payloads in attachments. Alert on heavily obfuscated script content.",
    },

    # =====================================================================
    # ML / NLP findings
    # =====================================================================
    "ml_phishing_classification": {
        "technique_id": "T1566",
        "technique": "Phishing",
        "tactic": "Initial Access",
        "kill_chain_phase": "Delivery",
        "description": "Machine learning classifier identified this email as likely phishing based on statistical analysis of header anomalies, URL characteristics, body language patterns, and attachment properties.",
        "detection": "Deploy ML-based email classification alongside rule-based detection. Retrain models regularly on new phishing samples. Use ML confidence scores to adjust quarantine thresholds.",
    },
    "nlp_urgency": {
        "technique_id": "T1598.003",
        "technique": "Phishing for Information: Spearphishing Link",
        "tactic": "Reconnaissance",
        "kill_chain_phase": "Reconnaissance",
        "description": "NLP analysis detected urgency and threat language patterns designed to pressure the victim into taking immediate action without careful consideration.",
        "detection": "Deploy NLP-based content analysis on inbound emails. Flag emails with high urgency language scores for additional review.",
    },
    "nlp_impersonation": {
        "technique_id": "T1656",
        "technique": "Impersonation",
        "tactic": "Defense Evasion",
        "kill_chain_phase": "Delivery",
        "description": "NLP analysis detected impersonation patterns — the email claims to be from an authority figure, support team, or official department to establish false trust.",
        "detection": "Deploy sender impersonation detection. Flag emails claiming organizational authority from external domains. Monitor for executive impersonation patterns.",
    },
    "nlp_grammar_anomalies": {
        "technique_id": "T1566",
        "technique": "Phishing",
        "tactic": "Initial Access",
        "kill_chain_phase": "Delivery",
        "description": "NLP analysis detected grammatical anomalies common in phishing — excessive formality, ESL patterns, machine translation artifacts, and unusual phrasing.",
        "detection": "Deploy text quality analysis on inbound emails. Flag emails with high rates of grammatical anomalies for review. Monitor for common phishing phrasing patterns.",
    },
}


def map_findings_to_mitre(score_breakdown):
    """Given a score breakdown list, return MITRE ATT&CK mappings for each finding.

    Returns a list of dicts, each with: technique_id, technique, tactic,
    description, detection, kill_chain_phase, and the original finding reason/points.
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
                    "detection": t.get("detection", ""),
                    "kill_chain_phase": t.get("kill_chain_phase", ""),
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

    # Browser detonation findings (check BEFORE generic URL/redirect matchers)
    if category == "browser":
        if "javascript redirect" in reason:
            return "js_redirect"
        if "meta refresh" in reason:
            return "meta_refresh"
        if "iframe" in reason:
            return "iframe_attack"
        if "credential" in reason and ("form" in reason or "harvesting" in reason):
            return "browser_credential_form"

    # Intermediate domain findings
    if "intermediate" in reason and ("phishing" in reason or "suspicious" in reason):
        return "intermediate_phishing_domain"

    # IDN homograph attacks
    if "idn homograph" in reason:
        return "idn_homograph"

    # Brand impersonation (HTML similarity)
    if "brand impersonation" in reason or "html similarity" in reason:
        return "brand_impersonation"

    # NLP findings
    if category == "nlp":
        if "urgency" in reason or "threat language" in reason:
            return "nlp_urgency"
        if "impersonation" in reason:
            return "nlp_impersonation"
        if "grammar" in reason or "anomal" in reason:
            return "nlp_grammar_anomalies"
        if "social engineering" in reason:
            return "nlp_social_engineering"
        return "nlp_urgency"

    # ML classification
    if "ml" in reason and ("phishing" in reason or "classification" in reason or "confidence" in reason):
        return "ml_phishing_classification"

    # Threat intel feed hits
    if "abuseipdb" in reason or "urlhaus" in reason or "phishtank" in reason or "alienvault" in reason:
        return "threat_intel_feed_hit"
    if "threat intel" in reason and "feed" in reason:
        return "threat_intel_feed_hit"

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

    # YARA rule matches
    if "yara rule" in reason or "yara:" in reason:
        if "phishing" in reason:
            return "yara_phishing"
        if "macro" in reason:
            return "yara_macro"
        if "exploit" in reason:
            return "yara_exploit"
        if "script" in reason:
            return "yara_script"
        if "evasion" in reason or "obfuscat" in reason:
            return "yara_evasion"
        if "embedded" in reason and "exe" in reason:
            return "yara_embedded_exe"
        return "yara_phishing"

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
        return {
            "kill_chain_phases": [],
            "technique_count": 0,
            "tactic_coverage": [],
            "detection_recommendations": [],
        }

    tactics_seen = []
    kill_chain_order = [
        "Reconnaissance", "Resource Development", "Initial Access",
        "Execution", "Persistence", "Defense Evasion", "Credential Access",
        "Discovery", "Collection", "Command and Control",
    ]
    for tactic in kill_chain_order:
        if any(m["tactic"] == tactic for m in mappings):
            tactics_seen.append(tactic)

    # Collect unique detection recommendations
    recommendations = []
    seen_recs = set()
    for m in mappings:
        detection = m.get("detection", "")
        if detection and detection not in seen_recs:
            seen_recs.add(detection)
            recommendations.append({
                "technique_id": m["technique_id"],
                "technique": m["technique"],
                "recommendation": detection,
            })

    return {
        "kill_chain_phases": tactics_seen,
        "technique_count": len(mappings),
        "tactic_coverage": tactics_seen,
        "detection_recommendations": recommendations,
    }
