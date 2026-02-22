import re
import logging
import dns.resolver
from config import THREAT_INTEL_IPS, SCORE_WEIGHTS, SUSPICIOUS_MAILERS

log = logging.getLogger(__name__)

DNS_TIMEOUT = 5


def analyze_headers(headers):
    _validate_authentication(headers)
    _live_spf_lookup(headers)
    _live_dmarc_lookup(headers)
    _check_originating_ip(headers)
    _check_received_chain_consistency(headers)
    return headers


def _live_spf_lookup(headers):
    """Query DNS for the actual SPF TXT record on the sender's domain."""
    domain = ""
    if headers.from_address and "@" in headers.from_address:
        domain = headers.from_address.split("@")[-1].lower()
    if not domain:
        return

    try:
        answers = dns.resolver.resolve(domain, "TXT", lifetime=DNS_TIMEOUT)
        for rdata in answers:
            txt = rdata.to_text().strip('"')
            if txt.startswith("v=spf1"):
                headers.spf_dns_record = txt
                return
        headers.anomalies.append(f"No SPF record found for {domain}")
    except Exception as e:
        etype = type(e).__name__
        if etype == "NXDOMAIN":
            headers.anomalies.append(f"Domain {domain} does not exist (NXDOMAIN)")
        elif etype == "NoAnswer":
            headers.anomalies.append(f"No TXT records returned for {domain}")
        elif etype == "NoNameservers":
            headers.anomalies.append(f"No nameservers reachable for {domain}")
        elif etype == "Timeout":
            log.debug("SPF lookup timed out for %s", domain)
        else:
            log.debug("SPF lookup error for %s: %s", domain, e)


def _live_dmarc_lookup(headers):
    """Query _dmarc.<domain> for the DMARC TXT record."""
    domain = ""
    if headers.from_address and "@" in headers.from_address:
        domain = headers.from_address.split("@")[-1].lower()
    if not domain:
        return

    try:
        dmarc_domain = f"_dmarc.{domain}"
        answers = dns.resolver.resolve(dmarc_domain, "TXT", lifetime=DNS_TIMEOUT)
        for rdata in answers:
            txt = rdata.to_text().strip('"')
            if txt.startswith("v=DMARC1"):
                headers.dmarc_dns_record = txt
                # If no result parsed from Authentication-Results, infer from policy
                if headers.dmarc_result == "none":
                    p_match = re.search(r'\bp=(\w+)', txt)
                    if p_match and p_match.group(1).lower() in ("quarantine", "reject"):
                        headers.dmarc_result = "fail"
                return
    except Exception as e:
        etype = type(e).__name__
        if etype not in ("NXDOMAIN", "NoAnswer", "NoNameservers", "Timeout"):
            log.debug("DMARC lookup error for %s: %s", domain, e)


def _validate_authentication(headers):
    if headers.spf_result in ("fail", "softfail"):
        headers.anomalies.append(
            f"SPF {headers.spf_result}: sender IP not authorized for this domain"
        )
    elif headers.spf_result == "none":
        headers.anomalies.append("No SPF result in Authentication-Results header")

    if headers.dkim_result == "fail":
        headers.anomalies.append("DKIM signature verification failed — possible tampering")
    elif headers.dkim_result == "none":
        headers.anomalies.append("No DKIM signature present")

    if headers.dmarc_result == "fail":
        headers.anomalies.append("DMARC alignment check failed")
    elif headers.dmarc_result == "none":
        headers.anomalies.append("No DMARC result in Authentication-Results header")


def _check_originating_ip(headers):
    if not headers.originating_ip:
        return
    if headers.originating_ip in THREAT_INTEL_IPS:
        headers.anomalies.append(
            f"Originating IP {headers.originating_ip} in threat intelligence watchlist"
        )
        headers.forged_headers.append(f"Threat intel hit: {headers.originating_ip}")


def _check_received_chain_consistency(headers):
    if len(headers.received_chain) < 2:
        return
    if len(headers.received_chain) > 8:
        headers.anomalies.append(
            f"Unusually long Received chain ({len(headers.received_chain)} hops)"
        )
    for entry in headers.received_chain:
        ip = entry.get("ip")
        if ip and ip in THREAT_INTEL_IPS:
            headers.anomalies.append(f"Threat intel IP in mail path: {ip}")
            headers.forged_headers.append(f"Threat intel IP in Received: {ip}")


def score_headers(headers):
    findings = []
    if headers.spf_result == "fail":
        findings.append(("SPF authentication failed", SCORE_WEIGHTS["spf_fail"]))
    elif headers.spf_result == "softfail":
        findings.append(("SPF softfail", SCORE_WEIGHTS["spf_softfail"]))
    elif headers.spf_result == "none":
        findings.append(("No SPF record or result", SCORE_WEIGHTS["spf_no_record"]))
    if headers.dkim_result == "fail":
        findings.append(("DKIM signature invalid", SCORE_WEIGHTS["dkim_fail"]))
    elif headers.dkim_result == "none":
        findings.append(("No DKIM signature present", SCORE_WEIGHTS["dkim_fail"] // 2))
    if headers.dmarc_result == "fail":
        findings.append(("DMARC policy failed", SCORE_WEIGHTS["dmarc_fail"]))
    elif headers.dmarc_result == "none":
        findings.append(("No DMARC result present", SCORE_WEIGHTS["dmarc_fail"] // 2))
    if headers.forged_headers:
        findings.append(("Forged or suspicious headers", SCORE_WEIGHTS["header_forged"]))
    if headers.display_name_spoofed:
        findings.append(("Display name spoofing", SCORE_WEIGHTS["spoofed_display_name"]))
    if headers.reply_to_mismatch:
        findings.append(("Reply-To domain mismatch", SCORE_WEIGHTS["reply_to_mismatch"]))
    if headers.originating_ip and headers.originating_ip in THREAT_INTEL_IPS:
        findings.append(("Originating IP in threat intel feed", SCORE_WEIGHTS["known_threat_intel_ip"]))
    if any("NXDOMAIN" in a or "does not exist" in a for a in headers.anomalies):
        findings.append(("Sender domain does not exist (NXDOMAIN)", SCORE_WEIGHTS["nxdomain_sender"]))
    if any("long Received chain" in a or "Unusually long" in a for a in headers.anomalies):
        findings.append(("Unusually long mail routing chain", SCORE_WEIGHTS["long_received_chain"]))
    if headers.spf_result == "none" and headers.dkim_result == "none" and headers.dmarc_result == "none":
        findings.append(("No email authentication whatsoever (SPF/DKIM/DMARC all absent)", SCORE_WEIGHTS["no_auth_all_none"]))
    if any("Missing Message-ID" in a for a in headers.anomalies):
        findings.append(("Missing Message-ID header", SCORE_WEIGHTS["missing_message_id"]))
    if any("No Received headers" in a for a in headers.anomalies):
        findings.append(("No Received headers — possible direct injection", SCORE_WEIGHTS["no_received_headers"]))
    if any("Missing Date" in a for a in headers.anomalies):
        findings.append(("Missing Date header", SCORE_WEIGHTS["missing_date"]))
    if headers.x_mailer:
        mailer_lower = headers.x_mailer.lower()
        for suspect in SUSPICIOUS_MAILERS:
            if suspect in mailer_lower:
                findings.append((f"Suspicious X-Mailer: {headers.x_mailer}", SCORE_WEIGHTS["suspicious_x_mailer"]))
                break
    return findings
