import email
import email.policy
import re
from email import message_from_bytes
from models import HeaderAnalysis, BodyAnalysis


def parse_eml(raw_bytes):
    msg = message_from_bytes(raw_bytes, policy=email.policy.default)
    headers = _extract_headers(msg)
    body = _extract_body(msg)
    attachments_raw = _extract_attachments(msg)
    return msg, headers, body, attachments_raw


def _extract_headers(msg):
    h = HeaderAnalysis()
    h.from_address = _get_email_addr(msg.get("From", ""))
    h.from_display = _get_display_name(msg.get("From", ""))
    h.reply_to = _get_email_addr(msg.get("Reply-To", ""))
    h.return_path = _get_email_addr(msg.get("Return-Path", ""))
    h.subject = msg.get("Subject", "")
    h.date = msg.get("Date", "")
    h.message_id = msg.get("Message-ID", "")
    h.x_mailer = msg.get("X-Mailer", "")
    h.content_type = msg.get_content_type()
    h.to_addresses = _get_all_addresses(msg.get_all("To", []))
    h.cc_addresses = _get_all_addresses(msg.get_all("Cc", []))
    h.received_chain = _parse_received_chain(msg.get_all("Received", []))
    h.originating_ip = _extract_originating_ip(h.received_chain)

    h.auth_results_raw = msg.get("Authentication-Results", "")
    h.spf_result = _parse_auth_field(h.auth_results_raw, "spf")
    h.dkim_result = _parse_auth_field(h.auth_results_raw, "dkim")
    h.dmarc_result = _parse_auth_field(h.auth_results_raw, "dmarc")

    # Fallback: parse Received-SPF header if Authentication-Results is absent or has no SPF
    if h.spf_result == "none":
        received_spf = msg.get("Received-SPF", "")
        if received_spf:
            h.spf_result = _parse_received_spf(received_spf)

    if h.reply_to and h.from_address:
        from_domain = h.from_address.split("@")[-1].lower() if "@" in h.from_address else ""
        reply_domain = h.reply_to.split("@")[-1].lower() if "@" in h.reply_to else ""
        if from_domain and reply_domain and from_domain != reply_domain:
            h.reply_to_mismatch = True
            h.anomalies.append(f"Reply-To domain ({reply_domain}) differs from From domain ({from_domain})")

    from config import LEGITIMATE_DOMAINS
    if h.from_display and "@" in h.from_display:
        display_domain = h.from_display.split("@")[-1].lower().rstrip(">").strip()
        actual_domain = h.from_address.split("@")[-1].lower() if "@" in h.from_address else ""
        if display_domain and actual_domain and display_domain != actual_domain:
            h.display_name_spoofed = True
            h.anomalies.append(f"Display name contains email from different domain: {h.from_display}")
    elif h.from_display and h.from_address:
        # Check if display name impersonates a known brand while sending from elsewhere
        legit_brands = {d.split(".")[0].lower(): d for d in LEGITIMATE_DOMAINS}
        display_lower = h.from_display.lower()
        actual_domain = h.from_address.split("@")[-1].lower() if "@" in h.from_address else ""
        for brand, legit_domain in legit_brands.items():
            if re.search(rf'\b{re.escape(brand)}\b', display_lower) and not actual_domain.endswith(legit_domain):
                h.display_name_spoofed = True
                h.anomalies.append(
                    f"Display name '{h.from_display}' impersonates {legit_domain} "
                    f"but sent from {actual_domain}"
                )
                break

    if h.return_path and h.from_address:
        rp_domain = h.return_path.split("@")[-1].lower() if "@" in h.return_path else ""
        from_domain = h.from_address.split("@")[-1].lower() if "@" in h.from_address else ""
        if rp_domain and from_domain and rp_domain != from_domain:
            h.forged_headers.append(f"Return-Path ({rp_domain}) doesn't match From ({from_domain})")

    if not h.message_id:
        h.anomalies.append("Missing Message-ID header")
    if not h.date:
        h.anomalies.append("Missing Date header")
    if not h.received_chain:
        h.anomalies.append("No Received headers — possible direct injection")

    return h


def _extract_body(msg):
    b = BodyAnalysis()
    if msg.is_multipart():
        for part in msg.walk():
            ct = part.get_content_type()
            disp = str(part.get("Content-Disposition", ""))
            if "attachment" in disp:
                continue
            if ct == "text/plain" and not b.text_content:
                payload = part.get_payload(decode=True)
                if payload:
                    b.text_content = payload.decode("utf-8", errors="replace")
            elif ct == "text/html" and not b.html_content:
                payload = part.get_payload(decode=True)
                if payload:
                    b.html_content = payload.decode("utf-8", errors="replace")
            elif ct and ct.startswith("image/"):
                b.embedded_images += 1
    else:
        ct = msg.get_content_type()
        payload = msg.get_payload(decode=True)
        if payload:
            text = payload.decode("utf-8", errors="replace")
            if ct == "text/html":
                b.html_content = text
            else:
                b.text_content = text

    if b.html_content:
        if re.search(r"<script", b.html_content, re.IGNORECASE):
            b.javascript_detected = True
        forms = re.findall(r'<form[^>]+action=["\']([^"\']+)', b.html_content, re.IGNORECASE)
        for action in forms:
            if action.startswith("http"):
                b.form_action_external = True
                break
        if re.search(r'color:\s*#fff|color:\s*white|display:\s*none|font-size:\s*0', b.html_content, re.IGNORECASE):
            b.hidden_text = True

    return b


def _extract_attachments(msg):
    attachments = []
    if not msg.is_multipart():
        return attachments
    for part in msg.walk():
        disp = str(part.get("Content-Disposition", ""))
        filename = part.get_filename()
        if filename or "attachment" in disp:
            payload = part.get_payload(decode=True)
            if payload:
                attachments.append({
                    "filename": filename or "unknown",
                    "content_type": part.get_content_type(),
                    "data": payload,
                })
    return attachments


def _get_email_addr(header_val):
    if not header_val:
        return ""
    match = re.search(r'[\w.+-]+@[\w.-]+\.\w+', str(header_val))
    return match.group(0).lower() if match else str(header_val).strip().lower()


def _get_display_name(header_val):
    if not header_val:
        return ""
    val = str(header_val)
    if "<" in val:
        return val.split("<")[0].strip().strip('"').strip("'")
    return ""


def _get_all_addresses(header_list):
    addrs = []
    for h in header_list:
        if not h:
            continue
        for part in str(h).split(","):
            addr = _get_email_addr(part)
            if addr:
                addrs.append(addr)
    return addrs


def _parse_received_chain(received_list):
    chain = []
    for r in (received_list or []):
        entry = {"raw": str(r).strip()}
        ip_match = re.search(r'\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]', str(r))
        if ip_match:
            entry["ip"] = ip_match.group(1)
        from_match = re.search(r'from\s+([\w.-]+)', str(r), re.IGNORECASE)
        if from_match:
            entry["from_host"] = from_match.group(1)
        by_match = re.search(r'by\s+([\w.-]+)', str(r), re.IGNORECASE)
        if by_match:
            entry["by_host"] = by_match.group(1)
        chain.append(entry)
    return chain


def _is_private_ip(ip):
    if ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("127."):
        return True
    if ip.startswith("172."):
        try:
            second_octet = int(ip.split(".")[1])
            if 16 <= second_octet <= 31:
                return True
        except (IndexError, ValueError):
            pass
    return False


def _extract_originating_ip(received_chain):
    for entry in reversed(received_chain):
        ip = entry.get("ip")
        if ip and not _is_private_ip(ip):
            return ip
    return None


def _parse_received_spf(received_spf):
    """Parse the Received-SPF header (different format to Authentication-Results).
    e.g. 'fail (google.com: domain does not designate ...)' """
    val = received_spf.strip().lower()
    for result in ("pass", "fail", "softfail", "neutral", "permerror", "temperror"):
        if val.startswith(result):
            return result
    return "none"


def _parse_auth_field(auth_results, field_name):
    if not auth_results:
        return "none"
    match = re.search(rf'{field_name}=(\w+)', auth_results, re.IGNORECASE)
    return match.group(1).lower() if match else "none"
