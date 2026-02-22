import re
from models import IOCExtraction


def extract_iocs(headers, body, url_findings, attachment_findings):
    iocs = IOCExtraction()

    if headers.originating_ip:
        iocs.ip_addresses.append(headers.originating_ip)
    for entry in headers.received_chain:
        ip = entry.get("ip")
        if ip and ip not in iocs.ip_addresses:
            iocs.ip_addresses.append(ip)

    all_text = (body.text_content or "") + " " + (body.html_content or "")
    body_ips = re.findall(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', all_text)
    for ip in body_ips:
        octets = ip.split(".")
        if all(0 <= int(o) <= 255 for o in octets) and ip not in iocs.ip_addresses:
            iocs.ip_addresses.append(ip)

    for uf in url_findings:
        if uf.domain and uf.domain not in iocs.domains:
            iocs.domains.append(uf.domain)
        if uf.url not in iocs.urls:
            iocs.urls.append(uf.url)

    for af in attachment_findings:
        iocs.file_hashes.append({
            "filename": af.filename, "md5": af.md5,
            "sha1": af.sha1, "sha256": af.sha256,
        })

    emails = set()
    if headers.from_address:
        emails.add(headers.from_address)
    if headers.reply_to:
        emails.add(headers.reply_to)
    if headers.return_path:
        emails.add(headers.return_path)
    body_emails = re.findall(r'[\w.+-]+@[\w.-]+\.\w{2,}', all_text)
    emails.update(e.lower() for e in body_emails)
    iocs.email_addresses = list(emails)

    return iocs
