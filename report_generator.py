"""PDF report generation for phishing analysis results.

Generates professional, downloadable PDF reports suitable for
incident response documentation, management briefings, and compliance.
Uses fpdf2 for lightweight PDF generation with no system-level dependencies.
"""

import io
import logging
from datetime import datetime, timezone

log = logging.getLogger(__name__)


def generate_pdf(report_dict):
    """Generate a PDF report from an analysis report dict.

    Returns a BytesIO object containing the PDF data.
    """
    try:
        from fpdf import FPDF
    except ImportError:
        log.warning("fpdf2 not installed — PDF generation unavailable")
        return None

    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=20)
    pdf.add_page()

    # --- Header ---
    pdf.set_font("Helvetica", "B", 20)
    pdf.set_text_color(30, 30, 30)
    pdf.cell(0, 12, "PhishGuard Analysis Report", new_x="LMARGIN", new_y="NEXT")
    pdf.set_draw_color(88, 166, 255)
    pdf.set_line_width(0.8)
    pdf.line(10, pdf.get_y(), 200, pdf.get_y())
    pdf.ln(6)

    # --- Metadata ---
    headers = report_dict.get("headers", {})
    score = report_dict.get("score", {})

    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(100, 100, 100)
    pdf.cell(0, 5, f"Report ID: {report_dict.get('report_id', 'N/A')}", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 5, f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 5, f"File: {report_dict.get('filename', 'N/A')}", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(4)

    # --- Verdict ---
    level = score.get("level", "clean")
    total = score.get("total", 0)
    label = score.get("level_label", "")

    level_colors = {
        "critical": (248, 81, 73),
        "high": (210, 153, 34),
        "medium": (227, 179, 65),
        "low": (63, 185, 80),
        "clean": (46, 160, 67),
    }
    color = level_colors.get(level, (100, 100, 100))

    pdf.set_fill_color(*color)
    pdf.set_text_color(255, 255, 255)
    pdf.set_font("Helvetica", "B", 14)
    pdf.cell(0, 10, f"  THREAT LEVEL: {level.upper()} ({total}/100)", fill=True, new_x="LMARGIN", new_y="NEXT")
    pdf.set_text_color(30, 30, 30)
    pdf.set_font("Helvetica", "", 10)
    pdf.cell(0, 6, label, new_x="LMARGIN", new_y="NEXT")
    pdf.ln(6)

    # --- Email Headers ---
    _section_title(pdf, "Email Headers")
    _detail_row(pdf, "From", f"{headers.get('from_display', '')} <{headers.get('from_address', '')}>")
    _detail_row(pdf, "Reply-To", headers.get("reply_to", "-"))
    _detail_row(pdf, "Return-Path", headers.get("return_path", "-"))
    _detail_row(pdf, "To", ", ".join(headers.get("to_addresses", [])) or "-")
    _detail_row(pdf, "Subject", headers.get("subject", "-"))
    _detail_row(pdf, "Date", headers.get("date", "-"))
    _detail_row(pdf, "Message-ID", headers.get("message_id", "-"))
    _detail_row(pdf, "Origin IP", headers.get("originating_ip", "Unknown"))
    pdf.ln(3)

    # --- Authentication ---
    _section_title(pdf, "Authentication Results")
    _detail_row(pdf, "SPF", headers.get("spf_result", "none").upper())
    _detail_row(pdf, "DKIM", headers.get("dkim_result", "none").upper())
    _detail_row(pdf, "DMARC", headers.get("dmarc_result", "none").upper())
    if headers.get("spf_dns_record"):
        _detail_row(pdf, "SPF Record", headers["spf_dns_record"])
    if headers.get("dmarc_dns_record"):
        _detail_row(pdf, "DMARC Record", headers["dmarc_dns_record"])
    pdf.ln(3)

    # --- Anomalies ---
    anomalies = headers.get("anomalies", [])
    if anomalies:
        _section_title(pdf, "Header Anomalies")
        for a in anomalies:
            pdf.set_font("Helvetica", "", 9)
            pdf.set_text_color(180, 80, 40)
            pdf.multi_cell(0, 4.5, f"  * {a}", new_x="LMARGIN", new_y="NEXT")
        pdf.set_text_color(30, 30, 30)
        pdf.ln(3)

    # --- Score Breakdown ---
    breakdown = score.get("breakdown", [])
    if breakdown:
        _section_title(pdf, "Score Breakdown")
        pdf.set_font("Helvetica", "B", 8)
        pdf.set_fill_color(240, 240, 240)
        pdf.cell(100, 6, "Finding", border=1, fill=True)
        pdf.cell(35, 6, "Category", border=1, fill=True)
        pdf.cell(25, 6, "Points", border=1, fill=True, new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", "", 8)
        for item in breakdown:
            reason = item.get("reason", "")[:70]
            cat = item.get("category", "")
            pts = item.get("points", 0)
            pdf.cell(100, 5, reason, border=1)
            pdf.cell(35, 5, cat, border=1)
            pdf.cell(25, 5, f"+{pts}", border=1, new_x="LMARGIN", new_y="NEXT")
        pdf.ln(3)

    # --- MITRE ATT&CK ---
    mitre = report_dict.get("mitre_mappings", [])
    if mitre:
        _section_title(pdf, "MITRE ATT&CK Mapping")
        pdf.set_font("Helvetica", "B", 8)
        pdf.set_fill_color(240, 240, 240)
        pdf.cell(25, 6, "Technique", border=1, fill=True)
        pdf.cell(55, 6, "Name", border=1, fill=True)
        pdf.cell(35, 6, "Tactic", border=1, fill=True)
        pdf.cell(75, 6, "Finding", border=1, fill=True, new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", "", 8)
        for m in mitre:
            pdf.cell(25, 5, m.get("technique_id", ""), border=1)
            pdf.cell(55, 5, m.get("technique", "")[:35], border=1)
            pdf.cell(35, 5, m.get("tactic", ""), border=1)
            pdf.cell(75, 5, m.get("finding", "")[:50], border=1, new_x="LMARGIN", new_y="NEXT")
        pdf.ln(3)

    # --- URLs ---
    urls = report_dict.get("urls", [])
    if urls:
        _section_title(pdf, f"URLs Analyzed ({len(urls)})")
        for u in urls[:15]:
            pdf.set_font("Helvetica", "", 8)
            url_str = u.get("url", "")[:90]
            risk = u.get("risk_score", 0)
            pdf.cell(0, 5, f"  [{risk} pts] {url_str}", new_x="LMARGIN", new_y="NEXT")
            indicators = u.get("threat_indicators", [])
            if indicators:
                pdf.set_font("Helvetica", "I", 7)
                pdf.set_text_color(180, 80, 40)
                for ind in indicators[:3]:
                    pdf.cell(0, 4, f"      {ind}", new_x="LMARGIN", new_y="NEXT")
                pdf.set_text_color(30, 30, 30)
        pdf.ln(3)

    # --- Attachments ---
    attachments = report_dict.get("attachments", [])
    if attachments:
        _section_title(pdf, f"Attachments ({len(attachments)})")
        for att in attachments:
            pdf.set_font("Helvetica", "B", 9)
            fname = att.get("filename", "unknown")
            size_kb = round(att.get("size", 0) / 1024, 1)
            pdf.cell(0, 5, f"  {fname} ({size_kb} KB)", new_x="LMARGIN", new_y="NEXT")
            pdf.set_font("Helvetica", "", 7)
            pdf.set_text_color(100, 100, 100)
            pdf.cell(0, 4, f"    MD5:    {att.get('md5', '')}", new_x="LMARGIN", new_y="NEXT")
            pdf.cell(0, 4, f"    SHA256: {att.get('sha256', '')}", new_x="LMARGIN", new_y="NEXT")
            pdf.set_text_color(30, 30, 30)
            for ind in att.get("threat_indicators", []):
                pdf.set_font("Helvetica", "I", 7)
                pdf.set_text_color(180, 80, 40)
                pdf.cell(0, 4, f"      {ind}", new_x="LMARGIN", new_y="NEXT")
                pdf.set_text_color(30, 30, 30)
        pdf.ln(3)

    # --- IOCs ---
    iocs = report_dict.get("iocs", {})
    _section_title(pdf, "Indicators of Compromise (IOCs)")
    pdf.set_font("Helvetica", "", 8)
    for label, key in [("IP Addresses", "ip_addresses"), ("Domains", "domains"),
                       ("Email Addresses", "email_addresses"), ("URLs", "urls")]:
        items = iocs.get(key, [])
        if items:
            pdf.set_font("Helvetica", "B", 8)
            pdf.cell(0, 5, f"  {label}:", new_x="LMARGIN", new_y="NEXT")
            pdf.set_font("Helvetica", "", 7)
            for item in items[:20]:
                pdf.cell(0, 4, f"    {str(item)[:100]}", new_x="LMARGIN", new_y="NEXT")

    # --- Footer ---
    pdf.ln(10)
    pdf.set_font("Helvetica", "I", 8)
    pdf.set_text_color(150, 150, 150)
    pdf.cell(0, 5, "Generated by PhishGuard Phishing Analyzer", new_x="LMARGIN", new_y="NEXT")

    buf = io.BytesIO()
    pdf.output(buf)
    buf.seek(0)
    return buf


def _section_title(pdf, title):
    pdf.set_font("Helvetica", "B", 11)
    pdf.set_text_color(88, 166, 255)
    pdf.cell(0, 8, title, new_x="LMARGIN", new_y="NEXT")
    pdf.set_text_color(30, 30, 30)


def _detail_row(pdf, label, value):
    pdf.set_font("Helvetica", "B", 9)
    pdf.cell(30, 5, f"{label}:")
    pdf.set_font("Helvetica", "", 9)
    value_str = str(value) if value else "-"
    # Truncate long values to avoid overflow
    if len(value_str) > 100:
        value_str = value_str[:100] + "..."
    pdf.cell(0, 5, value_str, new_x="LMARGIN", new_y="NEXT")
