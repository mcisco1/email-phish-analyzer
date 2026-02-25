"""PDF report generation for phishing analysis results.

Generates professional, downloadable PDF reports suitable for
incident response documentation, management briefings, and compliance.
Uses fpdf2 for lightweight PDF generation with no system-level dependencies.
"""

import io
import logging
from datetime import datetime, timezone

log = logging.getLogger(__name__)

# Characters that fpdf2's built-in Helvetica (latin-1) can't render
_UNICODE_REPLACEMENTS = {
    "\u2014": "--",   # em-dash
    "\u2013": "-",    # en-dash
    "\u2018": "'",    # left single quote
    "\u2019": "'",    # right single quote
    "\u201c": '"',    # left double quote
    "\u201d": '"',    # right double quote
    "\u2026": "...",  # ellipsis
    "\u2192": "->",   # right arrow
    "\u2190": "<-",   # left arrow
    "\u2022": "*",    # bullet
    "\u00b7": ".",    # middle dot
    "\u2502": "|",    # box drawing vertical
}


def _safe(text):
    """Replace Unicode characters that Helvetica (latin-1) can't encode."""
    if not text:
        return ""
    text = str(text)
    for char, replacement in _UNICODE_REPLACEMENTS.items():
        text = text.replace(char, replacement)
    # Strip any remaining non-latin-1 characters
    try:
        text.encode("latin-1")
    except UnicodeEncodeError:
        text = text.encode("latin-1", errors="replace").decode("latin-1")
    return text


def generate_pdf(report_dict):
    """Generate a PDF report from an analysis report dict.

    Returns a BytesIO object containing the PDF data.
    """
    try:
        from fpdf import FPDF
    except ImportError:
        log.warning("fpdf2 not installed -- PDF generation unavailable")
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
    pdf.cell(0, 5, _safe(f"Report ID: {report_dict.get('report_id', 'N/A')}"), new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 5, _safe(f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}"), new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 5, _safe(f"File: {report_dict.get('filename', 'N/A')}"), new_x="LMARGIN", new_y="NEXT")
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
    pdf.cell(0, 10, _safe(f"  THREAT LEVEL: {level.upper()} ({total}/100)"), fill=True, new_x="LMARGIN", new_y="NEXT")
    pdf.set_text_color(30, 30, 30)
    pdf.set_font("Helvetica", "", 10)
    pdf.cell(0, 6, _safe(label), new_x="LMARGIN", new_y="NEXT")
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
            pdf.multi_cell(0, 4.5, _safe(f"  * {a}"), new_x="LMARGIN", new_y="NEXT")
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
            reason = _safe(item.get("reason", ""))[:70]
            cat = _safe(item.get("category", ""))
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
            pdf.cell(25, 5, _safe(m.get("technique_id", "")), border=1)
            pdf.cell(55, 5, _safe(m.get("technique", ""))[:35], border=1)
            pdf.cell(35, 5, _safe(m.get("tactic", "")), border=1)
            pdf.cell(75, 5, _safe(m.get("finding", ""))[:50], border=1, new_x="LMARGIN", new_y="NEXT")
        pdf.ln(3)

    # --- URLs ---
    urls = report_dict.get("urls", [])
    if urls:
        _section_title(pdf, f"URLs Analyzed ({len(urls)})")
        for u in urls[:15]:
            pdf.set_font("Helvetica", "", 8)
            url_str = _safe(u.get("url", ""))[:90]
            risk = u.get("risk_score", 0)
            pdf.cell(0, 5, _safe(f"  [{risk} pts] {url_str}"), new_x="LMARGIN", new_y="NEXT")
            indicators = u.get("threat_indicators", [])
            if indicators:
                pdf.set_font("Helvetica", "I", 7)
                pdf.set_text_color(180, 80, 40)
                for ind in indicators[:3]:
                    pdf.cell(0, 4, _safe(f"      {ind}"), new_x="LMARGIN", new_y="NEXT")
                pdf.set_text_color(30, 30, 30)
            # Browser detonation summary
            if u.get("has_credential_form"):
                pdf.set_font("Helvetica", "B", 7)
                pdf.set_text_color(248, 81, 73)
                pdf.cell(0, 4, "      [BROWSER] Credential harvesting form detected", new_x="LMARGIN", new_y="NEXT")
                pdf.set_text_color(30, 30, 30)
            if u.get("js_redirects"):
                pdf.set_font("Helvetica", "I", 7)
                pdf.set_text_color(180, 80, 40)
                pdf.cell(0, 4, _safe(f"      [BROWSER] {len(u['js_redirects'])} JS redirect(s) detected"), new_x="LMARGIN", new_y="NEXT")
                pdf.set_text_color(30, 30, 30)
            if u.get("meta_refresh_detected"):
                pdf.set_font("Helvetica", "I", 7)
                pdf.set_text_color(180, 80, 40)
                pdf.cell(0, 4, _safe(f"      [BROWSER] Meta refresh -> {u.get('meta_refresh_url', 'unknown')[:60]}"), new_x="LMARGIN", new_y="NEXT")
                pdf.set_text_color(30, 30, 30)
            if u.get("iframes_detected"):
                pdf.set_font("Helvetica", "I", 7)
                pdf.set_text_color(180, 80, 40)
                pdf.cell(0, 4, _safe(f"      [BROWSER] {len(u['iframes_detected'])} iframe(s) detected"), new_x="LMARGIN", new_y="NEXT")
                pdf.set_text_color(30, 30, 30)
            # Intermediate domains
            if u.get("intermediate_domains"):
                pdf.set_font("Helvetica", "I", 7)
                pdf.set_text_color(100, 100, 100)
                for idom in u["intermediate_domains"][:5]:
                    domain = idom.get("domain", idom) if isinstance(idom, dict) else str(idom)
                    inds = idom.get("indicators", []) if isinstance(idom, dict) else []
                    suffix = f" -- {', '.join(inds)}" if inds else ""
                    pdf.cell(0, 4, _safe(f"      [HOP] {domain}{suffix}"), new_x="LMARGIN", new_y="NEXT")
                pdf.set_text_color(30, 30, 30)
        pdf.ln(3)

    # --- Attachments ---
    attachments = report_dict.get("attachments", [])
    if attachments:
        _section_title(pdf, f"Attachments ({len(attachments)})")
        for att in attachments:
            pdf.set_font("Helvetica", "B", 9)
            fname = _safe(att.get("filename", "unknown"))
            size_kb = round(att.get("size", 0) / 1024, 1)
            pdf.cell(0, 5, _safe(f"  {fname} ({size_kb} KB)"), new_x="LMARGIN", new_y="NEXT")
            pdf.set_font("Helvetica", "", 7)
            pdf.set_text_color(100, 100, 100)
            pdf.cell(0, 4, _safe(f"    MD5:    {att.get('md5', '')}"), new_x="LMARGIN", new_y="NEXT")
            pdf.cell(0, 4, _safe(f"    SHA256: {att.get('sha256', '')}"), new_x="LMARGIN", new_y="NEXT")
            pdf.set_text_color(30, 30, 30)
            # YARA matches
            yara_matches = att.get("yara_matches", [])
            if yara_matches:
                pdf.set_font("Helvetica", "B", 7)
                pdf.set_text_color(248, 81, 73)
                for ym in yara_matches:
                    if isinstance(ym, dict):
                        rule = ym.get("rule", "unknown")
                        sev = ym.get("severity", "")
                        desc = ym.get("description", "")
                        pdf.cell(0, 4, _safe(f"    [YARA] {rule} [{sev}] {desc[:50]}"), new_x="LMARGIN", new_y="NEXT")
                pdf.set_text_color(30, 30, 30)
            for ind in att.get("threat_indicators", []):
                pdf.set_font("Helvetica", "I", 7)
                pdf.set_text_color(180, 80, 40)
                pdf.cell(0, 4, _safe(f"      {ind}"), new_x="LMARGIN", new_y="NEXT")
                pdf.set_text_color(30, 30, 30)
        pdf.ln(3)

    # --- ML Classification ---
    ml = report_dict.get("ml_classification", {})
    if ml and ml.get("ml_available"):
        _section_title(pdf, "ML Classification")
        confidence = ml.get("ml_confidence", 0)
        verdict = ml.get("ml_verdict", "unknown")
        pdf.set_font("Helvetica", "B", 10)
        if verdict == "phishing":
            pdf.set_text_color(248, 81, 73)
        elif verdict == "suspicious":
            pdf.set_text_color(210, 153, 34)
        else:
            pdf.set_text_color(46, 160, 67)
        pdf.cell(0, 6, _safe(f"  Verdict: {verdict.upper()} ({confidence:.0f}% confidence)"), new_x="LMARGIN", new_y="NEXT")
        pdf.set_text_color(30, 30, 30)
        pdf.set_font("Helvetica", "", 8)
        pdf.cell(0, 4, _safe("  Model: Random Forest + Logistic Regression ensemble"), new_x="LMARGIN", new_y="NEXT")
        pdf.ln(3)

    # --- NLP Analysis ---
    body_data = report_dict.get("body", {})
    nlp = body_data.get("nlp_analysis", {}) if isinstance(body_data, dict) else {}
    if nlp and nlp.get("overall_nlp_score", 0) > 0:
        _section_title(pdf, "NLP Body Analysis")
        pdf.set_font("Helvetica", "", 9)
        for label, key in [("Urgency", "urgency_score"), ("Threat", "threat_score"),
                           ("Impersonation", "impersonation_score"), ("Grammar", "grammar_score"),
                           ("Social Engineering", "social_engineering_score")]:
            val = nlp.get(key, 0)
            if val > 0:
                pdf.cell(0, 4.5, _safe(f"  {label}: {val}/100"), new_x="LMARGIN", new_y="NEXT")
        if nlp.get("summary"):
            pdf.set_font("Helvetica", "I", 8)
            pdf.multi_cell(0, 4, _safe(f"  {nlp['summary']}"), new_x="LMARGIN", new_y="NEXT")
        pdf.ln(3)

    # --- Threat Intelligence ---
    ti = report_dict.get("threat_intel", {})
    ti_summary = ti.get("summary", {}) if isinstance(ti, dict) else {}
    if ti_summary.get("total_checked", 0) > 0:
        _section_title(pdf, "Threat Intelligence")
        pdf.set_font("Helvetica", "", 9)
        feeds = ", ".join(ti_summary.get("feeds_used", []))
        pdf.cell(0, 5, _safe(f"  Feeds: {feeds}"), new_x="LMARGIN", new_y="NEXT")
        pdf.cell(0, 5, _safe(f"  IOCs checked: {ti_summary.get('total_checked', 0)}, Flagged: {ti_summary.get('total_flagged', 0)}"), new_x="LMARGIN", new_y="NEXT")
        if ti_summary.get("total_flagged", 0) > 0:
            pdf.set_font("Helvetica", "B", 9)
            pdf.set_text_color(248, 81, 73)
            pdf.cell(0, 5, _safe(f"  WARNING: {ti_summary['total_flagged']} IOC(s) flagged as malicious"), new_x="LMARGIN", new_y="NEXT")
            pdf.set_text_color(30, 30, 30)
        pdf.ln(3)

    # --- IOCs ---
    iocs = report_dict.get("iocs", {})
    _section_title(pdf, "Indicators of Compromise (IOCs)")
    pdf.set_font("Helvetica", "", 8)
    for ioc_label, key in [("IP Addresses", "ip_addresses"), ("Domains", "domains"),
                           ("Email Addresses", "email_addresses"), ("URLs", "urls")]:
        items = iocs.get(key, [])
        if items:
            pdf.set_font("Helvetica", "B", 8)
            pdf.cell(0, 5, _safe(f"  {ioc_label}:"), new_x="LMARGIN", new_y="NEXT")
            pdf.set_font("Helvetica", "", 7)
            for item in items[:20]:
                pdf.cell(0, 4, _safe(f"    {str(item)[:100]}"), new_x="LMARGIN", new_y="NEXT")

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
    pdf.cell(0, 8, _safe(title), new_x="LMARGIN", new_y="NEXT")
    pdf.set_text_color(30, 30, 30)


def _detail_row(pdf, label, value):
    pdf.set_font("Helvetica", "B", 9)
    pdf.cell(30, 5, _safe(f"{label}:"))
    pdf.set_font("Helvetica", "", 9)
    value_str = str(value) if value else "-"
    # Truncate long values to avoid overflow
    if len(value_str) > 100:
        value_str = value_str[:100] + "..."
    pdf.cell(0, 5, _safe(value_str), new_x="LMARGIN", new_y="NEXT")
