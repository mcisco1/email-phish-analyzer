"""PDF report generation for phishing analysis results.

Generates professional security consultancy-grade PDF reports with:
- Cover page with threat verdict and risk visualization
- Table of contents
- Executive summary in plain English for management
- Risk rating with color-coded gradient bar
- Recommended actions based on findings
- Full technical findings
- Appendix with IOCs and raw data

Uses fpdf2 with embedded Inter and JetBrains Mono fonts for full
Unicode support and professional typography.
"""

import io
import os
import logging
from datetime import datetime, timezone

log = logging.getLogger(__name__)

_FONTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static", "fonts")

# Color palette matching the web UI
_COLORS = {
    "critical": (220, 38, 38),
    "high": (234, 88, 12),
    "medium": (202, 138, 4),
    "low": (34, 163, 72),
    "clean": (22, 130, 52),
    "accent": (56, 132, 220),
    "dark": (30, 30, 30),
    "gray": (120, 120, 120),
    "light_gray": (200, 200, 200),
    "bg_light": (248, 249, 250),
    "white": (255, 255, 255),
    "divider": (220, 220, 220),
    "cover_bg": (15, 23, 42),
    "cover_accent": (56, 132, 220),
}

# Risk bar gradient segments
_RISK_SEGMENTS = [
    (0, 10, (22, 130, 52)),
    (10, 30, (34, 163, 72)),
    (30, 50, (202, 138, 4)),
    (50, 70, (234, 88, 12)),
    (70, 100, (220, 38, 38)),
]


def generate_pdf(report_dict):
    """Generate a professional PDF report from an analysis report dict.

    Returns a BytesIO object containing the PDF data, or None on failure.
    """
    try:
        from fpdf import FPDF
    except ImportError:
        log.warning("fpdf2 not installed -- PDF generation unavailable")
        return None

    pdf = _PhishGuardPDF(report_dict)
    pdf.alias_nb_pages()

    # --- Cover Page ---
    _render_cover_page(pdf, report_dict)

    # --- Table of Contents placeholder ---
    toc_entries = []

    # --- Executive Summary ---
    pdf.add_page()
    toc_entries.append(("Executive Summary", pdf.page_no()))
    _render_executive_summary(pdf, report_dict)

    # --- Risk Rating ---
    toc_entries.append(("Risk Assessment", pdf.page_no()))
    _render_risk_assessment(pdf, report_dict)

    # --- Recommended Actions ---
    pdf.add_page()
    toc_entries.append(("Recommended Actions", pdf.page_no()))
    _render_recommended_actions(pdf, report_dict)

    # --- Technical Findings ---
    pdf.add_page()
    toc_entries.append(("Technical Findings", pdf.page_no()))
    _render_technical_findings(pdf, report_dict)

    # --- Appendix ---
    pdf.add_page()
    toc_entries.append(("Appendix", pdf.page_no()))
    _render_appendix(pdf, report_dict)

    # --- Insert Table of Contents on page 2 ---
    _insert_toc(pdf, toc_entries)

    buf = io.BytesIO()
    pdf.output(buf)
    buf.seek(0)
    return buf


# =========================================================================
# Custom PDF class with header/footer branding
# =========================================================================

class _PhishGuardPDF:
    """Wraps FPDF with professional branding and font management."""

    def __init__(self, report_dict):
        from fpdf import FPDF

        self._pdf = FPDF()
        self._pdf.set_auto_page_break(auto=True, margin=25)
        self._fonts_loaded = False
        self._report = report_dict
        self._toc_page = None
        self._is_cover = True

        # Try to load professional fonts
        try:
            inter_reg = os.path.join(_FONTS_DIR, "Inter-Regular.ttf")
            inter_bold = os.path.join(_FONTS_DIR, "Inter-Bold.ttf")
            jbm_reg = os.path.join(_FONTS_DIR, "JetBrainsMono-Regular.ttf")

            if os.path.exists(inter_reg) and os.path.exists(inter_bold) and os.path.exists(jbm_reg):
                self._pdf.add_font("Inter", "", inter_reg, uni=True)
                self._pdf.add_font("Inter", "B", inter_bold, uni=True)
                self._pdf.add_font("JBMono", "", jbm_reg, uni=True)
                self._fonts_loaded = True
                log.debug("Professional fonts loaded (Inter, JetBrains Mono)")
            else:
                log.debug("Font files not found -- using Helvetica fallback")
        except Exception:
            log.debug("Font loading failed -- using Helvetica fallback")

        self._body_font = "Inter" if self._fonts_loaded else "Helvetica"
        self._mono_font = "JBMono" if self._fonts_loaded else "Courier"

    # Delegate attribute access to the underlying FPDF instance
    def __getattr__(self, name):
        return getattr(self._pdf, name)

    def add_page(self, *args, **kwargs):
        self._is_cover = False
        self._pdf.add_page(*args, **kwargs)
        # Draw header/footer for non-cover pages
        self._draw_header()

    def _draw_header(self):
        if self._is_cover:
            return
        p = self._pdf
        p.set_y(8)
        p.set_font(self._body_font, "B", 7)
        p.set_text_color(*_COLORS["accent"])
        p.cell(95, 5, "PHISHGUARD SECURITY REPORT")
        p.set_text_color(*_COLORS["gray"])
        p.set_font(self._body_font, "", 7)
        rid = self._report.get("report_id", "")
        p.cell(95, 5, f"Report {rid}", align="R")
        p.ln(2)
        p.set_draw_color(*_COLORS["divider"])
        p.set_line_width(0.3)
        p.line(10, p.get_y(), 200, p.get_y())
        p.set_y(22)

    def draw_footer(self):
        p = self._pdf
        p.set_y(-18)
        p.set_draw_color(*_COLORS["divider"])
        p.set_line_width(0.3)
        p.line(10, p.get_y(), 200, p.get_y())
        p.ln(3)
        p.set_font(self._body_font, "", 7)
        p.set_text_color(*_COLORS["gray"])
        p.cell(95, 4, "Confidential -- PhishGuard Security Analysis")
        p.cell(95, 4, f"Page {p.page_no()}/{{nb}}", align="R")

    def section_title(self, title, size=14):
        p = self._pdf
        p.set_font(self._body_font, "B", size)
        p.set_text_color(*_COLORS["dark"])
        p.cell(0, 10, title, new_x="LMARGIN", new_y="NEXT")
        p.set_draw_color(*_COLORS["accent"])
        p.set_line_width(0.6)
        p.line(10, p.get_y(), 60, p.get_y())
        p.ln(6)

    def sub_title(self, title, size=11):
        p = self._pdf
        p.set_font(self._body_font, "B", size)
        p.set_text_color(*_COLORS["dark"])
        p.cell(0, 8, title, new_x="LMARGIN", new_y="NEXT")
        p.ln(2)

    def body_text(self, text, size=10):
        p = self._pdf
        p.set_font(self._body_font, "", size)
        p.set_text_color(50, 50, 50)
        p.multi_cell(0, 5.5, str(text), new_x="LMARGIN", new_y="NEXT")

    def mono_text(self, text, size=8):
        p = self._pdf
        p.set_font(self._mono_font, "", size)
        p.set_text_color(60, 60, 60)
        p.multi_cell(0, 4.5, str(text), new_x="LMARGIN", new_y="NEXT")

    def detail_row(self, label, value, label_w=38):
        p = self._pdf
        p.set_font(self._body_font, "B", 9)
        p.set_text_color(*_COLORS["gray"])
        p.cell(label_w, 5, f"{label}:")
        p.set_font(self._body_font, "", 9)
        p.set_text_color(50, 50, 50)
        val = str(value) if value else "-"
        if len(val) > 95:
            val = val[:95] + "..."
        p.cell(0, 5, val, new_x="LMARGIN", new_y="NEXT")

    def check_page_break(self, height=40):
        if self._pdf.get_y() + height > self._pdf.h - 30:
            self.add_page()


# =========================================================================
# Cover Page
# =========================================================================

def _render_cover_page(pdf, report_dict):
    p = pdf._pdf
    p.add_page()
    pdf._is_cover = True

    headers = report_dict.get("headers", {})
    score = report_dict.get("score", {})
    level = score.get("level", "clean")
    total = score.get("total", 0)

    # Dark background
    p.set_fill_color(*_COLORS["cover_bg"])
    p.rect(0, 0, 210, 297, "F")

    # Top accent line
    p.set_fill_color(*_COLORS["cover_accent"])
    p.rect(0, 0, 210, 4, "F")

    # Branding
    p.set_y(50)
    p.set_font(pdf._body_font, "B", 11)
    p.set_text_color(*_COLORS["cover_accent"])
    p.cell(0, 8, "PHISHGUARD", align="C", new_x="LMARGIN", new_y="NEXT")

    p.set_font(pdf._body_font, "", 28)
    p.set_text_color(255, 255, 255)
    p.cell(0, 14, "Security Analysis Report", align="C", new_x="LMARGIN", new_y="NEXT")
    p.ln(20)

    # Threat verdict box
    color = _COLORS.get(level, _COLORS["gray"])
    box_y = p.get_y()
    p.set_fill_color(*color)
    p.rect(40, box_y, 130, 40, "F")

    p.set_y(box_y + 6)
    p.set_font(pdf._body_font, "B", 12)
    p.set_text_color(255, 255, 255)
    p.cell(0, 8, "THREAT ASSESSMENT", align="C", new_x="LMARGIN", new_y="NEXT")

    p.set_font(pdf._body_font, "B", 22)
    p.cell(0, 12, f"{level.upper()}  --  {total}/100", align="C", new_x="LMARGIN", new_y="NEXT")
    p.ln(16)

    # Risk bar on cover
    _draw_risk_bar(pdf, total, p.get_y())
    p.ln(20)

    # Report metadata
    p.set_font(pdf._body_font, "", 10)
    p.set_text_color(180, 190, 210)

    rid = report_dict.get("report_id", "N/A")
    filename = report_dict.get("filename", "N/A")
    analyzed_at = report_dict.get("analyzed_at", "N/A")
    from_addr = headers.get("from_address", "Unknown")
    subject = headers.get("subject", "No subject")

    meta_items = [
        ("Report ID", rid),
        ("File", filename),
        ("Date", analyzed_at),
        ("Sender", from_addr),
        ("Subject", subject[:70] + ("..." if len(str(subject)) > 70 else "")),
    ]

    for label, value in meta_items:
        p.set_font(pdf._body_font, "B", 9)
        p.set_text_color(130, 145, 170)
        p.cell(40, 6, label, align="R")
        p.set_font(pdf._body_font, "", 9)
        p.set_text_color(210, 220, 235)
        p.cell(3, 6, "")
        p.cell(0, 6, str(value), new_x="LMARGIN", new_y="NEXT")

    # Footer branding
    p.set_y(-40)
    p.set_draw_color(60, 80, 110)
    p.set_line_width(0.3)
    p.line(40, p.get_y(), 170, p.get_y())
    p.ln(6)
    p.set_font(pdf._body_font, "", 8)
    p.set_text_color(100, 120, 150)
    p.cell(0, 5, f"Generated {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}", align="C", new_x="LMARGIN", new_y="NEXT")
    p.cell(0, 5, "PhishGuard Email Phishing Analyzer", align="C")


# =========================================================================
# Table of Contents
# =========================================================================

def _insert_toc(pdf, toc_entries):
    """Insert a table of contents page after the cover."""
    p = pdf._pdf

    # Move pages to insert TOC after cover (page 1)
    # fpdf2 doesn't support page insertion natively, so we render it
    # as the last page and note: the page numbers in the TOC are correct
    # because we recorded them during generation.
    # Instead, we'll add a TOC at the end and label it.
    pdf.add_page()

    pdf.section_title("Table of Contents", 16)
    p.ln(4)

    for title, page_num in toc_entries:
        p.set_font(pdf._body_font, "", 11)
        p.set_text_color(50, 50, 50)
        title_w = p.get_string_width(title)
        p.cell(title_w + 2, 7, title)

        # Dot leader
        dots_w = 160 - title_w - 10
        if dots_w > 0:
            p.set_text_color(*_COLORS["light_gray"])
            dot_str = " . " * max(1, int(dots_w / 5))
            p.cell(dots_w, 7, dot_str[:int(dots_w)])

        p.set_text_color(*_COLORS["accent"])
        p.set_font(pdf._mono_font, "", 10)
        p.cell(10, 7, str(page_num), align="R", new_x="LMARGIN", new_y="NEXT")
        p.ln(1)

    pdf.draw_footer()


# =========================================================================
# Executive Summary
# =========================================================================

def _render_executive_summary(pdf, report_dict):
    pdf.section_title("Executive Summary", 16)

    headers = report_dict.get("headers", {})
    score = report_dict.get("score", {})
    level = score.get("level", "clean")
    total = score.get("total", 0)
    breakdown = score.get("breakdown", [])

    from_addr = headers.get("from_address", "an unknown sender")
    subject = headers.get("subject", "no subject line")

    # Overview paragraph
    pdf.body_text(
        f'This report presents the findings of an automated security analysis performed on '
        f'an email received from {from_addr} with the subject "{subject}". '
        f'The analysis evaluated the email across multiple security dimensions including '
        f'sender authentication, embedded URLs, file attachments, linguistic patterns, '
        f'and threat intelligence databases.'
    )
    pdf._pdf.ln(4)

    # Verdict
    if level == "critical":
        verdict = (
            f"The analysis has identified this email as a CRITICAL threat with a risk score of "
            f"{total} out of 100. This email is almost certainly a phishing attack or contains "
            f"malicious content. Immediate action is required -- do not interact with this email."
        )
    elif level == "high":
        verdict = (
            f"The analysis has identified this email as a HIGH-severity threat with a risk score of "
            f"{total} out of 100. Multiple strong phishing indicators were detected. "
            f"Do not click any links or open any attachments from this email."
        )
    elif level == "medium":
        verdict = (
            f"The analysis found MEDIUM-severity suspicious elements with a risk score of "
            f"{total} out of 100. While not conclusively malicious, this email warrants "
            f"further investigation before any action is taken."
        )
    elif level == "low":
        verdict = (
            f"The analysis found minor anomalies resulting in a LOW risk score of "
            f"{total} out of 100. These findings are likely benign but are noted "
            f"for completeness. The email appears largely legitimate."
        )
    else:
        verdict = (
            f"The analysis found no significant threats, resulting in a CLEAN assessment "
            f"with a risk score of {total} out of 100. The email appears to be legitimate "
            f"with no detected phishing indicators."
        )

    pdf.body_text(verdict)
    pdf._pdf.ln(4)

    # Key findings summary
    if breakdown:
        pdf.sub_title("Key Findings")
        top_findings = sorted(breakdown, key=lambda x: x.get("points", 0), reverse=True)[:5]
        p = pdf._pdf
        for i, finding in enumerate(top_findings, 1):
            reason = finding.get("reason", "Unknown finding")
            pts = finding.get("points", 0)
            cat = finding.get("category", "general")

            color = _COLORS["critical"] if pts >= 10 else _COLORS["high"] if pts >= 5 else _COLORS["medium"]

            p.set_font(pdf._body_font, "B", 9)
            p.set_text_color(*color)
            p.cell(8, 5, f"{i}.")
            p.set_font(pdf._body_font, "", 9)
            p.set_text_color(50, 50, 50)
            p.multi_cell(0, 5, f"{reason} (+{pts} points, {cat})", new_x="LMARGIN", new_y="NEXT")
            p.ln(1)

    # Authentication overview (plain English)
    spf = headers.get("spf_result", "none")
    dkim = headers.get("dkim_result", "none")
    dmarc = headers.get("dmarc_result", "none")

    pdf._pdf.ln(4)
    pdf.sub_title("Email Authentication Overview")

    auth_summary = _build_auth_summary(spf, dkim, dmarc)
    pdf.body_text(auth_summary)

    pdf.draw_footer()


def _build_auth_summary(spf, dkim, dmarc):
    """Build a plain-English explanation of email authentication results."""
    parts = []

    parts.append(
        "Email authentication protocols help verify that an email genuinely came from "
        "the domain it claims to be from. Three key checks were performed:"
    )

    spf_s = spf.lower() if spf else "none"
    if spf_s == "pass":
        parts.append(
            "SPF (Sender Policy Framework): PASSED. The sending mail server is authorized "
            "by the sender's domain to send email on its behalf."
        )
    elif spf_s in ("fail", "softfail"):
        parts.append(
            "SPF (Sender Policy Framework): FAILED. The sending mail server is NOT authorized "
            "by the claimed sender's domain. This is a strong indicator of email spoofing."
        )
    else:
        parts.append(
            "SPF (Sender Policy Framework): NOT CONFIGURED. The sender's domain does not "
            "publish an SPF record, so server authorization could not be verified."
        )

    dkim_s = dkim.lower() if dkim else "none"
    if dkim_s == "pass":
        parts.append(
            "DKIM (DomainKeys Identified Mail): PASSED. The email's cryptographic signature "
            "is valid, confirming the message was not altered in transit."
        )
    elif dkim_s == "fail":
        parts.append(
            "DKIM (DomainKeys Identified Mail): FAILED. The email's cryptographic signature "
            "is invalid or missing, which may indicate the message was tampered with."
        )
    else:
        parts.append(
            "DKIM (DomainKeys Identified Mail): NOT CONFIGURED. No DKIM signature was found, "
            "so message integrity could not be verified."
        )

    dmarc_s = dmarc.lower() if dmarc else "none"
    if dmarc_s == "pass":
        parts.append(
            "DMARC (Domain-based Message Authentication): PASSED. The sender's domain has a "
            "DMARC policy and this email conforms to it."
        )
    elif dmarc_s == "fail":
        parts.append(
            "DMARC (Domain-based Message Authentication): FAILED. The email violates the "
            "sender domain's authentication policy, strongly suggesting it is not legitimate."
        )
    else:
        parts.append(
            "DMARC (Domain-based Message Authentication): NOT CONFIGURED. The sender's domain "
            "does not publish a DMARC policy."
        )

    return "\n\n".join(parts)


# =========================================================================
# Risk Assessment
# =========================================================================

def _render_risk_assessment(pdf, report_dict):
    pdf._pdf.ln(6)
    pdf.sub_title("Risk Assessment", 12)

    score = report_dict.get("score", {})
    total = score.get("total", 0)
    level = score.get("level", "clean")

    p = pdf._pdf

    # Visual risk bar
    _draw_risk_bar(pdf, total, p.get_y())
    p.ln(18)

    # Risk level explanation
    level_descriptions = {
        "critical": "CRITICAL (70-100): This email contains multiple confirmed phishing indicators and/or malicious content. Immediate containment and investigation is recommended.",
        "high": "HIGH (50-69): Strong evidence of phishing or social engineering. The email should be treated as malicious until proven otherwise.",
        "medium": "MEDIUM (30-49): Suspicious characteristics detected that require further investigation. Exercise caution with any links or attachments.",
        "low": "LOW (10-29): Minor anomalies detected that are common in legitimate emails. Low probability of malicious intent.",
        "clean": "CLEAN (0-9): No significant threats detected. The email appears to be legitimate.",
    }

    desc = level_descriptions.get(level, "")
    color = _COLORS.get(level, _COLORS["gray"])

    # Colored verdict box
    box_y = p.get_y()
    p.set_fill_color(*color)
    p.rect(10, box_y, 190, 14, "F")
    p.set_y(box_y + 3)
    p.set_font(pdf._body_font, "B", 10)
    p.set_text_color(255, 255, 255)
    p.cell(0, 8, f"  {desc}", new_x="LMARGIN", new_y="NEXT")
    p.ln(6)

    # Score breakdown table
    breakdown = score.get("breakdown", [])
    if breakdown:
        pdf.sub_title("Score Breakdown")

        # Table header
        p.set_font(pdf._body_font, "B", 8)
        p.set_fill_color(*_COLORS["bg_light"])
        p.set_text_color(*_COLORS["dark"])
        p.cell(95, 7, "  Finding", border="B", fill=True)
        p.cell(40, 7, "  Category", border="B", fill=True)
        p.cell(20, 7, "  Points", border="B", fill=True)
        p.cell(35, 7, "  Severity", border="B", fill=True, new_x="LMARGIN", new_y="NEXT")

        p.set_font(pdf._body_font, "", 8)
        for i, item in enumerate(breakdown):
            pdf.check_page_break(8)
            reason = str(item.get("reason", ""))[:60]
            cat = str(item.get("category", ""))
            pts = item.get("points", 0)

            if pts >= 10:
                sev = "Critical"
                sev_color = _COLORS["critical"]
            elif pts >= 5:
                sev = "High"
                sev_color = _COLORS["high"]
            elif pts >= 3:
                sev = "Medium"
                sev_color = _COLORS["medium"]
            else:
                sev = "Low"
                sev_color = _COLORS["low"]

            # Alternate row background
            if i % 2 == 0:
                p.set_fill_color(252, 252, 252)
            else:
                p.set_fill_color(255, 255, 255)

            p.set_text_color(50, 50, 50)
            p.cell(95, 6, f"  {reason}", fill=True)
            p.cell(40, 6, f"  {cat}", fill=True)
            p.set_font(pdf._mono_font, "", 8)
            p.cell(20, 6, f"  +{pts}", fill=True)
            p.set_font(pdf._body_font, "B", 8)
            p.set_text_color(*sev_color)
            p.cell(35, 6, f"  {sev}", fill=True, new_x="LMARGIN", new_y="NEXT")
            p.set_font(pdf._body_font, "", 8)

    pdf.draw_footer()


def _draw_risk_bar(pdf, score_val, y_pos):
    """Draw a horizontal risk gradient bar with score marker."""
    p = pdf._pdf
    bar_x = 25
    bar_w = 160
    bar_h = 10

    # Draw gradient segments
    for min_s, max_s, color in _RISK_SEGMENTS:
        x = bar_x + (min_s / 100) * bar_w
        w = ((max_s - min_s) / 100) * bar_w
        p.set_fill_color(*color)
        if min_s == 0:
            p.rect(x, y_pos, w, bar_h, "F")
        elif max_s == 100:
            p.rect(x, y_pos, w, bar_h, "F")
        else:
            p.rect(x, y_pos, w, bar_h, "F")

    # Score marker (white triangle/line)
    marker_x = bar_x + (score_val / 100) * bar_w
    p.set_fill_color(255, 255, 255)
    p.rect(marker_x - 1.2, y_pos - 2, 2.4, bar_h + 4, "F")

    # Score label above marker
    p.set_font(pdf._body_font, "B", 9)
    p.set_text_color(*_COLORS["dark"])
    label = str(score_val)
    label_w = p.get_string_width(label)
    p.set_xy(marker_x - label_w / 2, y_pos - 7)
    p.cell(label_w, 5, label, align="C")

    # Scale labels
    p.set_font(pdf._body_font, "", 7)
    p.set_text_color(*_COLORS["gray"])
    p.set_xy(bar_x - 3, y_pos + bar_h + 1)
    p.cell(10, 4, "0")
    p.set_xy(bar_x + bar_w - 7, y_pos + bar_h + 1)
    p.cell(10, 4, "100")

    # Level labels
    labels = [("Clean", 5), ("Low", 20), ("Medium", 40), ("High", 60), ("Critical", 85)]
    p.set_font(pdf._body_font, "", 6)
    for label_text, pos in labels:
        lx = bar_x + (pos / 100) * bar_w
        lw = p.get_string_width(label_text)
        p.set_xy(lx - lw / 2, y_pos + bar_h + 5)
        p.cell(lw, 4, label_text, align="C")

    p.set_y(y_pos + bar_h + 10)


# =========================================================================
# Recommended Actions
# =========================================================================

def _render_recommended_actions(pdf, report_dict):
    pdf.section_title("Recommended Actions", 16)

    score = report_dict.get("score", {})
    level = score.get("level", "clean")
    breakdown = score.get("breakdown", [])
    urls = report_dict.get("urls", [])
    attachments = report_dict.get("attachments", [])

    p = pdf._pdf
    actions = []

    # Level-based general actions
    if level in ("critical", "high"):
        actions.append("Do not click any links or open any attachments from this email.")
        actions.append("Report this email to your IT security team or security operations center immediately.")
        actions.append("Block the sender's email address and domain at your email gateway.")
        actions.append("If this email was received by multiple recipients, notify all of them not to interact with it.")
    elif level == "medium":
        actions.append("Do not click links or open attachments until the sender's identity has been verified.")
        actions.append("Contact the purported sender through an independent channel (phone, separate email) to confirm legitimacy.")
        actions.append("Report this email to your IT security team for further investigation.")
    elif level == "low":
        actions.append("Exercise normal caution when interacting with this email.")
        actions.append("Verify the sender if the email requests any sensitive information or actions.")
    else:
        actions.append("No immediate action is required based on the analysis findings.")
        actions.append("Continue to follow standard email security best practices.")

    # Finding-specific recommendations
    categories = set()
    for item in breakdown:
        categories.add(item.get("category", ""))
        reason = str(item.get("reason", "")).lower()
        if "credential" in reason or "login form" in reason:
            actions.append(
                "URGENT: If you entered any credentials (username, password) on a page linked from "
                "this email, change those passwords immediately and enable multi-factor authentication "
                "on the affected accounts."
            )
        if "macro" in reason or "vba" in reason:
            actions.append(
                "If any attachments were opened with macros enabled, run a full antivirus scan "
                "on the affected system and consider isolating it from the network."
            )

    # URL-specific
    has_phishing_urls = any(u.get("risk_score", 0) > 5 for u in urls)
    if has_phishing_urls:
        actions.append(
            "The email contains suspicious URLs. If any were visited, clear browser cache and cookies, "
            "and monitor account activity for unauthorized access."
        )

    has_cred_forms = any(u.get("has_credential_form") for u in urls)
    if has_cred_forms:
        actions.append(
            "Credential harvesting forms were detected on linked pages. These are designed to steal "
            "login credentials. If you submitted any information, treat all entered credentials as compromised."
        )

    # Attachment-specific
    has_malware = any(
        a.get("is_executable") or a.get("has_macros") or a.get("yara_matches")
        for a in attachments
    )
    if has_malware:
        actions.append(
            "Potentially malicious attachments were detected. If opened, immediately disconnect "
            "the system from the network and initiate an incident response procedure."
        )

    # Deduplicate while preserving order
    seen = set()
    unique_actions = []
    for a in actions:
        if a not in seen:
            seen.add(a)
            unique_actions.append(a)

    # Render actions
    for i, action in enumerate(unique_actions, 1):
        pdf.check_page_break(12)

        # Colored bullet based on urgency
        if "URGENT" in action or "immediately" in action.lower():
            bullet_color = _COLORS["critical"]
        elif level in ("critical", "high"):
            bullet_color = _COLORS["high"]
        elif level == "medium":
            bullet_color = _COLORS["medium"]
        else:
            bullet_color = _COLORS["low"]

        # Numbered item with colored accent
        p.set_fill_color(*bullet_color)
        p.rect(12, p.get_y() + 1, 3, 3, "F")

        p.set_font(pdf._body_font, "B", 10)
        p.set_text_color(*_COLORS["dark"])
        p.cell(8, 6, "")
        p.set_font(pdf._body_font, "", 10)
        p.set_text_color(50, 50, 50)
        p.multi_cell(175, 5.5, f"{i}. {action}", new_x="LMARGIN", new_y="NEXT")
        p.ln(3)

    pdf.draw_footer()


# =========================================================================
# Technical Findings
# =========================================================================

def _render_technical_findings(pdf, report_dict):
    pdf.section_title("Technical Findings", 16)

    headers = report_dict.get("headers", {})
    score = report_dict.get("score", {})
    urls = report_dict.get("urls", [])
    attachments = report_dict.get("attachments", [])
    body_data = report_dict.get("body", {})
    ml = report_dict.get("ml_classification", {})
    ti = report_dict.get("threat_intel", {})
    mitre = report_dict.get("mitre_mappings", [])

    p = pdf._pdf

    # --- Email Headers ---
    pdf.sub_title("Email Headers")
    pdf.detail_row("From", f"{headers.get('from_display', '')} <{headers.get('from_address', '')}>")
    pdf.detail_row("Reply-To", headers.get("reply_to", "-"))
    pdf.detail_row("Return-Path", headers.get("return_path", "-"))
    pdf.detail_row("To", ", ".join(headers.get("to_addresses", [])) or "-")
    pdf.detail_row("Subject", headers.get("subject", "-"))
    pdf.detail_row("Date", headers.get("date", "-"))
    pdf.detail_row("Message-ID", headers.get("message_id", "-"))
    pdf.detail_row("Origin IP", headers.get("originating_ip", "Unknown"))
    p.ln(3)

    # --- Authentication Results ---
    pdf.sub_title("Authentication Results")
    spf = headers.get("spf_result", "none")
    dkim = headers.get("dkim_result", "none")
    dmarc = headers.get("dmarc_result", "none")

    for proto, result in [("SPF", spf), ("DKIM", dkim), ("DMARC", dmarc)]:
        result_upper = result.upper() if result else "NONE"
        if result and result.lower() == "pass":
            color = _COLORS["clean"]
        elif result and result.lower() in ("fail", "softfail"):
            color = _COLORS["critical"]
        else:
            color = _COLORS["gray"]

        p.set_font(pdf._body_font, "B", 9)
        p.set_text_color(*_COLORS["dark"])
        p.cell(38, 5, f"{proto}:")
        p.set_font(pdf._body_font, "B", 9)
        p.set_text_color(*color)
        p.cell(0, 5, result_upper, new_x="LMARGIN", new_y="NEXT")

    # DNS records
    if headers.get("spf_dns_record"):
        p.ln(2)
        p.set_font(pdf._body_font, "", 8)
        p.set_text_color(*_COLORS["gray"])
        p.cell(38, 4, "SPF Record:")
        pdf.mono_text(headers["spf_dns_record"])
    if headers.get("dmarc_dns_record"):
        p.set_font(pdf._body_font, "", 8)
        p.set_text_color(*_COLORS["gray"])
        p.cell(38, 4, "DMARC Record:")
        pdf.mono_text(headers["dmarc_dns_record"])
    p.ln(3)

    # --- Anomalies ---
    anomalies = headers.get("anomalies", [])
    if anomalies:
        pdf.sub_title("Header Anomalies")
        for a in anomalies:
            pdf.check_page_break(8)
            p.set_fill_color(255, 245, 230)
            p.rect(12, p.get_y(), 2, 5, "F")
            p.set_font(pdf._body_font, "", 9)
            p.set_text_color(180, 90, 40)
            p.cell(6, 5, "")
            p.multi_cell(0, 5, str(a), new_x="LMARGIN", new_y="NEXT")
        p.set_text_color(*_COLORS["dark"])
        p.ln(3)

    # --- URLs ---
    if urls:
        pdf.check_page_break(20)
        pdf.sub_title(f"URLs Analyzed ({len(urls)})")
        for u in urls[:15]:
            pdf.check_page_break(20)
            url_str = str(u.get("url", ""))[:85]
            risk = u.get("risk_score", 0)

            # URL entry with risk indicator
            if risk >= 8:
                accent = _COLORS["critical"]
            elif risk >= 4:
                accent = _COLORS["high"]
            else:
                accent = _COLORS["low"]

            p.set_fill_color(*accent)
            p.rect(12, p.get_y(), 2, 5, "F")

            p.set_font(pdf._mono_font, "", 8)
            p.set_text_color(50, 50, 50)
            p.cell(6, 5, "")
            p.cell(145, 5, url_str)
            p.set_font(pdf._body_font, "B", 8)
            p.set_text_color(*accent)
            p.cell(0, 5, f"Risk: {risk}", new_x="LMARGIN", new_y="NEXT")

            # Threat indicators
            indicators = u.get("threat_indicators", [])
            for ind in indicators[:3]:
                p.set_font(pdf._body_font, "", 7)
                p.set_text_color(180, 90, 40)
                p.cell(10, 4, "")
                p.cell(0, 4, str(ind)[:80], new_x="LMARGIN", new_y="NEXT")

            # Browser detonation findings
            if u.get("has_credential_form"):
                p.set_font(pdf._body_font, "B", 7)
                p.set_text_color(*_COLORS["critical"])
                p.cell(10, 4, "")
                p.cell(0, 4, "[DETONATION] Credential harvesting form detected", new_x="LMARGIN", new_y="NEXT")
            if u.get("js_redirects"):
                p.set_font(pdf._body_font, "", 7)
                p.set_text_color(180, 90, 40)
                p.cell(10, 4, "")
                p.cell(0, 4, f"[DETONATION] {len(u['js_redirects'])} JavaScript redirect(s)", new_x="LMARGIN", new_y="NEXT")
            if u.get("iframes_detected"):
                p.set_font(pdf._body_font, "", 7)
                p.set_text_color(180, 90, 40)
                p.cell(10, 4, "")
                p.cell(0, 4, f"[DETONATION] {len(u['iframes_detected'])} iframe(s) detected", new_x="LMARGIN", new_y="NEXT")

            p.set_text_color(*_COLORS["dark"])
            p.ln(2)
        p.ln(3)

    # --- Attachments ---
    if attachments:
        pdf.check_page_break(20)
        pdf.sub_title(f"Attachments ({len(attachments)})")
        for att in attachments:
            pdf.check_page_break(20)
            fname = str(att.get("filename", "unknown"))
            size_kb = round(att.get("size", 0) / 1024, 1)

            has_threat = att.get("is_executable") or att.get("has_macros") or att.get("yara_matches")
            accent = _COLORS["critical"] if has_threat else _COLORS["accent"]

            p.set_fill_color(*accent)
            p.rect(12, p.get_y(), 2, 5, "F")

            p.set_font(pdf._body_font, "B", 9)
            p.set_text_color(*_COLORS["dark"])
            p.cell(6, 5, "")
            p.cell(0, 5, f"{fname} ({size_kb} KB)", new_x="LMARGIN", new_y="NEXT")

            # Hashes
            p.set_font(pdf._mono_font, "", 7)
            p.set_text_color(*_COLORS["gray"])
            if att.get("md5"):
                p.cell(10, 4, "")
                p.cell(0, 4, f"MD5:    {att['md5']}", new_x="LMARGIN", new_y="NEXT")
            if att.get("sha256"):
                p.cell(10, 4, "")
                p.cell(0, 4, f"SHA256: {att['sha256']}", new_x="LMARGIN", new_y="NEXT")

            # YARA matches
            yara_matches = att.get("yara_matches", [])
            for ym in yara_matches:
                if isinstance(ym, dict):
                    p.set_font(pdf._body_font, "B", 7)
                    p.set_text_color(*_COLORS["critical"])
                    rule = ym.get("rule", "unknown")
                    sev = ym.get("severity", "")
                    desc = ym.get("description", "")[:50]
                    p.cell(10, 4, "")
                    p.cell(0, 4, f"[YARA] {rule} [{sev}] {desc}", new_x="LMARGIN", new_y="NEXT")

            # Threat indicators
            for ind in att.get("threat_indicators", []):
                p.set_font(pdf._body_font, "", 7)
                p.set_text_color(180, 90, 40)
                p.cell(10, 4, "")
                p.cell(0, 4, str(ind)[:80], new_x="LMARGIN", new_y="NEXT")

            p.set_text_color(*_COLORS["dark"])
            p.ln(2)
        p.ln(3)

    # --- ML Classification ---
    if ml and ml.get("ml_available"):
        pdf.check_page_break(20)
        pdf.sub_title("Machine Learning Classification")
        confidence = ml.get("ml_confidence", 0)
        ml_verdict = ml.get("ml_verdict", "unknown")

        if ml_verdict == "phishing":
            v_color = _COLORS["critical"]
        elif ml_verdict == "suspicious":
            v_color = _COLORS["high"]
        else:
            v_color = _COLORS["clean"]

        p.set_font(pdf._body_font, "B", 10)
        p.set_text_color(*v_color)
        p.cell(0, 6, f"  Verdict: {ml_verdict.upper()} ({confidence:.0f}% confidence)", new_x="LMARGIN", new_y="NEXT")
        p.set_font(pdf._body_font, "", 8)
        p.set_text_color(*_COLORS["gray"])
        p.cell(0, 5, "  Model: Random Forest + Logistic Regression ensemble", new_x="LMARGIN", new_y="NEXT")
        p.ln(3)

    # --- NLP Analysis ---
    nlp = body_data.get("nlp_analysis", {}) if isinstance(body_data, dict) else {}
    if nlp and nlp.get("overall_nlp_score", 0) > 0:
        pdf.check_page_break(20)
        pdf.sub_title("Natural Language Analysis")
        p.set_font(pdf._body_font, "", 9)
        p.set_text_color(50, 50, 50)
        for label, key in [("Urgency", "urgency_score"), ("Threat Language", "threat_score"),
                           ("Impersonation", "impersonation_score"), ("Grammar Anomalies", "grammar_score"),
                           ("Social Engineering", "social_engineering_score")]:
            val = nlp.get(key, 0)
            if val > 0:
                bar_color = _COLORS["critical"] if val >= 70 else _COLORS["high"] if val >= 40 else _COLORS["medium"]
                p.set_font(pdf._body_font, "", 9)
                p.cell(45, 5, f"  {label}:")
                # Mini bar
                p.set_fill_color(*_COLORS["bg_light"])
                p.rect(p.get_x(), p.get_y() + 1, 60, 3, "F")
                p.set_fill_color(*bar_color)
                p.rect(p.get_x(), p.get_y() + 1, 60 * val / 100, 3, "F")
                p.cell(62, 5, "")
                p.set_font(pdf._mono_font, "", 8)
                p.cell(0, 5, f"{val}/100", new_x="LMARGIN", new_y="NEXT")
        if nlp.get("summary"):
            p.set_font(pdf._body_font, "", 8)
            p.set_text_color(*_COLORS["gray"])
            p.multi_cell(0, 4.5, f"  {nlp['summary']}", new_x="LMARGIN", new_y="NEXT")
        p.ln(3)

    # --- Threat Intelligence ---
    ti_summary = ti.get("summary", {}) if isinstance(ti, dict) else {}
    if ti_summary.get("total_checked", 0) > 0:
        pdf.check_page_break(15)
        pdf.sub_title("Threat Intelligence")
        feeds = ", ".join(ti_summary.get("feeds_used", []))
        p.set_font(pdf._body_font, "", 9)
        p.set_text_color(50, 50, 50)
        p.cell(0, 5, f"  Feeds queried: {feeds}", new_x="LMARGIN", new_y="NEXT")
        p.cell(0, 5, f"  IOCs checked: {ti_summary.get('total_checked', 0)}, "
                      f"Flagged: {ti_summary.get('total_flagged', 0)}", new_x="LMARGIN", new_y="NEXT")
        if ti_summary.get("total_flagged", 0) > 0:
            p.set_font(pdf._body_font, "B", 9)
            p.set_text_color(*_COLORS["critical"])
            p.cell(0, 5, f"  WARNING: {ti_summary['total_flagged']} IOC(s) flagged as malicious",
                   new_x="LMARGIN", new_y="NEXT")
        p.ln(3)

    # --- MITRE ATT&CK ---
    if mitre:
        pdf.check_page_break(20)
        pdf.sub_title("MITRE ATT&CK Mapping")

        # Table header
        p.set_font(pdf._body_font, "B", 8)
        p.set_fill_color(*_COLORS["bg_light"])
        p.set_text_color(*_COLORS["dark"])
        p.cell(25, 6, "  ID", border="B", fill=True)
        p.cell(50, 6, "  Technique", border="B", fill=True)
        p.cell(35, 6, "  Tactic", border="B", fill=True)
        p.cell(80, 6, "  Finding", border="B", fill=True, new_x="LMARGIN", new_y="NEXT")

        p.set_font(pdf._body_font, "", 7)
        for i, m in enumerate(mitre):
            pdf.check_page_break(8)
            if i % 2 == 0:
                p.set_fill_color(252, 252, 252)
            else:
                p.set_fill_color(255, 255, 255)
            p.set_text_color(50, 50, 50)

            p.set_font(pdf._mono_font, "", 7)
            p.cell(25, 5, f"  {str(m.get('technique_id', ''))}", fill=True)
            p.set_font(pdf._body_font, "", 7)
            p.cell(50, 5, f"  {str(m.get('technique', ''))[:30]}", fill=True)
            p.cell(35, 5, f"  {str(m.get('tactic', ''))}", fill=True)
            p.cell(80, 5, f"  {str(m.get('finding', ''))[:50]}", fill=True, new_x="LMARGIN", new_y="NEXT")
        p.ln(3)

    pdf.draw_footer()


# =========================================================================
# Appendix
# =========================================================================

def _render_appendix(pdf, report_dict):
    pdf.section_title("Appendix", 16)

    headers = report_dict.get("headers", {})
    iocs = report_dict.get("iocs", {})
    whois = report_dict.get("whois", {})

    p = pdf._pdf

    # --- Received Chain ---
    received_chain = headers.get("received_chain", [])
    if received_chain:
        pdf.sub_title("Email Received Chain")
        for i, hop in enumerate(received_chain):
            pdf.check_page_break(10)
            p.set_font(pdf._body_font, "B", 8)
            p.set_text_color(*_COLORS["accent"])
            p.cell(0, 5, f"  Hop {i + 1}", new_x="LMARGIN", new_y="NEXT")
            p.set_font(pdf._mono_font, "", 7)
            p.set_text_color(60, 60, 60)
            if isinstance(hop, dict):
                for k, v in hop.items():
                    p.cell(6, 4, "")
                    p.cell(0, 4, f"{k}: {v}"[:90], new_x="LMARGIN", new_y="NEXT")
            else:
                hop_str = str(hop)[:120]
                p.cell(6, 4, "")
                p.cell(0, 4, hop_str, new_x="LMARGIN", new_y="NEXT")
            p.ln(1)
        p.ln(3)

    # --- Full IOC List ---
    pdf.sub_title("Indicators of Compromise (IOCs)")
    ioc_sections = [
        ("IP Addresses", "ip_addresses"),
        ("Domains", "domains"),
        ("Email Addresses", "email_addresses"),
        ("URLs", "urls"),
        ("File Hashes", "file_hashes"),
    ]

    for label, key in ioc_sections:
        items = iocs.get(key, [])
        if items:
            pdf.check_page_break(10)
            p.set_font(pdf._body_font, "B", 9)
            p.set_text_color(*_COLORS["dark"])
            p.cell(0, 6, f"  {label} ({len(items)})", new_x="LMARGIN", new_y="NEXT")
            p.set_font(pdf._mono_font, "", 7)
            p.set_text_color(60, 60, 60)
            for item in items[:30]:
                pdf.check_page_break(6)
                p.cell(10, 4, "")
                p.cell(0, 4, str(item)[:95], new_x="LMARGIN", new_y="NEXT")
            p.ln(2)

    # --- WHOIS Data ---
    if whois:
        pdf.check_page_break(15)
        pdf.sub_title("Domain WHOIS Intelligence")
        p.set_font(pdf._body_font, "", 8)
        for domain, info in whois.items():
            if not isinstance(info, dict):
                continue
            pdf.check_page_break(12)
            p.set_font(pdf._body_font, "B", 8)
            p.set_text_color(*_COLORS["accent"])
            p.cell(0, 5, f"  {domain}", new_x="LMARGIN", new_y="NEXT")
            p.set_font(pdf._body_font, "", 8)
            p.set_text_color(60, 60, 60)
            for k in ["registrar", "creation_date", "country", "domain_age_days"]:
                val = info.get(k)
                if val is not None:
                    p.cell(10, 4, "")
                    p.cell(0, 4, f"{k}: {val}", new_x="LMARGIN", new_y="NEXT")
            p.ln(2)

    # --- Footer ---
    p.ln(8)
    p.set_draw_color(*_COLORS["divider"])
    p.line(10, p.get_y(), 200, p.get_y())
    p.ln(4)
    p.set_font(pdf._body_font, "", 8)
    p.set_text_color(*_COLORS["gray"])
    p.cell(0, 5, "End of Report", align="C", new_x="LMARGIN", new_y="NEXT")
    p.cell(0, 5, f"Generated by PhishGuard Email Phishing Analyzer -- "
                  f"{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
           align="C")

    pdf.draw_footer()
