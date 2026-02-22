from models import ThreatScore
from config import SCORE_WEIGHTS, THREAT_LEVELS, URGENCY_KEYWORDS
from header_analyzer import score_headers
from attachment_analyzer import score_attachment_breakdown


def calculate_score(headers, url_findings, attachment_findings, body):
    score = ThreatScore()
    breakdown = []

    # --- Headers ---
    for reason, points in score_headers(headers):
        breakdown.append({"reason": reason, "points": points, "category": "headers"})

    # --- URLs ---
    for uf in url_findings:
        if uf.known_phishing:
            breakdown.append({"reason": f"Known phishing domain: {uf.domain}", "points": SCORE_WEIGHTS["known_phish_url"], "category": "urls"})
        if uf.is_ip_based:
            breakdown.append({"reason": f"IP-based URL: {uf.url[:60]}", "points": SCORE_WEIGHTS["url_ip_address"], "category": "urls"})
        if uf.has_homoglyph:
            breakdown.append({"reason": f"Typosquatting: {uf.domain} -> {uf.homoglyph_target}", "points": SCORE_WEIGHTS["url_homoglyph"], "category": "urls"})
        if uf.subdomain_count > 1:
            breakdown.append({"reason": f"Excessive subdomains: {uf.domain}", "points": SCORE_WEIGHTS["url_excessive_subdomains"], "category": "urls"})
        if len(uf.redirect_chain) > 2:
            breakdown.append({"reason": f"{len(uf.redirect_chain)} redirects for {uf.domain}", "points": SCORE_WEIGHTS["url_redirect_chain"], "category": "urls"})
        if uf.suspicious_tld:
            breakdown.append({"reason": f"Suspicious TLD: {uf.domain}", "points": SCORE_WEIGHTS["suspicious_url"], "category": "urls"})
        if uf.is_shortened:
            breakdown.append({"reason": f"Shortened URL hides destination: {uf.domain}", "points": SCORE_WEIGHTS["url_shortened"], "category": "urls"})

    # --- Attachments: single source of truth via attachment_analyzer ---
    for af in attachment_findings:
        for reason, points in score_attachment_breakdown(af):
            breakdown.append({"reason": reason, "points": points, "category": "attachments"})

    # --- Body ---
    urgency_found = _check_urgency(body, headers.subject)
    if urgency_found:
        # Scale: 8 base + 2 per additional keyword beyond the first, capped at 30
        urgency_points = min(SCORE_WEIGHTS["urgency_language"] + (len(urgency_found) - 1) * 2, 30)
        breakdown.append({
            "reason": f"Urgency language ({len(urgency_found)} indicators): {', '.join(urgency_found[:3])}",
            "points": urgency_points,
            "category": "body",
        })
    if body.javascript_detected:
        breakdown.append({"reason": "JavaScript in HTML body", "points": 8, "category": "body"})
    if body.form_action_external:
        breakdown.append({"reason": "Form submits to external URL", "points": 10, "category": "body"})
    if body.hidden_text:
        breakdown.append({"reason": "Hidden text in HTML", "points": 5, "category": "body"})

    score.total = min(sum(item["points"] for item in breakdown), 100)
    score.breakdown = breakdown

    for level_name in ("critical", "high", "medium", "low", "clean"):
        level = THREAT_LEVELS[level_name]
        if score.total >= level["min"]:
            score.level = level_name
            score.level_label = level["label"]
            score.level_color = level["color"]
            break

    return score


def _check_urgency(body, subject=""):
    text = ((body.text_content or "") + " " + (body.html_content or "") + " " + (subject or "")).lower()
    return [kw for kw in URGENCY_KEYWORDS if kw.lower() in text]
