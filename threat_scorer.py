from models import ThreatScore
from config import SCORE_WEIGHTS, THREAT_LEVELS, URGENCY_KEYWORDS
from header_analyzer import score_headers
from attachment_analyzer import score_attachment_breakdown


def calculate_score(headers, url_findings, attachment_findings, body,
                    ml_result=None, nlp_result=None, threat_intel_result=None):
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
        if getattr(uf, "is_idn_homograph", False):
            breakdown.append({"reason": f"IDN homograph attack: {uf.domain}", "points": SCORE_WEIGHTS.get("idn_homograph", 15), "category": "urls"})
        if uf.subdomain_count > 1:
            breakdown.append({"reason": f"Excessive subdomains: {uf.domain}", "points": SCORE_WEIGHTS["url_excessive_subdomains"], "category": "urls"})
        if len(uf.redirect_chain) > 2:
            breakdown.append({"reason": f"{len(uf.redirect_chain)} redirects for {uf.domain}", "points": SCORE_WEIGHTS["url_redirect_chain"], "category": "urls"})
        if uf.suspicious_tld:
            breakdown.append({"reason": f"Suspicious TLD: {uf.domain}", "points": SCORE_WEIGHTS["suspicious_url"], "category": "urls"})
        if uf.is_shortened:
            breakdown.append({"reason": f"Shortened URL hides destination: {uf.domain}", "points": SCORE_WEIGHTS["url_shortened"], "category": "urls"})
        # Browser detonation findings
        if uf.js_redirects:
            breakdown.append({"reason": f"JavaScript redirect detected: {uf.domain} ({len(uf.js_redirects)} hop(s))", "points": SCORE_WEIGHTS.get("browser_js_redirect", 10), "category": "browser"})
        if uf.meta_refresh_detected:
            breakdown.append({"reason": f"Meta refresh tag: {uf.domain}", "points": SCORE_WEIGHTS.get("browser_meta_refresh", 8), "category": "browser"})
        if uf.iframes_detected:
            external = [i for i in uf.iframes_detected if isinstance(i, dict) and i.get("domain") and i["domain"] != uf.domain]
            if external:
                breakdown.append({"reason": f"External iframe attack: {uf.domain} ({len(external)} iframe(s))", "points": SCORE_WEIGHTS.get("browser_iframe_attack", 12), "category": "browser"})
        if uf.has_credential_form:
            breakdown.append({"reason": f"Credential harvesting form: {uf.domain}", "points": SCORE_WEIGHTS.get("browser_credential_form", 15), "category": "browser"})
        # HTML similarity / brand impersonation on URL
        html_sim = getattr(uf, "html_similarity", {}) or {}
        if html_sim.get("is_impersonation"):
            top = html_sim.get("top_match", {})
            breakdown.append({
                "reason": f"Brand impersonation: {uf.domain} mimics {top.get('brand', 'unknown')} ({top.get('similarity', 0):.0f}% similar)",
                "points": SCORE_WEIGHTS.get("html_brand_impersonation", 15),
                "category": "urls",
            })
        elif html_sim.get("top_match") and html_sim["top_match"].get("similarity", 0) >= 35:
            top = html_sim["top_match"]
            breakdown.append({
                "reason": f"HTML similarity to {top.get('brand', 'unknown')}: {top.get('similarity', 0):.0f}% (suspicious)",
                "points": SCORE_WEIGHTS.get("html_brand_suspicious", 8),
                "category": "urls",
            })
        # Intermediate domain findings
        if uf.intermediate_domains:
            for idom in uf.intermediate_domains:
                if isinstance(idom, dict) and idom.get("indicators"):
                    for ind in idom["indicators"]:
                        if "phishing" in ind.lower():
                            breakdown.append({"reason": f"Intermediate phishing domain: {idom.get('domain', 'unknown')}", "points": SCORE_WEIGHTS.get("intermediate_domain_phishing", 12), "category": "urls"})
                            break
                        elif "suspicious" in ind.lower() or "typosquatting" in ind.lower():
                            breakdown.append({"reason": f"Intermediate suspicious domain: {idom.get('domain', 'unknown')}", "points": SCORE_WEIGHTS.get("intermediate_domain_suspicious", 8), "category": "urls"})
                            break

    # --- Attachments: single source of truth via attachment_analyzer ---
    for af in attachment_findings:
        for reason, points in score_attachment_breakdown(af):
            breakdown.append({"reason": reason, "points": points, "category": "attachments"})

    # --- Body ---
    urgency_found = _check_urgency(body, headers.subject)
    if urgency_found:
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

    # --- NLP Analysis ---
    if nlp_result and nlp_result.get("overall_nlp_score", 0) > 0:
        nlp_score = nlp_result["overall_nlp_score"]
        if nlp_result.get("urgency_score", 0) >= 50:
            breakdown.append({
                "reason": f"NLP: High urgency language (score: {nlp_result['urgency_score']})",
                "points": SCORE_WEIGHTS.get("nlp_urgency_high", 10),
                "category": "nlp",
            })
        if nlp_result.get("threat_score", 0) >= 50:
            breakdown.append({
                "reason": f"NLP: Threat language detected (score: {nlp_result['threat_score']})",
                "points": SCORE_WEIGHTS.get("nlp_threat_high", 8),
                "category": "nlp",
            })
        if nlp_result.get("social_engineering_score", 0) >= 40:
            breakdown.append({
                "reason": f"NLP: Social engineering patterns (score: {nlp_result['social_engineering_score']})",
                "points": SCORE_WEIGHTS.get("nlp_social_engineering", 8),
                "category": "nlp",
            })
        if nlp_result.get("impersonation_score", 0) >= 40:
            breakdown.append({
                "reason": f"NLP: Impersonation indicators (score: {nlp_result['impersonation_score']})",
                "points": SCORE_WEIGHTS.get("nlp_impersonation", 6),
                "category": "nlp",
            })
        if nlp_result.get("grammar_score", 0) >= 50:
            breakdown.append({
                "reason": f"NLP: Grammar anomalies (score: {nlp_result['grammar_score']})",
                "points": 4,
                "category": "nlp",
            })

    # --- ML Classification ---
    if ml_result and ml_result.get("ml_available") and ml_result.get("ml_confidence") is not None:
        confidence = ml_result["ml_confidence"]
        if confidence >= 75:
            breakdown.append({
                "reason": f"ML classification: {confidence:.0f}% phishing confidence",
                "points": SCORE_WEIGHTS.get("ml_phishing_high", 12),
                "category": "ml",
            })
        elif confidence >= 50:
            breakdown.append({
                "reason": f"ML classification: {confidence:.0f}% phishing confidence (suspicious)",
                "points": SCORE_WEIGHTS.get("ml_phishing_medium", 6),
                "category": "ml",
            })

    # --- Threat Intel Feed Results ---
    if threat_intel_result:
        summary = threat_intel_result.get("summary", {})
        if summary.get("total_flagged", 0) > 0:
            feeds = ", ".join(summary.get("feeds_used", []))
            breakdown.append({
                "reason": f"Threat intel feeds: {summary['total_flagged']} IOC(s) flagged ({feeds})",
                "points": SCORE_WEIGHTS.get("threat_intel_url_malicious", 18),
                "category": "threat_intel",
            })

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
