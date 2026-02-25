"""NLP-based email body analysis for phishing detection.

Analyzes email text for:
- Urgency and threat language patterns
- Impersonation patterns (claiming to be from a brand/authority)
- Grammatical anomalies common in phishing
- Social engineering manipulation techniques
- Suspicious call-to-action patterns

Uses pattern matching and statistical text analysis rather than
heavy NLP libraries, keeping the dependency footprint minimal.
"""

import logging
import re
from collections import Counter

log = logging.getLogger(__name__)

# --- Urgency patterns (weighted by severity) ---
URGENCY_PATTERNS = [
    # High urgency (3 points each)
    (r'\b(?:immediate(?:ly)?|right\s+now|at\s+once)\b', 3, "immediate action demand"),
    (r'\b(?:within\s+\d+\s+(?:hour|minute|day)s?)\b', 3, "time pressure with deadline"),
    (r'\b(?:account\s+(?:will\s+be|has\s+been)\s+(?:suspended|closed|locked|terminated|deactivated))\b', 3, "account termination threat"),
    (r'\b(?:unauthorized\s+(?:access|activity|transaction|login))\b', 3, "unauthorized activity claim"),
    (r'\b(?:your\s+account\s+(?:has\s+been|is)\s+compromised)\b', 3, "account compromise claim"),
    (r'\b(?:failure\s+to\s+(?:respond|verify|confirm|act)\s+will)\b', 3, "consequence threat"),
    # Medium urgency (2 points each)
    (r'\b(?:urgent(?:ly)?|critical|important\s+(?:notice|update|alert))\b', 2, "urgency language"),
    (r'\b(?:verify\s+your\s+(?:account|identity|information|email))\b', 2, "verification demand"),
    (r'\b(?:confirm\s+your\s+(?:identity|account|details|information))\b', 2, "confirmation demand"),
    (r'\b(?:security\s+(?:alert|notice|warning|update|issue))\b', 2, "security alert claim"),
    (r'\b(?:suspicious\s+(?:activity|login|transaction|sign-?in))\b', 2, "suspicious activity claim"),
    (r'\b(?:password\s+(?:expired?|reset|change)(?:d|s)?)\b', 2, "password action demand"),
    (r'\b(?:final\s+(?:warning|notice|reminder))\b', 2, "final warning language"),
    (r'\b(?:act\s+now|don\'?t\s+delay|time\s+is\s+running\s+out)\b', 2, "pressure language"),
    # Low urgency (1 point each)
    (r'\b(?:click\s+(?:here|below|the\s+(?:link|button)))\b', 1, "click instruction"),
    (r'\b(?:update\s+(?:your|the)\s+(?:payment|billing|information))\b', 1, "payment update request"),
    (r'\b(?:log\s*in\s+(?:immediately|now|here))\b', 1, "login demand"),
    (r'\b(?:won\'?t\s+be\s+able\s+to\s+access)\b', 1, "access loss threat"),
    (r'\b(?:limited\s+time|expir(?:ing|es?)\s+soon)\b', 1, "time limitation"),
]

# --- Threat language patterns ---
THREAT_PATTERNS = [
    (r'\b(?:legal\s+action|law\s+enforcement|prosecut(?:ed?|ion))\b', 3, "legal threat"),
    (r'\b(?:permanently?\s+(?:delete|remove|block|ban))\b', 2, "permanent consequence"),
    (r'\b(?:data\s+(?:breach|loss|leak))\b', 2, "data loss threat"),
    (r'\b(?:identity\s+(?:theft|stolen|fraud))\b', 2, "identity theft warning"),
    (r'\b(?:bank\s+(?:account|card)\s+(?:blocked|frozen|suspended))\b', 3, "financial threat"),
    (r'\b(?:report(?:ed)?\s+to\s+(?:police|authorities|fbi|irs))\b', 3, "authority threat"),
    (r'\b(?:criminal\s+(?:charges?|investigation|activity))\b', 3, "criminal threat"),
    (r'\b(?:arrest\s+warrant|court\s+order|subpoena)\b', 3, "legal document threat"),
]

# --- Impersonation patterns ---
IMPERSONATION_PATTERNS = [
    (r'\b(?:(?:customer|technical|account)\s+(?:service|support)\s+(?:team|department|center))\b', 2, "support team claim"),
    (r'\b(?:(?:security|fraud|compliance)\s+(?:team|department|center|division))\b', 2, "security department claim"),
    (r'\b(?:(?:ceo|cfo|cto|cio|director|manager|president)\s+(?:of|at)\b)', 2, "executive impersonation"),
    (r'\b(?:(?:on\s+behalf\s+of|representing|from\s+the\s+(?:office|desk)\s+of))\b', 1, "authority claim"),
    (r'\b(?:(?:dear\s+(?:valued|esteemed|loyal)\s+(?:customer|client|member|user)))\b', 1, "generic greeting"),
    (r'\b(?:(?:dear\s+(?:sir|madam|customer|user|account\s+holder)))\b', 1, "impersonal greeting"),
    (r'\b(?:this\s+is\s+(?:an?\s+)?(?:official|automated|system)\s+(?:message|notification|email))\b', 2, "official message claim"),
    (r'\b(?:(?:we\s+have\s+(?:detected|noticed|observed|identified)\s+(?:unusual|suspicious|unauthorized)))\b', 2, "detection claim"),
]

# --- Grammatical anomaly patterns ---
GRAMMAR_PATTERNS = [
    # Common ESL/machine translation errors in phishing
    (r'\b(?:kindly\s+(?:do|click|verify|confirm|update|revert|proceed))\b', 2, "formal 'kindly' usage (common in phishing)"),
    (r'\b(?:do\s+the\s+needful)\b', 2, "'do the needful' phrasing"),
    (r'\b(?:please\s+to\s+(?:be|do|click|verify))\b', 2, "grammatical error: 'please to'"),
    (r'\b(?:your\s+(?:good\s+)?self)\b', 1, "overly formal 'your self' phrasing"),
    (r'\b(?:revert\s+(?:back|us|me))\b', 1, "misuse of 'revert'"),
    (r'(?:!!+|\?\?+|!!!)', 1, "excessive punctuation"),
    (r'(?:[A-Z]{5,})', 1, "excessive capitalization"),
    (r'\b(?:dear\s+friend|dear\s+beloved)\b', 2, "suspicious greeting"),
    (r'\b(?:(?:i|we)\s+(?:am|are)\s+(?:writing|contacting|reaching)\s+(?:you\s+)?(?:to\s+)?(?:inform|notify|let\s+you\s+know))\b', 1, "formal notification phrasing"),
]

# --- Social engineering patterns ---
SOCIAL_ENGINEERING_PATTERNS = [
    (r'\b(?:(?:you\s+(?:have\s+)?(?:won|inherited|been\s+selected|been\s+chosen)))\b', 3, "prize/reward claim"),
    (r'\b(?:(?:million|thousand)\s+(?:dollar|usd|euro|pound|gbp)s?)\b', 3, "large sum mention"),
    (r'\b(?:(?:wire\s+transfer|money\s+transfer|western\s+union|bitcoin|cryptocurrency))\b', 2, "financial transfer request"),
    (r'\b(?:(?:gift\s+card|itunes\s+card|google\s+play\s+card|steam\s+card))\b', 3, "gift card request"),
    (r'\b(?:(?:do\s+not\s+(?:share|tell|discuss)\s+(?:this|with\s+anyone)))\b', 2, "secrecy demand"),
    (r'\b(?:(?:confidential|private|between\s+us|for\s+your\s+eyes\s+only))\b', 1, "confidentiality claim"),
    (r'\b(?:(?:refund|compensation|reward|bonus|prize)\s+(?:of|worth|amount))\b', 2, "financial incentive"),
]


def analyze_body(text_content, html_content="", subject=""):
    """Analyze email body text for phishing indicators using NLP patterns.

    Args:
        text_content: Plain text body of the email
        html_content: HTML body (stripped of tags for analysis)
        subject: Email subject line

    Returns a dict with:
        - urgency_score: int (0-100)
        - threat_score: int (0-100)
        - impersonation_score: int (0-100)
        - grammar_score: int (0-100) — higher = more anomalies
        - social_engineering_score: int (0-100)
        - overall_nlp_score: int (0-100) composite
        - findings: list of {pattern, category, severity, detail}
        - summary: human-readable summary
    """
    # Combine all text sources
    text = _prepare_text(text_content, html_content, subject)
    if not text or len(text) < 10:
        return _empty_result()

    findings = []

    # Run each pattern category
    urgency_pts = _scan_patterns(text, URGENCY_PATTERNS, "urgency", findings)
    threat_pts = _scan_patterns(text, THREAT_PATTERNS, "threat", findings)
    impersonation_pts = _scan_patterns(text, IMPERSONATION_PATTERNS, "impersonation", findings)
    grammar_pts = _scan_patterns(text, GRAMMAR_PATTERNS, "grammar", findings)
    social_pts = _scan_patterns(text, SOCIAL_ENGINEERING_PATTERNS, "social_engineering", findings)

    # Additional statistical analysis
    text_stats = _analyze_text_statistics(text)
    if text_stats:
        findings.extend(text_stats)
        grammar_pts += sum(1 for s in text_stats if s["category"] == "grammar")

    # Normalize scores to 0-100
    urgency_score = min(100, urgency_pts * 8)
    threat_score = min(100, threat_pts * 10)
    impersonation_score = min(100, impersonation_pts * 10)
    grammar_score = min(100, grammar_pts * 12)
    social_score = min(100, social_pts * 10)

    # Weighted composite
    overall = min(100, int(
        urgency_score * 0.25 +
        threat_score * 0.25 +
        impersonation_score * 0.20 +
        grammar_score * 0.10 +
        social_score * 0.20
    ))

    summary = _generate_summary(
        urgency_score, threat_score, impersonation_score,
        grammar_score, social_score, findings,
    )

    return {
        "urgency_score": urgency_score,
        "threat_score": threat_score,
        "impersonation_score": impersonation_score,
        "grammar_score": grammar_score,
        "social_engineering_score": social_score,
        "overall_nlp_score": overall,
        "findings": findings,
        "summary": summary,
    }


def _prepare_text(text_content, html_content, subject):
    """Combine and clean text for analysis."""
    parts = []
    if subject:
        parts.append(subject)
    if text_content:
        parts.append(text_content)
    if html_content:
        # Strip HTML tags for text analysis
        stripped = re.sub(r'<[^>]+>', ' ', html_content)
        stripped = re.sub(r'&[a-z]+;', ' ', stripped)
        stripped = re.sub(r'\s+', ' ', stripped).strip()
        if stripped and stripped != text_content:
            parts.append(stripped)
    return " ".join(parts)


def _scan_patterns(text, patterns, category, findings):
    """Scan text against a pattern list and accumulate findings."""
    total_pts = 0
    text_lower = text.lower()

    for pattern, weight, description in patterns:
        matches = re.findall(pattern, text_lower)
        if matches:
            total_pts += weight
            findings.append({
                "pattern": description,
                "category": category,
                "severity": "high" if weight >= 3 else "medium" if weight >= 2 else "low",
                "detail": f"Matched {len(matches)} time(s)",
                "match_count": len(matches),
            })

    return total_pts


def _analyze_text_statistics(text):
    """Statistical text analysis for phishing indicators."""
    findings = []

    if len(text) < 20:
        return findings

    words = text.split()
    if not words:
        return findings

    # Short email with links — typical phishing pattern
    if len(words) < 50 and re.search(r'https?://', text):
        findings.append({
            "pattern": "Short email with URL (common phishing pattern)",
            "category": "social_engineering",
            "severity": "low",
            "detail": f"{len(words)} words with embedded URL",
            "match_count": 1,
        })

    # Excessive capitalization ratio
    caps_words = [w for w in words if w.isupper() and len(w) > 2]
    if len(caps_words) > 3 and len(caps_words) / len(words) > 0.1:
        findings.append({
            "pattern": "Excessive use of ALL CAPS",
            "category": "grammar",
            "severity": "low",
            "detail": f"{len(caps_words)} all-caps words ({len(caps_words)/len(words)*100:.0f}%)",
            "match_count": len(caps_words),
        })

    # Exclamation and question mark abuse
    excl_count = text.count('!')
    if excl_count > 3:
        findings.append({
            "pattern": "Excessive exclamation marks",
            "category": "grammar",
            "severity": "low",
            "detail": f"{excl_count} exclamation marks",
            "match_count": excl_count,
        })

    # Mixed character sets (potential homograph or encoding tricks)
    non_ascii = sum(1 for c in text if ord(c) > 127)
    if non_ascii > 5 and non_ascii / len(text) > 0.02:
        findings.append({
            "pattern": "Non-ASCII characters detected (potential encoding tricks)",
            "category": "grammar",
            "severity": "medium",
            "detail": f"{non_ascii} non-ASCII characters",
            "match_count": non_ascii,
        })

    # Spelling errors approximation — repeated character patterns
    repeated = re.findall(r'(\w)\1{3,}', text.lower())
    if repeated:
        findings.append({
            "pattern": "Repeated character sequences (potential obfuscation)",
            "category": "grammar",
            "severity": "low",
            "detail": f"{len(repeated)} sequences",
            "match_count": len(repeated),
        })

    return findings


def _generate_summary(urgency, threat, impersonation, grammar, social, findings):
    """Generate a human-readable NLP analysis summary."""
    parts = []

    if urgency >= 50:
        parts.append("High urgency language detected")
    elif urgency >= 25:
        parts.append("Moderate urgency language")

    if threat >= 50:
        parts.append("threatening language patterns")
    elif threat >= 25:
        parts.append("some threat language")

    if impersonation >= 50:
        parts.append("strong impersonation indicators")
    elif impersonation >= 25:
        parts.append("possible impersonation")

    if grammar >= 50:
        parts.append("significant grammatical anomalies")
    elif grammar >= 25:
        parts.append("some grammatical issues")

    if social >= 50:
        parts.append("social engineering manipulation")
    elif social >= 25:
        parts.append("some social engineering patterns")

    if not parts:
        return "No significant NLP phishing indicators detected."

    return "NLP analysis: " + ", ".join(parts) + "."


def _empty_result():
    return {
        "urgency_score": 0,
        "threat_score": 0,
        "impersonation_score": 0,
        "grammar_score": 0,
        "social_engineering_score": 0,
        "overall_nlp_score": 0,
        "findings": [],
        "summary": "No email body text to analyze.",
    }
