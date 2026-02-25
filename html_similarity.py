"""HTML similarity analysis for brand impersonation detection.

Compares rendered phishing page structure and content against known
brand login page signatures (Google, Microsoft, Apple, banks) to
detect visual cloning and brand impersonation attacks that URL
analysis alone cannot catch.

Uses structural similarity (DOM element patterns, form fields, CSS
classes, page titles) rather than pixel comparison, so it works
without screenshots and runs fast.
"""

import logging
import re
from difflib import SequenceMatcher

log = logging.getLogger(__name__)

# Brand login page signatures — structural fingerprints
# Each brand has multiple signals: title patterns, form patterns,
# characteristic CSS/class names, and DOM structure markers.
BRAND_SIGNATURES = {
    "Google": {
        "titles": [
            "sign in", "google account", "gmail", "google sign-in",
            "google accounts", "google signin",
        ],
        "form_fields": ["identifier", "email", "password", "passwd"],
        "css_markers": [
            "gaia", "signin", "google-header", "g-recaptcha",
            "googleusercontent", "accounts.google",
        ],
        "dom_markers": [
            "data-g-id", "googlelogo", "google_favicon", "gstatic.com",
            "accounts.google.com", "g-recaptcha",
        ],
        "brand_terms": [
            "google", "gmail", "google drive", "google workspace",
            "g suite", "@gmail.com",
        ],
    },
    "Microsoft": {
        "titles": [
            "sign in", "microsoft account", "outlook", "office 365",
            "microsoft 365", "onedrive", "sharepoint",
        ],
        "form_fields": [
            "loginfmt", "passwd", "login", "emailInput",
            "passwordInput", "usernameInput",
        ],
        "css_markers": [
            "login-paginated", "microsoftLogo", "aad-logo",
            "office-brand", "ms-login", "microsoft",
        ],
        "dom_markers": [
            "login.microsoftonline.com", "login.live.com",
            "microsoft.com", "aadcdn.msftauth.net",
            "logincdn.msftauth.net", "office.com",
        ],
        "brand_terms": [
            "microsoft", "outlook", "office 365", "onedrive",
            "sharepoint", "teams", "@outlook.com", "@hotmail.com",
        ],
    },
    "Apple": {
        "titles": [
            "apple id", "sign in", "icloud", "apple account",
            "my apple id",
        ],
        "form_fields": [
            "account_name_text_field", "password_text_field",
            "appleId", "appleid",
        ],
        "css_markers": [
            "apple-id", "idms", "appleid-signin", "appleid",
            "icloud-ui",
        ],
        "dom_markers": [
            "appleid.apple.com", "icloud.com",
            "apple.com/favicon", "apple-logo",
        ],
        "brand_terms": [
            "apple", "icloud", "apple id", "itunes",
            "app store", "@icloud.com",
        ],
    },
    "PayPal": {
        "titles": [
            "paypal", "log in", "pay pal", "paypal login",
        ],
        "form_fields": [
            "email", "password", "login_email", "login_password",
            "phoneCode",
        ],
        "css_markers": [
            "paypal", "pp-header", "paypal-logo", "pp-",
        ],
        "dom_markers": [
            "paypal.com", "paypalobjects.com", "pp-logo",
        ],
        "brand_terms": [
            "paypal", "send money", "pay pal", "paypal inc",
        ],
    },
    "Amazon": {
        "titles": [
            "amazon", "sign in", "amazon sign-in", "amazon.com sign in",
        ],
        "form_fields": [
            "email", "password", "ap_email", "ap_password",
        ],
        "css_markers": [
            "a-button", "a-box", "amazon-logo", "a-spacing",
        ],
        "dom_markers": [
            "amazon.com", "images-amazon.com", "ssl-images-amazon",
        ],
        "brand_terms": [
            "amazon", "prime", "amazon.com", "aws",
        ],
    },
    "Netflix": {
        "titles": [
            "netflix", "sign in", "netflix login",
        ],
        "form_fields": [
            "userLoginId", "password", "email", "loginFormFields",
        ],
        "css_markers": [
            "login-body", "login-form", "nf-", "netflix-sans",
        ],
        "dom_markers": [
            "netflix.com", "nflxext.com", "nflximg.net",
        ],
        "brand_terms": [
            "netflix", "streaming", "watch now",
        ],
    },
    "Chase Bank": {
        "titles": [
            "chase", "sign in", "chase online", "jpmorgan chase",
        ],
        "form_fields": [
            "userId", "password", "logon", "userName",
        ],
        "css_markers": [
            "chase-logo", "secure-login", "chase-",
        ],
        "dom_markers": [
            "chase.com", "jpmorgan", "secure01b.chase.com",
        ],
        "brand_terms": [
            "chase", "jpmorgan", "chase bank",
        ],
    },
    "Wells Fargo": {
        "titles": [
            "wells fargo", "sign on", "wells fargo online",
        ],
        "form_fields": [
            "userid", "password", "j_username", "j_password",
        ],
        "css_markers": [
            "wf-", "wellsfargo", "stagecoach",
        ],
        "dom_markers": [
            "wellsfargo.com", "wf.com",
        ],
        "brand_terms": [
            "wells fargo", "wellsfargo",
        ],
    },
    "Bank of America": {
        "titles": [
            "bank of america", "sign in", "bofa",
        ],
        "form_fields": [
            "onlineId1", "passcode1", "userId",
        ],
        "css_markers": [
            "boa-", "bankofamerica", "bofa-",
        ],
        "dom_markers": [
            "bankofamerica.com", "bofa.com", "bac-assets",
        ],
        "brand_terms": [
            "bank of america", "bofa", "merrill",
        ],
    },
    "DHL": {
        "titles": [
            "dhl", "tracking", "dhl express", "shipment",
        ],
        "form_fields": ["email", "password"],
        "css_markers": ["dhl-", "dhl_logo"],
        "dom_markers": ["dhl.com", "dhl.de"],
        "brand_terms": ["dhl", "shipment", "tracking", "delivery"],
    },
    "FedEx": {
        "titles": [
            "fedex", "tracking", "fedex tracking",
        ],
        "form_fields": ["userId", "password"],
        "css_markers": ["fedex-", "fdx-"],
        "dom_markers": ["fedex.com"],
        "brand_terms": ["fedex", "federal express", "tracking"],
    },
    "Dropbox": {
        "titles": [
            "dropbox", "sign in", "dropbox login",
        ],
        "form_fields": ["login_email", "login_password", "email", "password"],
        "css_markers": ["dropbox-", "dbx-"],
        "dom_markers": ["dropbox.com", "dropboxstatic.com"],
        "brand_terms": ["dropbox", "shared file", "file sharing"],
    },
    "DocuSign": {
        "titles": [
            "docusign", "please review", "review document",
        ],
        "form_fields": ["email", "password"],
        "css_markers": ["docusign", "ds-"],
        "dom_markers": ["docusign.com", "docusign.net"],
        "brand_terms": ["docusign", "review document", "electronic signature"],
    },
    "LinkedIn": {
        "titles": [
            "linkedin", "sign in", "linkedin login",
        ],
        "form_fields": ["session_key", "session_password", "username"],
        "css_markers": ["linkedin-", "ember-", "artdeco-"],
        "dom_markers": ["linkedin.com", "licdn.com"],
        "brand_terms": ["linkedin", "professional network"],
    },
    "Facebook": {
        "titles": [
            "facebook", "log in", "log into facebook",
        ],
        "form_fields": ["email", "pass", "login", "m_login_email"],
        "css_markers": ["fb_logo", "facebook", "_5yd0", "fbconnect"],
        "dom_markers": ["facebook.com", "fbcdn.net", "fb.com"],
        "brand_terms": ["facebook", "meta", "fb"],
    },
}


def _normalize_html(html):
    """Lowercase and strip whitespace for comparison."""
    if not html:
        return ""
    return re.sub(r'\s+', ' ', html.lower().strip())


def _extract_page_signals(html):
    """Extract structural signals from HTML for comparison."""
    if not html:
        return {}

    norm = _normalize_html(html)

    # Title
    title_match = re.search(r'<title[^>]*>(.*?)</title>', norm, re.DOTALL)
    title = title_match.group(1).strip() if title_match else ""

    # Form fields (input names and ids)
    form_fields = re.findall(
        r'<input[^>]*(?:name|id)\s*=\s*["\']([^"\']+)["\']', norm
    )

    # CSS classes
    css_classes = re.findall(r'class\s*=\s*["\']([^"\']+)["\']', norm)
    all_classes = " ".join(css_classes)

    # Has password field
    has_password = bool(re.search(r'type\s*=\s*["\']password["\']', norm))

    # Has login form
    has_login_form = has_password and bool(
        re.search(r'<form', norm)
    )

    # Image sources
    img_srcs = re.findall(r'<img[^>]*src\s*=\s*["\']([^"\']+)["\']', norm)

    # Link hrefs
    hrefs = re.findall(r'href\s*=\s*["\']([^"\']+)["\']', norm)

    return {
        "title": title,
        "form_fields": [f.lower() for f in form_fields],
        "css_text": all_classes.lower(),
        "has_password": has_password,
        "has_login_form": has_login_form,
        "img_srcs": [s.lower() for s in img_srcs],
        "hrefs": [h.lower() for h in hrefs],
        "full_text": norm,
    }


def _score_brand_match(signals, brand_name, brand_sig):
    """Score how similar the page signals are to a brand signature.

    Returns a float 0-100 representing similarity confidence.
    """
    if not signals or not signals.get("full_text"):
        return 0.0

    score = 0.0
    max_score = 0.0

    # Title matching (weight: 25)
    max_score += 25
    title = signals.get("title", "")
    for brand_title in brand_sig["titles"]:
        if brand_title in title:
            score += 25
            break
    else:
        # Partial title match
        for brand_title in brand_sig["titles"]:
            ratio = SequenceMatcher(None, title, brand_title).ratio()
            if ratio > 0.6:
                score += 25 * ratio
                break

    # Form field matching (weight: 20)
    max_score += 20
    page_fields = set(signals.get("form_fields", []))
    brand_fields = set(f.lower() for f in brand_sig["form_fields"])
    if page_fields and brand_fields:
        overlap = len(page_fields & brand_fields)
        if overlap > 0:
            score += min(20, 10 * overlap)

    # CSS/class markers (weight: 15)
    max_score += 15
    css_text = signals.get("css_text", "")
    css_hits = sum(1 for m in brand_sig["css_markers"] if m.lower() in css_text)
    score += min(15, 5 * css_hits)

    # DOM markers in full HTML (weight: 20)
    max_score += 20
    full_text = signals.get("full_text", "")
    dom_hits = sum(1 for m in brand_sig["dom_markers"] if m.lower() in full_text)
    score += min(20, 7 * dom_hits)

    # Brand terms in page text (weight: 15)
    max_score += 15
    term_hits = sum(1 for t in brand_sig["brand_terms"] if t.lower() in full_text)
    score += min(15, 5 * term_hits)

    # Has login form bonus (weight: 5)
    max_score += 5
    if signals.get("has_login_form"):
        score += 5

    return min(round((score / max_score) * 100, 1), 100.0) if max_score > 0 else 0.0


def analyze_html_similarity(html_content, url_domain=""):
    """Analyze HTML content for brand impersonation.

    Args:
        html_content: Raw HTML string from the email body or fetched page
        url_domain: The domain of the URL being analyzed (for exclusion)

    Returns a dict with:
        - matches: list of {brand, similarity, signals_matched}
        - top_match: {brand, similarity} or None
        - is_impersonation: bool (True if similarity > 50% to any brand
          AND the domain is not the legitimate brand domain)
    """
    if not html_content:
        return {
            "matches": [],
            "top_match": None,
            "is_impersonation": False,
        }

    signals = _extract_page_signals(html_content)
    matches = []

    for brand_name, brand_sig in BRAND_SIGNATURES.items():
        similarity = _score_brand_match(signals, brand_name, brand_sig)

        if similarity >= 20:  # Minimum threshold to report
            # Check if the URL domain is actually the legitimate brand
            is_legit_domain = False
            if url_domain:
                for dom_marker in brand_sig["dom_markers"]:
                    if dom_marker in url_domain.lower():
                        is_legit_domain = True
                        break

            matched_signals = []
            title = signals.get("title", "")
            for bt in brand_sig["titles"]:
                if bt in title:
                    matched_signals.append(f"title: '{bt}'")
                    break
            full_text = signals.get("full_text", "")
            for dm in brand_sig["dom_markers"]:
                if dm.lower() in full_text:
                    matched_signals.append(f"dom: {dm}")
            for bt in brand_sig["brand_terms"][:3]:
                if bt.lower() in full_text:
                    matched_signals.append(f"term: {bt}")

            matches.append({
                "brand": brand_name,
                "similarity": similarity,
                "signals_matched": matched_signals[:5],
                "is_legitimate_domain": is_legit_domain,
            })

    matches.sort(key=lambda m: m["similarity"], reverse=True)

    top_match = matches[0] if matches else None
    is_impersonation = (
        top_match is not None
        and top_match["similarity"] >= 50
        and not top_match.get("is_legitimate_domain", False)
    )

    return {
        "matches": matches[:5],
        "top_match": {
            "brand": top_match["brand"],
            "similarity": top_match["similarity"],
        } if top_match else None,
        "is_impersonation": is_impersonation,
    }


def analyze_email_html(html_body, from_domain=""):
    """Analyze the email's HTML body for brand impersonation.

    This is called on the email's own HTML content, not fetched URLs.
    Returns a list of matched brand signals found in the email body.
    """
    if not html_body:
        return []

    results = analyze_html_similarity(html_body, url_domain=from_domain)
    return results.get("matches", [])
