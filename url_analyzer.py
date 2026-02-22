import re
import logging
from urllib.parse import urlparse, unquote
import urllib3
import requests
from models import URLFinding
from config import (
    KNOWN_PHISH_DOMAINS, HOMOGLYPHS, LEGITIMATE_DOMAINS, SCORE_WEIGHTS,
    URL_DETONATION_TIMEOUT, URL_DETONATION_MAX_REDIRECTS,
    URL_DETONATION_USER_AGENT, MAX_URL_DETONATIONS,
)

# Suppress SSL warnings — intentional for phishing URL detonation (bad certs are expected)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

log = logging.getLogger(__name__)

SHORTENED_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "is.gd", "buff.ly", "adf.ly", "bl.ink", "rb.gy",
    "shorturl.at", "tiny.cc", "cutt.ly",
}

SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".buzz", ".click", ".gq", ".ml",
    ".cf", ".ga", ".tk", ".work", ".racing", ".loan",
    ".download", ".stream", ".win", ".bid", ".icu",
    ".rest", ".fit", ".surf", ".cam", ".quest", ".cyou",
    ".cfd", ".sbs", ".monster", ".hair", ".beauty",
}


def _normalize_defanged(text):
    """Restore defanged URLs: hxxp->http, [.]->.  so they can be extracted."""
    if not text:
        return text
    text = re.sub(r'hxxps?://', lambda m: m.group(0).lower().replace('hxxp', 'http'), text, flags=re.IGNORECASE)
    text = text.replace('[.]', '.').replace('[:]', ':')
    return text


def extract_urls(text_content, html_content):
    urls = set()
    # Normalize defanged notation (e.g. hxxp, [.]) before extraction
    if text_content:
        urls.update(re.findall(r'https?://[^\s<>"\']+', _normalize_defanged(text_content)))
    if html_content:
        norm_html = _normalize_defanged(html_content)
        urls.update(re.findall(r'href=["\']?(https?://[^"\'\s>]+)', norm_html, re.IGNORECASE))
        urls.update(re.findall(r'https?://[^\s<>"\']+', norm_html))
    cleaned = set()
    for u in urls:
        u = u.rstrip(".,;:)>]}")
        u = unquote(u)
        if len(u) > 10:
            cleaned.add(u)
    return list(cleaned)


def analyze_url(url):
    finding = URLFinding(url=url)

    try:
        parsed = urlparse(url)
        finding.domain = parsed.hostname or ""
        finding.uses_https = parsed.scheme == "https"
    except Exception:
        finding.threat_indicators.append("Malformed URL")
        finding.risk_score = 15
        return finding

    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', finding.domain):
        finding.is_ip_based = True
        finding.threat_indicators.append("URL uses raw IP address instead of domain")

    if finding.domain in SHORTENED_DOMAINS:
        finding.is_shortened = True
        finding.threat_indicators.append(f"Shortened URL ({finding.domain}) hides true destination")

    parts = finding.domain.split(".")
    if len(parts) > 2:
        finding.subdomain_count = len(parts) - 2
    if finding.subdomain_count > 1:
        finding.threat_indicators.append(f"Excessive subdomains ({finding.subdomain_count})")

    for tld in SUSPICIOUS_TLDS:
        if finding.domain.endswith(tld):
            finding.suspicious_tld = True
            finding.threat_indicators.append(f"Suspicious TLD: {tld}")
            break

    for phish_domain in KNOWN_PHISH_DOMAINS:
        if phish_domain in finding.domain:
            finding.known_phishing = True
            finding.threat_indicators.append(f"Known phishing domain: {phish_domain}")
            break

    _check_homoglyphs(finding)

    if not finding.uses_https:
        finding.threat_indicators.append("No HTTPS")

    # real detonation: follow redirects, capture chain, status, title
    _detonate_url(finding)

    # re-check phishing indicators on the final landing domain if it changed
    if finding.final_url and finding.final_url != finding.url:
        try:
            final_parsed = urlparse(finding.final_url)
            final_domain = final_parsed.hostname or ""
            if final_domain and final_domain != finding.domain:
                _check_final_domain(finding, final_domain)
        except Exception:
            pass

    finding.risk_score = _score_url(finding)
    return finding


def _detonate_url(finding):
    """Make a real HTTP request. Follow redirects. Capture the chain, final
    status code, page title, and server header."""
    try:
        session = requests.Session()
        session.max_redirects = URL_DETONATION_MAX_REDIRECTS
        resp = session.get(
            finding.url,
            allow_redirects=True,
            timeout=URL_DETONATION_TIMEOUT,
            headers={"User-Agent": URL_DETONATION_USER_AGENT},
            verify=False,
            stream=True,
        )

        # build redirect chain from response.history
        chain = []
        for hop in resp.history:
            chain.append({
                "url": hop.url,
                "status": hop.status_code,
            })
        chain.append({"url": resp.url, "status": resp.status_code})

        finding.redirect_chain = chain
        finding.status_code = resp.history[0].status_code if resp.history else resp.status_code
        finding.final_url = resp.url
        finding.final_status_code = resp.status_code
        finding.server = resp.headers.get("Server", "")
        finding.content_type = resp.headers.get("Content-Type", "")

        # read first 50KB to grab the title
        body_chunk = resp.raw.read(50000)
        resp.close()

        if body_chunk:
            text = body_chunk.decode("utf-8", errors="replace")
            title_match = re.search(r'<title[^>]*>([^<]+)</title>', text, re.IGNORECASE)
            if title_match:
                finding.page_title = title_match.group(1).strip()[:200]

        if len(chain) > 2:
            finding.threat_indicators.append(f"{len(chain)} redirects in chain")

        # flag if final domain differs from original
        try:
            orig_domain = urlparse(finding.url).hostname
            final_domain = urlparse(finding.final_url).hostname
            if orig_domain and final_domain and orig_domain != final_domain:
                finding.threat_indicators.append(
                    f"Redirect lands on different domain: {final_domain}"
                )
        except Exception:
            pass

    except requests.exceptions.TooManyRedirects:
        finding.detonation_error = "Too many redirects"
        finding.threat_indicators.append("Excessive redirects (possible redirect loop)")
    except requests.exceptions.SSLError:
        finding.detonation_error = "SSL certificate error"
        finding.threat_indicators.append("Invalid SSL certificate")
    except requests.exceptions.ConnectionError:
        finding.detonation_error = "Connection refused or host unreachable"
    except requests.exceptions.Timeout:
        finding.detonation_error = "Request timed out"
    except Exception as e:
        finding.detonation_error = str(e)[:200]
        log.warning("detonation failed for %s: %s", finding.url, e)


def _get_registrable_domain(domain):
    """Return the registrable domain (SLD.TLD) so subdomains don't defeat homoglyph checks."""
    parts = domain.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return domain


def _check_homoglyphs(finding):
    domain_lower = finding.domain.lower()
    # compare against the registrable domain (SLD.TLD) so login.micros0ft.com is caught
    reg_domain = _get_registrable_domain(domain_lower)
    # digit/character substitution check
    normalized = reg_domain.replace("0", "o").replace("1", "l").replace("5", "s")
    for legit in LEGITIMATE_DOMAINS:
        if normalized == legit and reg_domain != legit:
            finding.has_homoglyph = True
            finding.homoglyph_target = legit
            finding.threat_indicators.append(
                f"Character substitution impersonating {legit}"
            )
            return

    for legit in LEGITIMATE_DOMAINS:
        if reg_domain == legit:
            continue
        similarity = _homoglyph_similarity(reg_domain, legit)
        if similarity > 0.85 and reg_domain != legit:
            finding.has_homoglyph = True
            finding.homoglyph_target = legit
            finding.threat_indicators.append(
                f"Possible typosquatting of {legit} ({similarity:.0%} similar)"
            )
            return


def _check_final_domain(finding, final_domain):
    """Check the redirect landing domain for phishing indicators not visible on the original URL."""
    final_lower = final_domain.lower()

    for phish_domain in KNOWN_PHISH_DOMAINS:
        if phish_domain in final_lower:
            finding.known_phishing = True
            finding.threat_indicators.append(f"Redirect lands on known phishing domain: {phish_domain}")
            return

    for tld in SUSPICIOUS_TLDS:
        if final_lower.endswith(tld):
            finding.suspicious_tld = True
            finding.threat_indicators.append(f"Redirect lands on suspicious TLD: {tld}")
            break

    if not finding.has_homoglyph:
        reg_final = _get_registrable_domain(final_lower)
        normalized = reg_final.replace("0", "o").replace("1", "l").replace("5", "s")
        for legit in LEGITIMATE_DOMAINS:
            if normalized == legit and reg_final != legit:
                finding.has_homoglyph = True
                finding.homoglyph_target = legit
                finding.threat_indicators.append(
                    f"Redirect lands on character-substitution domain impersonating {legit}"
                )
                return
        for legit in LEGITIMATE_DOMAINS:
            if reg_final == legit:
                continue
            similarity = _homoglyph_similarity(reg_final, legit)
            if similarity > 0.85 and reg_final != legit:
                finding.has_homoglyph = True
                finding.homoglyph_target = legit
                finding.threat_indicators.append(
                    f"Redirect lands on typosquatting domain impersonating {legit} ({similarity:.0%} similar)"
                )
                return


def _homoglyph_similarity(domain, target):
    d_base = domain.rsplit(".", 1)[0] if "." in domain else domain
    t_base = target.rsplit(".", 1)[0] if "." in target else target
    if not d_base or not t_base or abs(len(d_base) - len(t_base)) > 2:
        return 0.0
    # pad shorter string for comparison
    max_len = max(len(d_base), len(t_base))
    d_padded = d_base.ljust(max_len)
    t_padded = t_base.ljust(max_len)
    matches = 0
    for dc, tc in zip(d_padded, t_padded):
        if dc == tc:
            matches += 1
        elif tc in HOMOGLYPHS and dc in HOMOGLYPHS[tc]:
            matches += 0.9
    return matches / max_len


def _score_url(finding):
    score = 0
    if finding.known_phishing:
        score += SCORE_WEIGHTS["known_phish_url"]
    if finding.is_ip_based:
        score += SCORE_WEIGHTS["url_ip_address"]
    if finding.has_homoglyph:
        score += SCORE_WEIGHTS["url_homoglyph"]
    if finding.subdomain_count > 1:
        score += SCORE_WEIGHTS["url_excessive_subdomains"]
    if len(finding.redirect_chain) > 2:
        score += SCORE_WEIGHTS["url_redirect_chain"]
    if finding.suspicious_tld:
        score += SCORE_WEIGHTS["suspicious_url"]
    if not finding.uses_https:
        score += 3
    if finding.is_shortened:
        score += SCORE_WEIGHTS.get("url_shortened", 10)
    if finding.final_status_code and finding.final_status_code >= 400:
        score += SCORE_WEIGHTS.get("url_bad_status", 5)
    return min(score, 50)


def analyze_all_urls(text_content, html_content):
    raw_urls = extract_urls(text_content, html_content)
    if len(raw_urls) > MAX_URL_DETONATIONS:
        log.warning("Capping URL analysis at %d (found %d)", MAX_URL_DETONATIONS, len(raw_urls))
    return [analyze_url(u) for u in raw_urls[:MAX_URL_DETONATIONS]]
