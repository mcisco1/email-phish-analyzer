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
    BROWSER_DETONATION_ENABLED,
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

# IDN homograph attack detection — maps Cyrillic/Greek/other look-alike
# characters to the Latin characters they impersonate
IDN_HOMOGRAPH_MAP = {
    # Cyrillic look-alikes
    '\u0430': 'a',  # Cyrillic а -> Latin a
    '\u0435': 'e',  # Cyrillic е -> Latin e
    '\u0456': 'i',  # Cyrillic і -> Latin i
    '\u043e': 'o',  # Cyrillic о -> Latin o
    '\u0440': 'p',  # Cyrillic р -> Latin p
    '\u0441': 'c',  # Cyrillic с -> Latin c
    '\u0443': 'y',  # Cyrillic у -> Latin y (visual)
    '\u0445': 'x',  # Cyrillic х -> Latin x
    '\u0455': 's',  # Cyrillic ѕ -> Latin s
    '\u04bb': 'h',  # Cyrillic һ -> Latin h
    '\u0501': 'd',  # Cyrillic ԁ -> Latin d
    '\u051b': 'q',  # Cyrillic ԛ -> Latin q
    '\u0261': 'g',  # Latin Small Letter Script G
    '\u0562': 'b',  # Armenian բ -> Latin b (visual)
    # Greek look-alikes
    '\u03b1': 'a',  # Greek α -> Latin a
    '\u03b5': 'e',  # Greek ε -> Latin e
    '\u03b9': 'i',  # Greek ι -> Latin i
    '\u03bf': 'o',  # Greek ο -> Latin o
    '\u03c1': 'p',  # Greek ρ -> Latin p
    '\u03c4': 't',  # Greek τ -> Latin t (visual)
    '\u03c5': 'u',  # Greek υ -> Latin u (visual)
    '\u03ba': 'k',  # Greek κ -> Latin k
    '\u03bd': 'v',  # Greek ν -> Latin v
    # Other confusable characters
    '\u0251': 'a',  # Latin Small Letter Alpha
    '\u0261': 'g',  # Latin Small Letter Script G
    '\u026f': 'm',  # turned m (visual in some fonts)
    '\ua731': 's',  # Latin Small Letter S with dot
    '\u03f2': 'c',  # Greek Lunate Sigma Symbol
    '\u0451': 'e',  # Cyrillic ё -> Latin e (visual without dots)
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

    # --- Recursive intermediate domain analysis ---
    _analyze_intermediate_domains(finding)

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


def _check_idn_homograph(finding):
    """Detect IDN homograph attacks using Cyrillic/Greek/other Unicode look-alikes.

    Catches attacks like аpple.com (Cyrillic 'а') vs apple.com (Latin 'a'),
    which look identical visually but resolve to different domains.
    """
    domain = finding.domain
    if not domain:
        return

    # Check if domain is an IDN (contains non-ASCII or starts with xn--)
    is_punycode = domain.startswith("xn--") or any(
        p.startswith("xn--") for p in domain.split(".")
    )
    has_non_ascii = any(ord(c) > 127 for c in domain)

    if not is_punycode and not has_non_ascii:
        return

    # Decode punycode to Unicode for analysis
    unicode_domain = domain
    if is_punycode:
        try:
            unicode_domain = domain.encode('ascii').decode('idna')
        except (UnicodeError, UnicodeDecodeError):
            try:
                # Try component-wise decoding
                parts = domain.split(".")
                decoded = []
                for part in parts:
                    if part.startswith("xn--"):
                        decoded.append(part.encode('ascii').decode('idna'))
                    else:
                        decoded.append(part)
                unicode_domain = ".".join(decoded)
            except Exception:
                return

    # Check for mixed scripts in the domain
    scripts_found = set()
    homograph_chars = []
    for char in unicode_domain:
        if char in ('.', '-'):
            continue
        cp = ord(char)
        if cp < 128:
            scripts_found.add("Latin")
        elif 0x0400 <= cp <= 0x04FF:
            scripts_found.add("Cyrillic")
            if char in IDN_HOMOGRAPH_MAP:
                homograph_chars.append((char, IDN_HOMOGRAPH_MAP[char]))
        elif 0x0370 <= cp <= 0x03FF:
            scripts_found.add("Greek")
            if char in IDN_HOMOGRAPH_MAP:
                homograph_chars.append((char, IDN_HOMOGRAPH_MAP[char]))
        elif 0x0530 <= cp <= 0x058F:
            scripts_found.add("Armenian")
        elif cp > 127:
            if char in IDN_HOMOGRAPH_MAP:
                homograph_chars.append((char, IDN_HOMOGRAPH_MAP[char]))
            scripts_found.add("Other")

    # Flag mixed-script domains (classic IDN homograph indicator)
    if len(scripts_found) > 1 and "Latin" in scripts_found:
        mixed_scripts = scripts_found - {"Latin"}
        finding.threat_indicators.append(
            f"IDN homograph: mixed scripts detected ({', '.join(sorted(scripts_found))})"
        )

    # Convert all homograph characters to Latin equivalents and check
    if homograph_chars:
        latin_version = unicode_domain
        for orig, replacement in IDN_HOMOGRAPH_MAP.items():
            latin_version = latin_version.replace(orig, replacement)

        reg_latin = _get_registrable_domain(latin_version.lower())
        for legit in LEGITIMATE_DOMAINS:
            if reg_latin == legit:
                finding.has_homoglyph = True
                finding.homoglyph_target = legit
                chars_detail = ", ".join(
                    f"'{orig}'(U+{ord(orig):04X})->'{repl}'"
                    for orig, repl in homograph_chars[:3]
                )
                finding.threat_indicators.append(
                    f"IDN homograph attack impersonating {legit}: "
                    f"uses look-alike characters [{chars_detail}]"
                )
                return

    # Purely non-Latin domain that looks like a legit domain
    if not scripts_found or scripts_found == {"Latin"}:
        return

    # Full Cyrillic/Greek domain that transliterates to a known brand
    if homograph_chars:
        latin_version = unicode_domain
        for orig, replacement in IDN_HOMOGRAPH_MAP.items():
            latin_version = latin_version.replace(orig, replacement)
        reg_latin = _get_registrable_domain(latin_version.lower())
        normalized = reg_latin.replace("0", "o").replace("1", "l").replace("5", "s")
        for legit in LEGITIMATE_DOMAINS:
            if normalized == legit and reg_latin != legit:
                finding.has_homoglyph = True
                finding.homoglyph_target = legit
                finding.threat_indicators.append(
                    f"IDN homograph attack: {unicode_domain} impersonates {legit} "
                    f"using {', '.join(sorted(scripts_found - {'Latin'}))} characters"
                )
                return


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

    # IDN homograph detection (Cyrillic/Greek Unicode attacks)
    _check_idn_homograph(finding)


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
    # Browser detonation findings
    if finding.js_redirects:
        score += SCORE_WEIGHTS.get("browser_js_redirect", 10)
    if finding.meta_refresh_detected:
        score += SCORE_WEIGHTS.get("browser_meta_refresh", 8)
    if finding.iframes_detected:
        external_iframes = [
            iframe for iframe in finding.iframes_detected
            if isinstance(iframe, dict) and iframe.get("domain") and iframe["domain"] != finding.domain
        ]
        if external_iframes:
            score += SCORE_WEIGHTS.get("browser_iframe_attack", 12)
    if finding.has_credential_form:
        score += SCORE_WEIGHTS.get("browser_credential_form", 15)
    if finding.browser_final_url and finding.final_url:
        try:
            http_final = urlparse(finding.final_url).hostname or ""
            browser_final = urlparse(finding.browser_final_url).hostname or ""
            if http_final and browser_final and http_final != browser_final:
                score += SCORE_WEIGHTS.get("browser_domain_mismatch", 10)
        except Exception:
            pass
    # Intermediate domain findings
    for idom in finding.intermediate_domains:
        if isinstance(idom, dict) and idom.get("indicators"):
            for ind in idom["indicators"]:
                if "phishing" in ind.lower():
                    score += SCORE_WEIGHTS.get("intermediate_domain_phishing", 12)
                    break
                elif "suspicious" in ind.lower() or "typosquatting" in ind.lower():
                    score += SCORE_WEIGHTS.get("intermediate_domain_suspicious", 8)
                    break
    return min(score, 50)


def _analyze_intermediate_domains(finding):
    """Analyze every intermediate domain in the redirect chain.

    For each hop in the chain, extract the domain and check it against
    phishing domain lists, suspicious TLDs, and homoglyph detection.
    This catches multi-stage phishing where intermediate redirectors are
    themselves suspicious or compromised.
    """
    if len(finding.redirect_chain) < 2:
        return

    seen_domains = {finding.domain}
    if finding.final_url:
        try:
            seen_domains.add(urlparse(finding.final_url).hostname or "")
        except Exception:
            pass

    for hop in finding.redirect_chain:
        hop_url = hop.get("url", "") if isinstance(hop, dict) else str(hop)
        if not hop_url:
            continue
        try:
            hop_domain = urlparse(hop_url).hostname or ""
        except Exception:
            continue

        if not hop_domain or hop_domain in seen_domains:
            continue
        seen_domains.add(hop_domain)

        domain_info = {
            "domain": hop_domain,
            "url": hop_url[:200],
            "indicators": [],
        }

        # Check against known phishing domains
        for phish_domain in KNOWN_PHISH_DOMAINS:
            if phish_domain in hop_domain:
                domain_info["indicators"].append(f"Known phishing domain: {phish_domain}")
                finding.threat_indicators.append(
                    f"Intermediate hop via known phishing domain: {hop_domain}"
                )
                break

        # Check suspicious TLDs
        for tld in SUSPICIOUS_TLDS:
            if hop_domain.endswith(tld):
                domain_info["indicators"].append(f"Suspicious TLD: {tld}")
                finding.threat_indicators.append(
                    f"Intermediate hop via suspicious TLD domain: {hop_domain}"
                )
                break

        # Check for IP-based intermediate URLs
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', hop_domain):
            domain_info["indicators"].append("IP-based URL")
            finding.threat_indicators.append(
                f"Intermediate hop uses raw IP: {hop_domain}"
            )

        # Homoglyph / typosquatting check on intermediate domain
        reg_domain = _get_registrable_domain(hop_domain.lower())
        normalized = reg_domain.replace("0", "o").replace("1", "l").replace("5", "s")
        for legit in LEGITIMATE_DOMAINS:
            if normalized == legit and reg_domain != legit:
                domain_info["indicators"].append(f"Typosquatting of {legit}")
                finding.threat_indicators.append(
                    f"Intermediate hop impersonates {legit}: {hop_domain}"
                )
                break

        finding.intermediate_domains.append(domain_info)


def _enrich_with_browser(findings):
    """Run headless browser detonation on URL findings and merge results."""
    if not BROWSER_DETONATION_ENABLED:
        return

    try:
        from browser_detonator import detonate_urls_browser
    except ImportError:
        log.debug("browser_detonator module not available")
        return

    # Collect URLs that should be browser-detonated (skip IP-only or error URLs)
    urls_to_detonate = []
    for f in findings:
        if f.detonation_error and "refused" in f.detonation_error.lower():
            continue  # host unreachable, skip browser too
        urls_to_detonate.append(f.url)

    if not urls_to_detonate:
        return

    browser_results = detonate_urls_browser(urls_to_detonate)

    # Merge browser results back into findings
    for f in findings:
        br = browser_results.get(f.url)
        if not br:
            continue

        f.screenshot_path = br.get("screenshot_path", "")
        f.browser_final_url = br.get("browser_final_url", "")
        f.browser_page_title = br.get("browser_page_title", "")
        f.browser_error = br.get("browser_error", "")
        f.js_redirects = br.get("js_redirects", [])
        f.meta_refresh_detected = br.get("meta_refresh_detected", False)
        f.meta_refresh_url = br.get("meta_refresh_url", "")
        f.iframes_detected = br.get("iframes_detected", [])
        f.has_credential_form = br.get("has_credential_form", False)

        # Add threat indicators from browser findings
        if f.js_redirects:
            redirect_domains = [r.get("url", "")[:60] for r in f.js_redirects[:3]]
            f.threat_indicators.append(
                f"JavaScript redirect detected ({len(f.js_redirects)} hop(s)): "
                + ", ".join(redirect_domains)
            )

        if f.meta_refresh_detected:
            indicator = "Meta refresh tag detected"
            if f.meta_refresh_url:
                indicator += f" → {f.meta_refresh_url[:80]}"
            f.threat_indicators.append(indicator)

        if f.iframes_detected:
            external_iframes = [
                iframe for iframe in f.iframes_detected
                if iframe.get("domain") and iframe["domain"] != f.domain
            ]
            if external_iframes:
                f.threat_indicators.append(
                    f"{len(external_iframes)} external iframe(s) detected: "
                    + ", ".join(iframe["domain"] for iframe in external_iframes[:3])
                )

        if f.has_credential_form:
            f.threat_indicators.append(
                "Credential harvesting form detected (password input field)"
            )

        # Check if browser landed on a different domain than HTTP detonation
        if f.browser_final_url and f.final_url:
            try:
                http_final = urlparse(f.final_url).hostname or ""
                browser_final = urlparse(f.browser_final_url).hostname or ""
                if http_final and browser_final and http_final != browser_final:
                    f.threat_indicators.append(
                        f"Browser JS execution changed destination: {http_final} → {browser_final}"
                    )
            except Exception:
                pass

        # Re-score after browser enrichment
        f.risk_score = _score_url(f)


def analyze_all_urls(text_content, html_content):
    raw_urls = extract_urls(text_content, html_content)
    if len(raw_urls) > MAX_URL_DETONATIONS:
        log.warning("Capping URL analysis at %d (found %d)", MAX_URL_DETONATIONS, len(raw_urls))
    findings = [analyze_url(u) for u in raw_urls[:MAX_URL_DETONATIONS]]

    # Run headless browser detonation on all findings
    try:
        _enrich_with_browser(findings)
    except Exception:
        log.exception("Browser detonation enrichment failed — continuing without it")

    return findings
