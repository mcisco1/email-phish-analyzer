"""Multiple threat intelligence feed integration.

Queries external threat intel APIs to enrich analysis with:
- AbuseIPDB: IP reputation scoring
- URLhaus: Known malicious URL lookup
- PhishTank: Known phishing URL verification
- AlienVault OTX: IOC enrichment (IP, domain, URL)
- VirusTotal: URL reputation (alongside existing hash lookups)

All feeds are optional — each degrades gracefully if the API key
is missing or the service is unreachable. Rate limiting is applied
per-service to stay within free tier limits.
"""

import logging
import time
import threading
import hashlib
import base64
from urllib.parse import urlparse, quote

import requests

log = logging.getLogger(__name__)

# Thread-safe rate limiting per service
_rate_locks = {
    "abuseipdb": threading.Lock(),
    "urlhaus": threading.Lock(),
    "phishtank": threading.Lock(),
    "otx": threading.Lock(),
    "vt_url": threading.Lock(),
}
_rate_timestamps = {
    "abuseipdb": 0.0,
    "urlhaus": 0.0,
    "phishtank": 0.0,
    "otx": 0.0,
    "vt_url": 0.0,
}

# Minimum seconds between API calls per service
_RATE_DELAYS = {
    "abuseipdb": 2.0,   # 1000/day free = ~1.4s
    "urlhaus": 0.5,      # No official limit, be polite
    "phishtank": 1.0,    # Be polite
    "otx": 1.0,          # 10k/day = ~0.1s but be polite
    "vt_url": 15.0,      # 4/min free tier
}


def _rate_wait(service):
    """Thread-safe rate limiting for a service."""
    global _rate_timestamps
    with _rate_locks[service]:
        now = time.time()
        elapsed = now - _rate_timestamps[service]
        delay = _RATE_DELAYS.get(service, 1.0)
        if elapsed < delay:
            time.sleep(delay - elapsed)
        _rate_timestamps[service] = time.time()


# =========================================================================
# AbuseIPDB — IP Reputation
# =========================================================================

def check_abuseipdb(ip_address, api_key):
    """Query AbuseIPDB for IP reputation.

    Returns dict with:
        - abuse_confidence: int 0-100
        - country: str
        - isp: str
        - domain: str
        - total_reports: int
        - is_tor: bool
        - is_whitelisted: bool
        - error: str or None
    """
    if not api_key or not ip_address:
        return None

    _rate_wait("abuseipdb")

    try:
        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip_address, "maxAgeInDays": 90},
            headers={
                "Key": api_key,
                "Accept": "application/json",
            },
            timeout=10,
        )

        if resp.status_code == 200:
            data = resp.json().get("data", {})
            return {
                "source": "AbuseIPDB",
                "abuse_confidence": data.get("abuseConfidenceScore", 0),
                "country": data.get("countryCode", ""),
                "isp": data.get("isp", ""),
                "domain": data.get("domain", ""),
                "total_reports": data.get("totalReports", 0),
                "is_tor": data.get("isTor", False),
                "is_whitelisted": data.get("isWhitelisted", False),
                "error": None,
            }
        elif resp.status_code == 429:
            log.warning("AbuseIPDB rate limit hit")
            return {"source": "AbuseIPDB", "error": "rate_limited"}
        else:
            log.debug("AbuseIPDB returned %d for %s", resp.status_code, ip_address)
            return {"source": "AbuseIPDB", "error": f"http_{resp.status_code}"}

    except requests.exceptions.RequestException as e:
        log.warning("AbuseIPDB request failed: %s", e)
        return {"source": "AbuseIPDB", "error": str(e)[:100]}


# =========================================================================
# URLhaus — Malicious URL Database
# =========================================================================

def check_urlhaus(url):
    """Query URLhaus for known malicious URL.

    Returns dict with:
        - is_malicious: bool
        - threat_type: str (e.g., "malware_download")
        - status: str (e.g., "online", "offline")
        - tags: list of str
        - date_added: str
        - error: str or None
    """
    if not url:
        return None

    _rate_wait("urlhaus")

    try:
        resp = requests.post(
            "https://urlhaus-api.abuse.ch/v1/url/",
            data={"url": url},
            timeout=10,
        )

        if resp.status_code == 200:
            data = resp.json()
            if data.get("query_status") == "no_results":
                return {
                    "source": "URLhaus",
                    "is_malicious": False,
                    "error": None,
                }
            return {
                "source": "URLhaus",
                "is_malicious": True,
                "threat_type": data.get("threat", "unknown"),
                "status": data.get("url_status", "unknown"),
                "tags": data.get("tags", []) or [],
                "date_added": data.get("date_added", ""),
                "error": None,
            }
        else:
            return {"source": "URLhaus", "error": f"http_{resp.status_code}"}

    except requests.exceptions.RequestException as e:
        log.warning("URLhaus request failed: %s", e)
        return {"source": "URLhaus", "error": str(e)[:100]}


def check_urlhaus_domain(domain):
    """Query URLhaus for a known malicious domain/host."""
    if not domain:
        return None

    _rate_wait("urlhaus")

    try:
        resp = requests.post(
            "https://urlhaus-api.abuse.ch/v1/host/",
            data={"host": domain},
            timeout=10,
        )

        if resp.status_code == 200:
            data = resp.json()
            if data.get("query_status") == "no_results":
                return {
                    "source": "URLhaus",
                    "is_malicious": False,
                    "url_count": 0,
                    "error": None,
                }
            urls = data.get("urls", []) or []
            return {
                "source": "URLhaus",
                "is_malicious": len(urls) > 0,
                "url_count": data.get("urls_online", 0),
                "tags": list(set(
                    tag for u in urls[:10]
                    for tag in (u.get("tags", []) or [])
                )),
                "error": None,
            }
        else:
            return {"source": "URLhaus", "error": f"http_{resp.status_code}"}

    except requests.exceptions.RequestException as e:
        log.warning("URLhaus domain check failed: %s", e)
        return {"source": "URLhaus", "error": str(e)[:100]}


# =========================================================================
# PhishTank — Phishing URL Database
# =========================================================================

def check_phishtank(url, api_key=""):
    """Query PhishTank for known phishing URL.

    Returns dict with:
        - is_phishing: bool
        - verified: bool
        - verified_at: str
        - error: str or None
    """
    if not url:
        return None

    _rate_wait("phishtank")

    try:
        params = {
            "url": url,
            "format": "json",
        }
        if api_key:
            params["app_key"] = api_key

        resp = requests.post(
            "https://checkurl.phishtank.com/checkurl/",
            data=params,
            timeout=10,
        )

        if resp.status_code == 200:
            data = resp.json()
            results = data.get("results", {})
            return {
                "source": "PhishTank",
                "is_phishing": results.get("in_database", False),
                "verified": results.get("verified", False),
                "verified_at": results.get("verified_at", ""),
                "phish_id": results.get("phish_id", ""),
                "error": None,
            }
        elif resp.status_code == 509:
            log.warning("PhishTank rate limit hit")
            return {"source": "PhishTank", "error": "rate_limited"}
        else:
            return {"source": "PhishTank", "error": f"http_{resp.status_code}"}

    except requests.exceptions.RequestException as e:
        log.warning("PhishTank request failed: %s", e)
        return {"source": "PhishTank", "error": str(e)[:100]}


# =========================================================================
# AlienVault OTX — Open Threat Exchange
# =========================================================================

def check_otx_ip(ip_address, api_key):
    """Query AlienVault OTX for IP reputation."""
    if not api_key or not ip_address:
        return None

    _rate_wait("otx")

    try:
        resp = requests.get(
            f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip_address}/general",
            headers={"X-OTX-API-KEY": api_key},
            timeout=10,
        )

        if resp.status_code == 200:
            data = resp.json()
            pulses = data.get("pulse_info", {}).get("count", 0)
            return {
                "source": "AlienVault OTX",
                "pulse_count": pulses,
                "is_malicious": pulses > 0,
                "reputation": data.get("reputation", 0),
                "country": data.get("country_code", ""),
                "asn": data.get("asn", ""),
                "error": None,
            }
        else:
            return {"source": "AlienVault OTX", "error": f"http_{resp.status_code}"}

    except requests.exceptions.RequestException as e:
        log.warning("OTX IP check failed: %s", e)
        return {"source": "AlienVault OTX", "error": str(e)[:100]}


def check_otx_domain(domain, api_key):
    """Query AlienVault OTX for domain reputation."""
    if not api_key or not domain:
        return None

    _rate_wait("otx")

    try:
        resp = requests.get(
            f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general",
            headers={"X-OTX-API-KEY": api_key},
            timeout=10,
        )

        if resp.status_code == 200:
            data = resp.json()
            pulses = data.get("pulse_info", {}).get("count", 0)
            return {
                "source": "AlienVault OTX",
                "pulse_count": pulses,
                "is_malicious": pulses > 0,
                "alexa_rank": data.get("alexa", ""),
                "whois_info": data.get("whois", "")[:200] if data.get("whois") else "",
                "error": None,
            }
        else:
            return {"source": "AlienVault OTX", "error": f"http_{resp.status_code}"}

    except requests.exceptions.RequestException as e:
        log.warning("OTX domain check failed: %s", e)
        return {"source": "AlienVault OTX", "error": str(e)[:100]}


# =========================================================================
# VirusTotal — URL Reputation
# =========================================================================

def check_vt_url(url, api_key):
    """Query VirusTotal for URL reputation.

    Uses the URL scan lookup endpoint (not submission).
    Free tier: 4 requests/minute.

    Returns dict with:
        - malicious: int (engine detections)
        - total_engines: int
        - categories: dict
        - permalink: str
        - error: str or None
    """
    if not api_key or not url:
        return None

    _rate_wait("vt_url")

    # VT v3 uses URL ID = base64url(url) without padding
    url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")

    try:
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers={"x-apikey": api_key},
            timeout=15,
        )

        if resp.status_code == 200:
            data = resp.json()
            attrs = data.get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            categories = attrs.get("categories", {})
            malicious = stats.get("malicious", 0) + stats.get("suspicious", 0)
            total = sum(stats.values()) if stats else 0

            return {
                "source": "VirusTotal",
                "malicious": malicious,
                "total_engines": total,
                "categories": categories,
                "permalink": f"https://www.virustotal.com/gui/url/{url_id}",
                "final_url": attrs.get("last_final_url", ""),
                "title": attrs.get("title", ""),
                "error": None,
            }
        elif resp.status_code == 404:
            log.debug("VT URL not found: %s", url[:60])
            return {"source": "VirusTotal", "is_known": False, "error": None}
        elif resp.status_code == 429:
            log.warning("VT URL rate limit hit")
            return {"source": "VirusTotal", "error": "rate_limited"}
        else:
            return {"source": "VirusTotal", "error": f"http_{resp.status_code}"}

    except requests.exceptions.RequestException as e:
        log.warning("VT URL check failed: %s", e)
        return {"source": "VirusTotal", "error": str(e)[:100]}


# =========================================================================
# Aggregation — Run all applicable feeds for a set of IOCs
# =========================================================================

def enrich_iocs(ip_addresses=None, domains=None, urls=None, config=None):
    """Run all configured threat intel feeds against extracted IOCs.

    Args:
        ip_addresses: list of IP strings
        domains: list of domain strings
        urls: list of URL strings
        config: config module or object with API key attributes

    Returns dict with:
        - ip_results: {ip: [feed_results]}
        - domain_results: {domain: [feed_results]}
        - url_results: {url: [feed_results]}
        - summary: {total_checked, total_flagged, feeds_used}
    """
    results = {
        "ip_results": {},
        "domain_results": {},
        "url_results": {},
        "summary": {
            "total_checked": 0,
            "total_flagged": 0,
            "feeds_used": [],
        },
    }

    if config is None:
        return results

    abuseipdb_key = getattr(config, "ABUSEIPDB_API_KEY", "")
    otx_key = getattr(config, "OTX_API_KEY", "")
    phishtank_key = getattr(config, "PHISHTANK_API_KEY", "")
    vt_key = getattr(config, "VT_API_KEY", "")
    feeds_enabled = getattr(config, "THREAT_INTEL_ENABLED", False)

    if not feeds_enabled:
        return results

    feeds_used = set()
    failed_feeds = []

    # --- IP Enrichment ---
    for ip in (ip_addresses or [])[:20]:  # Cap to prevent abuse
        ip_feeds = []
        results["summary"]["total_checked"] += 1

        if abuseipdb_key:
            result = check_abuseipdb(ip, abuseipdb_key)
            if result and not result.get("error"):
                ip_feeds.append(result)
                feeds_used.add("AbuseIPDB")
                if result.get("abuse_confidence", 0) > 25:
                    results["summary"]["total_flagged"] += 1
            elif result and result.get("error"):
                failed_feeds.append({"feed": "AbuseIPDB", "error": result["error"]})

        if otx_key:
            result = check_otx_ip(ip, otx_key)
            if result and not result.get("error"):
                ip_feeds.append(result)
                feeds_used.add("AlienVault OTX")
                if result.get("is_malicious"):
                    results["summary"]["total_flagged"] += 1
            elif result and result.get("error"):
                failed_feeds.append({"feed": "AlienVault OTX", "error": result["error"]})

        if ip_feeds:
            results["ip_results"][ip] = ip_feeds

    # --- Domain Enrichment ---
    for domain in (domains or [])[:30]:
        domain_feeds = []
        results["summary"]["total_checked"] += 1

        urlhaus_result = check_urlhaus_domain(domain)
        if urlhaus_result and not urlhaus_result.get("error"):
            domain_feeds.append(urlhaus_result)
            feeds_used.add("URLhaus")
            if urlhaus_result.get("is_malicious"):
                results["summary"]["total_flagged"] += 1
        elif urlhaus_result and urlhaus_result.get("error"):
            failed_feeds.append({"feed": "URLhaus", "error": urlhaus_result["error"]})

        if otx_key:
            result = check_otx_domain(domain, otx_key)
            if result and not result.get("error"):
                domain_feeds.append(result)
                feeds_used.add("AlienVault OTX")
            elif result and result.get("error"):
                failed_feeds.append({"feed": "AlienVault OTX", "error": result["error"]})

        if domain_feeds:
            results["domain_results"][domain] = domain_feeds

    # --- URL Enrichment ---
    for url in (urls or [])[:15]:
        url_feeds = []
        results["summary"]["total_checked"] += 1

        urlhaus_result = check_urlhaus(url)
        if urlhaus_result and not urlhaus_result.get("error"):
            url_feeds.append(urlhaus_result)
            feeds_used.add("URLhaus")
            if urlhaus_result.get("is_malicious"):
                results["summary"]["total_flagged"] += 1
        elif urlhaus_result and urlhaus_result.get("error"):
            failed_feeds.append({"feed": "URLhaus", "error": urlhaus_result["error"]})

        phishtank_result = check_phishtank(url, phishtank_key)
        if phishtank_result and not phishtank_result.get("error"):
            url_feeds.append(phishtank_result)
            feeds_used.add("PhishTank")
            if phishtank_result.get("is_phishing"):
                results["summary"]["total_flagged"] += 1
        elif phishtank_result and phishtank_result.get("error"):
            failed_feeds.append({"feed": "PhishTank", "error": phishtank_result["error"]})

        if vt_key:
            vt_result = check_vt_url(url, vt_key)
            if vt_result and not vt_result.get("error"):
                url_feeds.append(vt_result)
                feeds_used.add("VirusTotal")
                if vt_result.get("malicious", 0) > 0:
                    results["summary"]["total_flagged"] += 1
            elif vt_result and vt_result.get("error"):
                failed_feeds.append({"feed": "VirusTotal", "error": vt_result["error"]})

        if url_feeds:
            results["url_results"][url] = url_feeds

    results["summary"]["feeds_used"] = sorted(feeds_used)
    # Deduplicate failed feeds (same feed may fail for multiple IOCs)
    seen = set()
    unique_failed = []
    for ff in failed_feeds:
        key = ff["feed"]
        if key not in seen:
            seen.add(key)
            unique_failed.append(ff)
    results["failed_feeds"] = unique_failed
    return results
