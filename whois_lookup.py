"""WHOIS domain intelligence enrichment.

Performs WHOIS lookups on domains extracted from phishing emails to surface:
- Domain age (newly registered domains are a strong phishing indicator)
- Registrar information
- Creation and expiration dates
- Domain status flags

Domain age < 30 days is a high-confidence phishing signal used by
enterprise email gateways like Proofpoint, Mimecast, and Microsoft Defender.
"""

import logging
from datetime import datetime, timezone

log = logging.getLogger(__name__)

# Minimum age in days before a domain is considered suspicious
SUSPICIOUS_AGE_DAYS = 30


def lookup_domain(domain):
    """Perform a WHOIS lookup on a domain.

    Returns a dict with domain intelligence or an error message.
    """
    if not domain or _is_ip(domain):
        return None

    # Strip subdomains — WHOIS operates on the registrable domain
    registrable = _get_registrable(domain)
    if not registrable:
        return None

    try:
        import whois
        w = whois.whois(registrable)
    except ImportError:
        log.debug("python-whois not installed — skipping WHOIS lookup")
        return None
    except Exception as e:
        log.debug("WHOIS lookup failed for %s: %s", registrable, e)
        return {"domain": registrable, "error": str(e)[:200]}

    result = {
        "domain": registrable,
        "registrar": _safe_str(w.registrar),
        "creation_date": _format_date(w.creation_date),
        "expiration_date": _format_date(w.expiration_date),
        "updated_date": _format_date(w.updated_date),
        "name_servers": _safe_list(w.name_servers),
        "status": _safe_list(w.status),
        "country": _safe_str(getattr(w, "country", None)),
        "org": _safe_str(getattr(w, "org", None)),
    }

    # Calculate domain age
    creation = _parse_date(w.creation_date)
    if creation:
        age_days = (datetime.now(timezone.utc) - creation).days
        result["age_days"] = age_days
        result["is_new"] = age_days < SUSPICIOUS_AGE_DAYS
        if result["is_new"]:
            result["warning"] = f"Domain registered only {age_days} days ago"
    else:
        result["age_days"] = None
        result["is_new"] = False

    return result


def enrich_url_findings(url_findings):
    """Enrich a list of URLFinding objects with WHOIS data.

    Deduplicates by registrable domain to avoid redundant lookups.
    Returns a dict mapping domain -> whois_result.
    """
    seen = set()
    results = {}

    for uf in url_findings:
        domain = uf.domain if hasattr(uf, "domain") else uf.get("domain", "")
        if not domain:
            continue
        registrable = _get_registrable(domain)
        if registrable in seen:
            continue
        seen.add(registrable)

        info = lookup_domain(registrable)
        if info:
            results[registrable] = info

    return results


def _is_ip(domain):
    parts = domain.split(".")
    if len(parts) == 4:
        try:
            return all(0 <= int(p) <= 255 for p in parts)
        except ValueError:
            pass
    return False


def _get_registrable(domain):
    """Extract the registrable domain (SLD.TLD)."""
    parts = domain.strip(".").split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:]).lower()
    return domain.lower()


def _safe_str(val):
    if val is None:
        return ""
    if isinstance(val, list):
        return str(val[0]) if val else ""
    return str(val)


def _safe_list(val):
    if val is None:
        return []
    if isinstance(val, str):
        return [val]
    return [str(v) for v in val]


def _format_date(val):
    if val is None:
        return ""
    if isinstance(val, list):
        val = val[0] if val else None
    if val is None:
        return ""
    if isinstance(val, datetime):
        return val.strftime("%Y-%m-%d")
    return str(val)


def _parse_date(val):
    if val is None:
        return None
    if isinstance(val, list):
        val = val[0] if val else None
    if val is None:
        return None
    if isinstance(val, datetime):
        if val.tzinfo is None:
            return val.replace(tzinfo=timezone.utc)
        return val
    return None
