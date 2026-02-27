# helpers.py — assorted utility functions
# this file grew organically over time... should probably split it up eventually

import re
import hashlib
import time
from datetime import datetime, timezone


def truncate(s, n=80):
    """Truncate string to n chars with ellipsis."""
    if not s or len(s) <= n:
        return s
    return s[:n - 1] + "…"


def safe_filename(name):
    # strip anything that's not alphanumeric, dash, underscore, or dot
    cleaned = re.sub(r'[^\w\-.]', '_', name)
    # collapse multiple underscores
    cleaned = re.sub(r'_+', '_', cleaned)
    return cleaned[:200]  # sane length limit


def hash_content(data, algo="sha256"):
    if isinstance(data, str):
        data = data.encode("utf-8")
    h = hashlib.new(algo)
    h.update(data)
    return h.hexdigest()


def fmt_timestamp(ts=None, fmt="%Y-%m-%d %H:%M:%S UTC"):
    """Format a unix timestamp or current time."""
    if ts is None:
        dt = datetime.now(timezone.utc)
    elif isinstance(ts, (int, float)):
        dt = datetime.fromtimestamp(ts, tz=timezone.utc)
    else:
        dt = ts
    return dt.strftime(fmt)

def time_ago(ts):
    # returns human-friendly relative time string
    diff = time.time() - ts
    if diff < 60:
        return "just now"
    mins = int(diff / 60)
    if mins < 60:
        return f"{mins}m ago"
    hrs = int(mins / 60)
    if hrs < 24:
        return f"{hrs}h ago"
    days = int(hrs / 24)
    if days < 30:
        return f"{days}d ago"
    return f"{int(days / 30)}mo ago"


def is_valid_email(addr):
    """Quick and dirty email validation. Not RFC-complete but good enough."""
    if not addr or not isinstance(addr, str):
        return False
    return bool(re.match(r'^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$', addr))


def extract_domain(email_or_url):
    """Pull the domain out of an email address or URL."""
    if '@' in email_or_url:
        return email_or_url.split('@')[-1].lower().strip()
    # try as URL
    import urllib.parse
    parsed = urllib.parse.urlparse(email_or_url)
    if parsed.hostname:
        return parsed.hostname.lower()
    return email_or_url.lower().strip()


def chunked(lst, n):
    for i in range(0, len(lst), n):
        yield lst[i:i + n]


# HACK: this is used in exactly one place (imap_poller) but it felt wrong
# to put it inline there, so here it lives
def parse_email_address(raw):
    """Extract email from 'Display Name <email@example.com>' format."""
    if not raw:
        return "", ""
    match = re.match(r'(.+?)\s*<(.+?)>', raw)
    if match:
        return match.group(1).strip().strip('"'), match.group(2).strip()
    if is_valid_email(raw.strip()):
        return "", raw.strip()
    return raw.strip(), ""


def clamp(val, lo, hi):
    return max(lo, min(hi, val))


# def normalize_url(url):
#     """was going to normalize URLs before comparison but url_analyzer
#     already handles this. keeping in case we need it later"""
#     from urllib.parse import urlparse, urlunparse
#     p = urlparse(url.lower().strip())
#     return urlunparse((p.scheme, p.netloc, p.path.rstrip('/'), '', '', ''))


def pluralize(word, count):
    if count == 1:
        return word
    return word + "s"


def env_bool(val, default=False):
    """Parse a boolean from env var string."""
    if val is None:
        return default
    return str(val).lower() in ("true", "1", "yes", "on")


def mask_email(addr):
    """Partially mask an email for display: j***@example.com"""
    if not addr or '@' not in addr:
        return addr
    local, domain = addr.split('@', 1)
    if len(local) <= 1:
        return f"*@{domain}"
    return f"{local[0]}{'*' * (len(local) - 1)}@{domain}"

print("[helpers] loaded")  # debug — should remove before release
