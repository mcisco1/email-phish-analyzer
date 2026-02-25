import hashlib
import math
import os
import logging
import time
import threading
from collections import Counter
import requests
from models import AttachmentFinding
from config import (
    KNOWN_MALWARE_HASHES, EXECUTABLE_EXTENSIONS, MACRO_EXTENSIONS,
    SCORE_WEIGHTS, VT_API_KEY, VT_ENABLED, YARA_ENABLED,
)

log = logging.getLogger(__name__)

MAGIC_BYTES = {
    b'\x50\x4b\x03\x04': "application/zip",
    b'\xd0\xcf\x11\xe0': "application/msoffice",
    b'\x25\x50\x44\x46': "application/pdf",
    b'\x7f\x45\x4c\x46': "application/x-elf",
    b'\x4d\x5a':         "application/x-dosexec",
    b'\x89\x50\x4e\x47': "image/png",
    b'\xff\xd8\xff':     "image/jpeg",
    b'\x47\x49\x46\x38': "image/gif",
    b'\x52\x61\x72\x21': "application/x-rar",
    b'\x1f\x8b':         "application/gzip",
    b'\x37\x7a\xbc\xaf': "application/x-7z-compressed",
}

_vt_lock = threading.Lock()
_vt_last_call = 0.0


def analyze_attachment(filename, content_type, data):
    finding = AttachmentFinding(
        filename=filename,
        content_type=content_type,
        size=len(data),
        declared_type=content_type,
    )

    finding.md5 = hashlib.md5(data).hexdigest()
    finding.sha1 = hashlib.sha1(data).hexdigest()
    finding.sha256 = hashlib.sha256(data).hexdigest()
    finding.entropy = _calculate_entropy(data)
    finding.actual_type = _detect_type(data)

    _check_extension_mismatch(finding)

    ext = os.path.splitext(filename)[1].lower() if filename else ""
    if ext in EXECUTABLE_EXTENSIONS:
        finding.is_executable = True
        finding.threat_indicators.append(f"Executable file type: {ext}")
    if ext in MACRO_EXTENSIONS:
        finding.has_macro = True
        finding.threat_indicators.append(f"Macro-enabled document: {ext}")
    # detect double extensions (e.g. report.pdf.exe)
    if filename and ext:
        stem = os.path.splitext(filename)[0]
        stem_ext = os.path.splitext(stem)[1].lower()
        if stem_ext and ext in EXECUTABLE_EXTENSIONS:
            finding.threat_indicators.append(f"Double extension attack: {filename}")
    if _has_vba_markers(data):
        finding.has_macro = True
        if not any("Macro" in t or "VBA" in t for t in finding.threat_indicators):
            finding.threat_indicators.append("VBA macro content detected")

    _check_malware_hashes(finding)

    # real VirusTotal lookup when an API key is configured
    if VT_ENABLED:
        _virustotal_lookup(finding)

    # YARA rule scanning
    if YARA_ENABLED:
        _yara_scan(finding, data)

    if finding.entropy > 7.5:
        finding.threat_indicators.append(f"High entropy ({finding.entropy:.2f}) — possibly packed or encrypted")

    finding.risk_score = _score_attachment(finding)
    return finding


def _virustotal_lookup(finding):
    """Query VirusTotal's file report endpoint by SHA-256.
    Free tier: 4 requests per minute. We rate-limit ourselves to stay under.
    Thread-safe via _vt_lock."""
    global _vt_last_call

    with _vt_lock:
        now = time.time()
        elapsed = now - _vt_last_call
        if elapsed < 15:
            time.sleep(15 - elapsed)

        url = f"https://www.virustotal.com/api/v3/files/{finding.sha256}"
        headers = {"x-apikey": VT_API_KEY}
        try:
            resp = requests.get(url, headers=headers, timeout=10)
            _vt_last_call = time.time()

            if resp.status_code == 200:
                data = resp.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                finding.vt_detections = stats.get("malicious", 0) + stats.get("suspicious", 0)
                finding.vt_total_engines = sum(stats.values())
                finding.vt_permalink = f"https://www.virustotal.com/gui/file/{finding.sha256}"
                if finding.vt_detections > 0:
                    finding.threat_indicators.append(
                        f"VirusTotal: {finding.vt_detections}/{finding.vt_total_engines} engines flagged"
                    )
            elif resp.status_code == 404:
                log.debug("VT: hash not found — %s", finding.sha256)
            elif resp.status_code == 429:
                log.warning("VT rate limit hit")
            else:
                log.warning("VT returned %d for %s", resp.status_code, finding.sha256)
        except requests.exceptions.RequestException as e:
            log.warning("VT request failed: %s", e)


def _calculate_entropy(data):
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 4)


def _detect_type(data):
    if not data or len(data) < 4:
        return "unknown"
    for magic, ftype in MAGIC_BYTES.items():
        if data[:len(magic)] == magic:
            return ftype
    try:
        head = data[:512].decode("utf-8", errors="strict")
        if head.strip().startswith("<?xml") or head.strip().startswith("<html"):
            return "text/html"
        if head.strip().startswith("{") or head.strip().startswith("["):
            return "application/json"
        return "text/plain"
    except (UnicodeDecodeError, ValueError):
        return "application/octet-stream"


def _check_extension_mismatch(finding):
    ext = os.path.splitext(finding.filename)[1].lower() if finding.filename else ""
    if not ext or finding.actual_type == "unknown":
        return
    ext_type_map = {
        ".pdf": "application/pdf", ".doc": "application/msoffice",
        ".docx": "application/zip", ".xls": "application/msoffice",
        ".xlsx": "application/zip", ".zip": "application/zip",
        ".rar": "application/x-rar", ".png": "image/png",
        ".jpg": "image/jpeg", ".jpeg": "image/jpeg",
        ".gif": "image/gif", ".exe": "application/x-dosexec",
    }
    expected = ext_type_map.get(ext)
    if expected and finding.actual_type != expected:
        if ext in (".docx", ".xlsx", ".pptx") and finding.actual_type == "application/zip":
            return
        finding.extension_mismatch = True
        finding.threat_indicators.append(
            f"Extension mismatch: {ext} should be {expected}, detected {finding.actual_type}"
        )


def _has_vba_markers(data):
    markers = (b"VBA", b"Auto_Open", b"AutoOpen", b"Sub ", b"ThisDocument")
    hits = sum(1 for sig in markers if sig in data)
    return hits >= 2


def _types_compatible(declared, actual):
    """Check if declared content-type and detected type are compatible (not suspicious)."""
    # Office documents are actually ZIP containers
    if "officedocument" in declared and actual == "application/zip":
        return True
    if declared in ("application/msword", "application/vnd.ms-excel", "application/vnd.ms-powerpoint"):
        if actual in ("application/msoffice", "application/zip"):
            return True
    # Generic octet-stream is often used as a catch-all
    if declared == "application/octet-stream":
        return True
    # Same type
    if declared == actual:
        return True
    # text/* vs text/*
    if declared.startswith("text/") and actual.startswith("text/"):
        return True
    return False


def _yara_scan(finding, data):
    """Run YARA rules against the attachment data."""
    try:
        from yara_scanner import scan_attachment
        matches = scan_attachment(finding.filename, data)
        finding.yara_matches = matches

        for match in matches:
            severity = match.get("severity", "medium")
            rule_name = match.get("rule", "unknown")
            description = match.get("description", "")
            category = match.get("category", "unknown")

            indicator = f"YARA: {rule_name}"
            if description:
                indicator += f" — {description}"
            indicator += f" [{severity}/{category}]"
            finding.threat_indicators.append(indicator)

    except ImportError:
        log.debug("yara_scanner module not available")
    except Exception as e:
        log.warning("YARA scan failed for %s: %s", finding.filename, e)


def _check_malware_hashes(finding):
    for h in (finding.md5, finding.sha1, finding.sha256):
        if h in KNOWN_MALWARE_HASHES:
            match = KNOWN_MALWARE_HASHES[h]
            finding.malware_match = match["name"]
            finding.malware_family = match["family"]
            finding.threat_indicators.append(
                f"Local hash match: {match['name']} ({match['family']})"
            )
            return


def _score_attachment(finding):
    """Delegates to score_attachment_breakdown — single source of truth."""
    return min(sum(pts for _, pts in score_attachment_breakdown(finding)), 50)


def analyze_all_attachments(attachments_raw):
    return [
        analyze_attachment(att["filename"], att["content_type"], att["data"])
        for att in attachments_raw
    ]


def score_attachment_breakdown(finding):
    """Returns list of (reason, points) tuples — single source of truth shared with threat_scorer."""
    items = []
    if finding.malware_match:
        items.append((f"Malware hash: {finding.malware_match}", SCORE_WEIGHTS["attachment_malware_hash"]))
    if finding.vt_detections > 0:
        items.append((f"VirusTotal: {finding.vt_detections}/{finding.vt_total_engines} detections", SCORE_WEIGHTS["attachment_vt_hit"]))
    if finding.is_executable:
        items.append((f"Executable: {finding.filename}", SCORE_WEIGHTS["attachment_executable"]))
    if finding.has_macro:
        items.append((f"Macro-enabled: {finding.filename}", SCORE_WEIGHTS["attachment_macro_detected"]))
    if finding.extension_mismatch:
        items.append((f"Type mismatch: {finding.filename}", SCORE_WEIGHTS["attachment_type_mismatch"]))
    if finding.entropy > 7.5:
        items.append((f"High entropy: {finding.filename} ({finding.entropy:.2f})", SCORE_WEIGHTS["attachment_high_entropy"]))
    if finding.declared_type and finding.actual_type and finding.actual_type != "unknown":
        declared = finding.declared_type.lower()
        actual = finding.actual_type.lower()
        if declared != actual and not _types_compatible(declared, actual):
            items.append((f"Content-Type mismatch: declared {declared}, actual {actual}", SCORE_WEIGHTS["declared_type_mismatch"]))
    # YARA rule matches — score by severity
    if hasattr(finding, "yara_matches") and finding.yara_matches:
        seen_severities = set()
        for match in finding.yara_matches:
            severity = match.get("severity", "medium")
            if severity not in seen_severities:
                seen_severities.add(severity)
                weight_key = f"yara_match_{severity}"
                points = SCORE_WEIGHTS.get(weight_key, SCORE_WEIGHTS.get("yara_match_medium", 10))
                items.append((
                    f"YARA rule: {match.get('rule', 'unknown')} [{severity}]",
                    points,
                ))
    return items
