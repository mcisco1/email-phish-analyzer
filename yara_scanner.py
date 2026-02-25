"""
YARA rule scanning engine for email attachments.

Compiles all .yar/.yara files from the yara_rules directory and scans
attachment binary data against them. Returns structured match results
with rule metadata (severity, category, description).
"""

import os
import logging
from config import YARA_ENABLED, YARA_RULES_DIR, YARA_SCAN_TIMEOUT

log = logging.getLogger(__name__)

# Lazy-initialized compiled rules
_compiled_rules = None
_yara_available = None


def _check_yara():
    """Check if yara-python is installed."""
    global _yara_available
    if _yara_available is not None:
        return _yara_available
    try:
        import yara  # noqa: F401
        _yara_available = True
    except ImportError:
        log.warning("yara-python not installed — YARA scanning disabled")
        _yara_available = False
    return _yara_available


def _load_rules():
    """Compile all YARA rules from the rules directory."""
    global _compiled_rules

    if _compiled_rules is not None:
        return _compiled_rules

    if not _check_yara():
        return None

    import yara

    if not os.path.isdir(YARA_RULES_DIR):
        log.warning("YARA rules directory not found: %s", YARA_RULES_DIR)
        return None

    # Collect all .yar and .yara files
    rule_files = {}
    for filename in sorted(os.listdir(YARA_RULES_DIR)):
        if filename.endswith((".yar", ".yara")):
            filepath = os.path.join(YARA_RULES_DIR, filename)
            namespace = os.path.splitext(filename)[0]
            rule_files[namespace] = filepath

    if not rule_files:
        log.warning("No YARA rule files found in %s", YARA_RULES_DIR)
        return None

    try:
        _compiled_rules = yara.compile(filepaths=rule_files)
        rule_count = sum(1 for _ in _compiled_rules)
        log.info("Compiled %d YARA rule files from %s", len(rule_files), YARA_RULES_DIR)
    except yara.SyntaxError as e:
        log.error("YARA rule syntax error: %s", e)
        return None
    except Exception as e:
        log.error("Failed to compile YARA rules: %s", e)
        return None

    return _compiled_rules


def scan_data(data, filename=""):
    """
    Scan binary data against all compiled YARA rules.

    Args:
        data: bytes — raw attachment content
        filename: str — original filename for logging

    Returns:
        list of dicts, each with:
            rule: str — rule identifier
            namespace: str — rule namespace (file it came from)
            description: str — from rule metadata
            severity: str — critical/high/medium/low
            category: str — phishing/macro/exploit/embedded/script/evasion
            tags: list[str] — YARA rule tags
            strings_matched: list[str] — identifiers of matched strings
    """
    if not YARA_ENABLED:
        return []

    rules = _load_rules()
    if rules is None:
        return []

    matches = []
    try:
        yara_matches = rules.match(data=data, timeout=YARA_SCAN_TIMEOUT)

        for match in yara_matches:
            meta = match.meta or {}

            # Extract matched string identifiers (without showing actual data for safety)
            matched_strings = []
            if hasattr(match, "strings"):
                for string_match in match.strings:
                    if hasattr(string_match, "identifier"):
                        ident = string_match.identifier
                    else:
                        # Older yara-python versions use tuple format
                        ident = string_match[1] if isinstance(string_match, tuple) else str(string_match)
                    if ident not in matched_strings:
                        matched_strings.append(ident)

            matches.append({
                "rule": match.rule,
                "namespace": match.namespace,
                "description": meta.get("description", ""),
                "severity": meta.get("severity", "medium"),
                "category": meta.get("category", "unknown"),
                "tags": list(match.tags) if match.tags else [],
                "strings_matched": matched_strings[:10],  # cap for report readability
            })

        if matches:
            log.info("YARA: %d rule(s) matched for %s: %s",
                     len(matches), filename,
                     ", ".join(m["rule"] for m in matches))

    except Exception as e:
        log.error("YARA scan error for %s: %s", filename, e)

    return matches


def scan_attachment(filename, data):
    """
    Convenience wrapper: scan an attachment and return results.
    Same interface as scan_data but with clearer naming.
    """
    return scan_data(data, filename=filename)


def get_rule_stats():
    """Return summary info about loaded YARA rules."""
    rules = _load_rules()
    if rules is None:
        return {"available": False, "rule_count": 0, "files": []}

    rule_files = []
    if os.path.isdir(YARA_RULES_DIR):
        rule_files = [
            f for f in sorted(os.listdir(YARA_RULES_DIR))
            if f.endswith((".yar", ".yara"))
        ]

    return {
        "available": True,
        "rule_count": sum(1 for _ in rules),
        "files": rule_files,
    }
