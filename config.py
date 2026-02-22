import os
import secrets

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE_PATH = os.path.join(BASE_DIR, "phishing.db")
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
MAX_FILE_SIZE = 25 * 1024 * 1024

# random key per process unless explicitly set in environment
SECRET_KEY = os.environ.get("PHISH_SECRET", secrets.token_hex(32))

# VirusTotal — free tier: 4 req/min, 500 req/day
VT_API_KEY = os.environ.get("VT_API_KEY", "")
VT_ENABLED = bool(VT_API_KEY)

# API authentication — set PHISH_API_KEY to require X-API-Key header on API routes
API_KEY = os.environ.get("PHISH_API_KEY", "")

# real URL detonation via requests
URL_DETONATION_TIMEOUT = 8
URL_DETONATION_MAX_REDIRECTS = 10
URL_DETONATION_USER_AGENT = "PhishGuard/1.0 (Security Scanner)"

SCORE_WEIGHTS = {
    "spf_fail": 15,
    "spf_softfail": 10,
    "spf_no_record": 5,
    "dkim_fail": 15,
    "dmarc_fail": 10,
    "header_forged": 12,
    "suspicious_url": 10,
    "known_phish_url": 20,
    "url_redirect_chain": 8,
    "url_ip_address": 8,
    "url_homoglyph": 12,
    "url_excessive_subdomains": 5,
    "url_bad_status": 6,
    "url_shortened": 10,
    "attachment_malware_hash": 25,
    "attachment_vt_hit": 20,
    "attachment_high_entropy": 8,
    "attachment_type_mismatch": 10,
    "attachment_macro_detected": 15,
    "attachment_executable": 12,
    "urgency_language": 8,
    "spoofed_display_name": 10,
    "reply_to_mismatch": 8,
    "known_threat_intel_ip": 15,
    "nxdomain_sender": 12,
    "long_received_chain": 8,
    "no_auth_all_none": 15,
    "missing_message_id": 5,
    "missing_date": 3,
    "no_received_headers": 10,
    "suspicious_x_mailer": 6,
    "declared_type_mismatch": 12,
}

MAX_URL_DETONATIONS = 25

THREAT_LEVELS = {
    "critical": {"min": 70, "color": "#ef4444", "label": "Critical — Highly Likely Phishing"},
    "high":     {"min": 50, "color": "#f97316", "label": "High — Strong Phishing Indicators"},
    "medium":   {"min": 30, "color": "#eab308", "label": "Medium — Suspicious Elements Detected"},
    "low":      {"min": 10, "color": "#22c55e", "label": "Low — Minor Anomalies"},
    "clean":    {"min": 0,  "color": "#10b981", "label": "Clean — No Threats Detected"},
}

KNOWN_MALWARE_HASHES = {
    "44d88612fea8a8f36de82e1278abb02f": {"name": "EICAR Test File", "family": "Test"},
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f": {"name": "EICAR SHA256", "family": "Test"},
    "e99a18c428cb38d5f260853678922e03": {"name": "Emotet Dropper", "family": "Emotet"},
    "d41d8cd98f00b204e9800998ecf8427e": {"name": "Empty File", "family": "Suspicious"},
    "7b3014eec70c7567c16e64e17b1d5b33": {"name": "TrickBot Loader", "family": "TrickBot"},
}

KNOWN_PHISH_DOMAINS = [
    "secure-login-verify.com", "account-verify-now.com", "paypa1-secure.com",
    "micros0ft-login.com", "g00gle-verify.com", "amaz0n-security.com",
    "app1e-id-verify.com", "netflix-billing-update.com", "wells-farg0-alert.com",
    "chase-secure-verify.com", "dropbox-share-file.com", "docusign-review-doc.com",
    "verify-account-now.com", "secure-update-center.com", "login-confirm-identity.com",
    "account-recovery-help.com", "security-alert-center.com", "update-billing-now.com",
    "urgent-action-required.com", "suspended-account-restore.com",
]

THREAT_INTEL_IPS = [
    "185.220.101.34", "45.155.205.233", "89.248.167.131",
    "171.25.193.78", "62.102.148.68", "194.26.29.120",
    "23.129.64.210", "185.56.80.65", "91.219.236.222",
    "198.98.56.149",
]

EXECUTABLE_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".com", ".pif", ".vbs",
    ".js", ".wsf", ".ps1", ".msi", ".dll", ".hta",
}

MACRO_EXTENSIONS = {".docm", ".xlsm", ".pptm", ".dotm", ".xltm"}

SUSPICIOUS_MAILERS = [
    "phpmailer", "swiftmailer", "king-phisher", "gophish",
    "cobalt strike", "sendinblue", "emkei", "anonymousemail",
    "guerrillamail", "mailgun", "mass mailer",
]

URGENCY_KEYWORDS = [
    "urgent", "immediate action", "verify your account", "suspended",
    "unauthorized", "click here immediately", "within 24 hours",
    "account will be closed", "confirm your identity", "security alert",
    "unusual activity", "password expired", "action required",
    "final warning", "your account has been compromised",
    "update your payment", "billing problem", "invoice attached",
    "wire transfer", "act now", "limited time",
    "verify now", "your account is at risk", "deactivate",
    "within 48 hours", "failure to respond", "validate your",
    "re-confirm", "click below", "won't be able to access",
    "expiring soon", "log in immediately", "unrecognized sign-in",
    "remaining balance", "overdue payment", "authorize this transaction",
]

HOMOGLYPHS = {
    "a": ["а", "ɑ", "α"],
    "e": ["е", "ё", "ε"],
    "o": ["о", "ο", "0"],
    "i": ["і", "ι", "1", "l"],
    "c": ["с", "ϲ"],
    "p": ["р", "ρ"],
    "s": ["ѕ", "ꜱ"],
}

LEGITIMATE_DOMAINS = [
    "google.com", "microsoft.com", "apple.com", "amazon.com", "paypal.com",
    "netflix.com", "facebook.com", "instagram.com", "twitter.com", "linkedin.com",
    "chase.com", "bankofamerica.com", "wellsfargo.com", "dropbox.com",
    "docusign.com", "fedex.com", "dhl.com", "ups.com", "usps.com",
]
