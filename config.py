import os
import secrets
from datetime import timedelta

# ---------------------------------------------------------------------------
# Load .env file for local development (python-dotenv is optional)
# ---------------------------------------------------------------------------
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# ---------------------------------------------------------------------------
# Environment selector: "development", "staging", "production"
# ---------------------------------------------------------------------------
FLASK_ENV = os.environ.get("FLASK_ENV", "production")
IS_DEV = FLASK_ENV == "development"
IS_STAGING = FLASK_ENV == "staging"
IS_PROD = FLASK_ENV == "production"

# ---------------------------------------------------------------------------
# Core paths
# ---------------------------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")

# ---------------------------------------------------------------------------
# Flask
# ---------------------------------------------------------------------------
SECRET_KEY = os.environ.get("PHISH_SECRET", secrets.token_hex(32))
MAX_FILE_SIZE = int(os.environ.get("MAX_FILE_SIZE", 25 * 1024 * 1024))  # 25 MB
DEBUG = IS_DEV  # never True in production/staging

# ---------------------------------------------------------------------------
# Database — PostgreSQL in production, SQLite fallback in dev
# ---------------------------------------------------------------------------
_default_db = f"sqlite:///{os.path.join(BASE_DIR, 'phishing.db')}"
_env_db = os.environ.get("DATABASE_URL", "")
# Resolve relative sqlite paths to absolute
if _env_db.startswith("sqlite:///") and not os.path.isabs(_env_db[len("sqlite:///"):]):
    _env_db = f"sqlite:///{os.path.join(BASE_DIR, _env_db[len('sqlite:///'):])}"
DATABASE_URL = _env_db if _env_db else _default_db
# Legacy path for backwards compat with old database.py usage
DATABASE_PATH = os.path.join(BASE_DIR, "phishing.db")

# SQLAlchemy
SQLALCHEMY_DATABASE_URI = DATABASE_URL
SQLALCHEMY_TRACK_MODIFICATIONS = False
SQLALCHEMY_ENGINE_OPTIONS = {
    "pool_pre_ping": True,
}
if DATABASE_URL.startswith("postgresql"):
    SQLALCHEMY_ENGINE_OPTIONS.update({
        "pool_size": int(os.environ.get("DB_POOL_SIZE", 10)),
        "max_overflow": int(os.environ.get("DB_MAX_OVERFLOW", 20)),
        "pool_recycle": 300,
    })

# ---------------------------------------------------------------------------
# Redis
# ---------------------------------------------------------------------------
REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")

# ---------------------------------------------------------------------------
# Celery
# ---------------------------------------------------------------------------
CELERY_BROKER_URL = os.environ.get("CELERY_BROKER_URL", REDIS_URL)
CELERY_RESULT_BACKEND = os.environ.get("CELERY_RESULT_BACKEND", REDIS_URL)

# ---------------------------------------------------------------------------
# S3 / MinIO file storage
# ---------------------------------------------------------------------------
S3_ENDPOINT_URL = os.environ.get("S3_ENDPOINT_URL", "")  # e.g. http://minio:9000
S3_ACCESS_KEY = os.environ.get("S3_ACCESS_KEY", "")
S3_SECRET_KEY = os.environ.get("S3_SECRET_KEY", "")
S3_BUCKET = os.environ.get("S3_BUCKET", "phishguard-uploads")
S3_REGION = os.environ.get("S3_REGION", "us-east-1")
S3_ENABLED = bool(S3_ENDPOINT_URL and S3_ACCESS_KEY and S3_SECRET_KEY)

# ---------------------------------------------------------------------------
# OAuth 2.0 — Google
# ---------------------------------------------------------------------------
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET", "")
GOOGLE_ENABLED = bool(GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET)

# ---------------------------------------------------------------------------
# OAuth 2.0 — Microsoft
# ---------------------------------------------------------------------------
MICROSOFT_CLIENT_ID = os.environ.get("MICROSOFT_CLIENT_ID", "")
MICROSOFT_CLIENT_SECRET = os.environ.get("MICROSOFT_CLIENT_SECRET", "")
MICROSOFT_TENANT_ID = os.environ.get("MICROSOFT_TENANT_ID", "common")
MICROSOFT_ENABLED = bool(MICROSOFT_CLIENT_ID and MICROSOFT_CLIENT_SECRET)

# ---------------------------------------------------------------------------
# JWT tokens
# ---------------------------------------------------------------------------
JWT_SECRET_KEY = os.environ.get("JWT_SECRET_KEY", SECRET_KEY)
JWT_ACCESS_TOKEN_EXPIRES = timedelta(
    minutes=int(os.environ.get("JWT_ACCESS_MINUTES", 30))
)
JWT_REFRESH_TOKEN_EXPIRES = timedelta(
    days=int(os.environ.get("JWT_REFRESH_DAYS", 7))
)
JWT_ALGORITHM = "HS256"

# ---------------------------------------------------------------------------
# Session management
# ---------------------------------------------------------------------------
SESSION_TIMEOUT = timedelta(
    minutes=int(os.environ.get("SESSION_TIMEOUT_MINUTES", 60))
)
PERMANENT_SESSION_LIFETIME = SESSION_TIMEOUT

# Secure cookie flags
SESSION_COOKIE_SECURE = not IS_DEV  # HTTPS only in prod/staging
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Lax"
SESSION_COOKIE_NAME = "phishguard_session"

# ---------------------------------------------------------------------------
# VirusTotal
# ---------------------------------------------------------------------------
VT_API_KEY = os.environ.get("VT_API_KEY", "")
VT_ENABLED = bool(VT_API_KEY)

# ---------------------------------------------------------------------------
# Threat Intelligence Feeds
# ---------------------------------------------------------------------------
THREAT_INTEL_ENABLED = os.environ.get("THREAT_INTEL_ENABLED", "false").lower() in ("true", "1", "yes")
ABUSEIPDB_API_KEY = os.environ.get("ABUSEIPDB_API_KEY", "")
OTX_API_KEY = os.environ.get("OTX_API_KEY", "")
PHISHTANK_API_KEY = os.environ.get("PHISHTANK_API_KEY", "")

# ---------------------------------------------------------------------------
# ML Classifier
# ---------------------------------------------------------------------------
ML_CLASSIFIER_ENABLED = os.environ.get("ML_CLASSIFIER_ENABLED", "true").lower() in ("true", "1", "yes")

# ---------------------------------------------------------------------------
# NLP Analysis
# ---------------------------------------------------------------------------
NLP_ANALYSIS_ENABLED = os.environ.get("NLP_ANALYSIS_ENABLED", "true").lower() in ("true", "1", "yes")

# ---------------------------------------------------------------------------
# HTML Similarity Analysis
# ---------------------------------------------------------------------------
HTML_SIMILARITY_ENABLED = os.environ.get("HTML_SIMILARITY_ENABLED", "true").lower() in ("true", "1", "yes")

# ---------------------------------------------------------------------------
# Legacy API key auth (still supported alongside JWT)
# ---------------------------------------------------------------------------
API_KEY = os.environ.get("PHISH_API_KEY", "")

# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------
RATELIMIT_DEFAULT = os.environ.get("RATELIMIT_DEFAULT", "200 per hour")
RATELIMIT_API_ANALYZE = os.environ.get("RATELIMIT_API_ANALYZE", "30 per hour")
RATELIMIT_STORAGE_URI = REDIS_URL if not IS_DEV else "memory://"

# ---------------------------------------------------------------------------
# URL detonation (HTTP)
# ---------------------------------------------------------------------------
URL_DETONATION_TIMEOUT = int(os.environ.get("URL_DETONATION_TIMEOUT", 8))
URL_DETONATION_MAX_REDIRECTS = 10
URL_DETONATION_USER_AGENT = "PhishGuard/2.0 (Security Scanner)"
MAX_URL_DETONATIONS = 25

# ---------------------------------------------------------------------------
# Headless browser detonation (Playwright)
# ---------------------------------------------------------------------------
BROWSER_DETONATION_ENABLED = os.environ.get("BROWSER_DETONATION_ENABLED", "true").lower() in ("true", "1", "yes")
BROWSER_DETONATION_TIMEOUT = int(os.environ.get("BROWSER_DETONATION_TIMEOUT", 15000))  # ms
BROWSER_SCREENSHOT_DIR = os.path.join(BASE_DIR, "screenshots")
BROWSER_VIEWPORT_WIDTH = 1280
BROWSER_VIEWPORT_HEIGHT = 720
# Max URLs to detonate with the browser (expensive — subset of MAX_URL_DETONATIONS)
BROWSER_MAX_DETONATIONS = int(os.environ.get("BROWSER_MAX_DETONATIONS", 10))

# ---------------------------------------------------------------------------
# YARA rule scanning
# ---------------------------------------------------------------------------
YARA_ENABLED = os.environ.get("YARA_ENABLED", "true").lower() in ("true", "1", "yes")
YARA_RULES_DIR = os.path.join(BASE_DIR, "yara_rules")
YARA_SCAN_TIMEOUT = int(os.environ.get("YARA_SCAN_TIMEOUT", 30))  # seconds

# ---------------------------------------------------------------------------
# Scoring weights
# ---------------------------------------------------------------------------
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
    # Browser detonation findings
    "browser_js_redirect": 10,
    "browser_meta_refresh": 8,
    "browser_iframe_attack": 12,
    "browser_credential_form": 15,
    "browser_domain_mismatch": 10,
    # YARA rule matches
    "yara_match_critical": 20,
    "yara_match_high": 15,
    "yara_match_medium": 10,
    "yara_match_low": 5,
    # Recursive intermediate domain analysis
    "intermediate_domain_phishing": 12,
    "intermediate_domain_suspicious": 8,
    # IDN homograph attacks
    "idn_homograph": 15,
    # ML classifier
    "ml_phishing_high": 12,
    "ml_phishing_medium": 6,
    # NLP analysis
    "nlp_urgency_high": 10,
    "nlp_threat_high": 8,
    "nlp_social_engineering": 8,
    "nlp_impersonation": 6,
    # HTML similarity / brand impersonation
    "html_brand_impersonation": 15,
    "html_brand_suspicious": 8,
    # Threat intel feeds
    "threat_intel_url_malicious": 18,
    "threat_intel_ip_malicious": 15,
    "threat_intel_domain_malicious": 15,
}

# ---------------------------------------------------------------------------
# Threat levels
# ---------------------------------------------------------------------------
THREAT_LEVELS = {
    "critical": {"min": 70, "color": "#ef4444", "label": "Critical — Highly Likely Phishing"},
    "high":     {"min": 50, "color": "#f97316", "label": "High — Strong Phishing Indicators"},
    "medium":   {"min": 30, "color": "#eab308", "label": "Medium — Suspicious Elements Detected"},
    "low":      {"min": 10, "color": "#22c55e", "label": "Low — Minor Anomalies"},
    "clean":    {"min": 0,  "color": "#10b981", "label": "Clean — No Threats Detected"},
}

# ---------------------------------------------------------------------------
# Watchlists and threat intel
# ---------------------------------------------------------------------------
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
    "a": ["\u0430", "\u0251", "\u03b1"],
    "e": ["\u0435", "\u0451", "\u03b5"],
    "o": ["\u043e", "\u03bf", "0"],
    "i": ["\u0456", "\u03b9", "1", "l"],
    "c": ["\u0441", "\u03f2"],
    "p": ["\u0440", "\u03c1"],
    "s": ["\u0455", "\ua731"],
}

LEGITIMATE_DOMAINS = [
    "google.com", "microsoft.com", "apple.com", "amazon.com", "paypal.com",
    "netflix.com", "facebook.com", "instagram.com", "twitter.com", "linkedin.com",
    "chase.com", "bankofamerica.com", "wellsfargo.com", "dropbox.com",
    "docusign.com", "fedex.com", "dhl.com", "ups.com", "usps.com",
]

# ---------------------------------------------------------------------------
# Allowed .eml MIME signatures for upload validation
# ---------------------------------------------------------------------------
EML_MAX_SIZE = MAX_FILE_SIZE
ALLOWED_UPLOAD_EXTENSIONS = {".eml"}

# ---------------------------------------------------------------------------
# Email / SMTP notifications
# ---------------------------------------------------------------------------
SMTP_HOST = os.environ.get("SMTP_HOST", "")
SMTP_PORT = int(os.environ.get("SMTP_PORT", 587))
SMTP_USER = os.environ.get("SMTP_USER", "")
SMTP_PASS = os.environ.get("SMTP_PASS", "")
SMTP_FROM = os.environ.get("SMTP_FROM", "noreply@phishguard.local")
SMTP_USE_TLS = os.environ.get("SMTP_USE_TLS", "true").lower() in ("true", "1", "yes")
SMTP_ENABLED = bool(SMTP_HOST)

# ---------------------------------------------------------------------------
# Slack notifications
# ---------------------------------------------------------------------------
SLACK_DEFAULT_WEBHOOK = os.environ.get("SLACK_WEBHOOK_URL", "")

# ---------------------------------------------------------------------------
# IMAP Email Forwarding (analyze emails forwarded to a shared inbox)
# ---------------------------------------------------------------------------
IMAP_HOST = os.environ.get("IMAP_HOST", "")
IMAP_PORT = int(os.environ.get("IMAP_PORT", 993))
IMAP_USER = os.environ.get("IMAP_USER", "")
IMAP_PASS = os.environ.get("IMAP_PASS", "")
IMAP_FOLDER = os.environ.get("IMAP_FOLDER", "INBOX")
IMAP_USE_SSL = os.environ.get("IMAP_USE_SSL", "true").lower() in ("true", "1", "yes")
IMAP_POLL_INTERVAL = int(os.environ.get("IMAP_POLL_INTERVAL", 60))  # seconds
IMAP_ENABLED = bool(IMAP_HOST and IMAP_USER and IMAP_PASS)
IMAP_AUTO_REPLY = os.environ.get("IMAP_AUTO_REPLY", "true").lower() in ("true", "1", "yes")

# ---------------------------------------------------------------------------
# Application base URL (for links in notifications)
# ---------------------------------------------------------------------------
APP_BASE_URL = os.environ.get("APP_BASE_URL", "http://127.0.0.1:5000")

# ---------------------------------------------------------------------------
# PDF Report branding
# ---------------------------------------------------------------------------
REPORT_COMPANY_NAME = os.environ.get("REPORT_COMPANY_NAME", "PhishGuard")
REPORT_CONFIDENTIALITY = os.environ.get(
    "REPORT_CONFIDENTIALITY",
    "CONFIDENTIAL — This report contains sensitive security information. "
    "Distribution is restricted to authorized personnel only.",
)
REPORT_TLP_LEVEL = os.environ.get("REPORT_TLP_LEVEL", "TLP:AMBER")
REPORT_LOGO_PATH = os.environ.get("REPORT_LOGO_PATH", "")
