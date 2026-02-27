"""Shared pytest fixtures for PhishGuard tests."""

import os
import sys
import pytest

# Ensure project root is on path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

SAMPLES_DIR = os.path.join(os.path.dirname(__file__), "samples")


def _read_sample(name):
    with open(os.path.join(SAMPLES_DIR, name), "rb") as f:
        return f.read()


@pytest.fixture
def app():
    """Create a Flask test app with in-memory SQLite."""
    # Override config before importing app
    os.environ["DATABASE_URL"] = "sqlite://"
    os.environ["FLASK_ENV"] = "testing"
    os.environ["PHISH_SECRET"] = "test-secret-key-not-for-prod"

    import config
    config.SQLALCHEMY_DATABASE_URI = "sqlite://"
    config.S3_ENABLED = False
    config.SMTP_ENABLED = False
    config.IMAP_ENABLED = False
    config.BROWSER_DETONATION_ENABLED = False
    config.YARA_ENABLED = False
    config.VT_ENABLED = False
    config.THREAT_INTEL_ENABLED = False
    config.GOOGLE_ENABLED = False
    config.MICROSOFT_ENABLED = False
    config.RATELIMIT_STORAGE_URI = "memory://"

    from app import create_app
    test_app = create_app()
    test_app.config["TESTING"] = True
    test_app.config["WTF_CSRF_ENABLED"] = False
    test_app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite://"

    with test_app.app_context():
        from database import db
        db.create_all()
        yield test_app
        db.drop_all()


@pytest.fixture
def client(app):
    """Flask test client."""
    return app.test_client()


@pytest.fixture
def db_session(app):
    """Database session for direct DB operations."""
    from database import db
    with app.app_context():
        yield db.session


@pytest.fixture
def sample_eml():
    """Phishing sample .eml bytes."""
    return _read_sample("phishing_email.eml")


@pytest.fixture
def clean_eml():
    """Clean/legitimate sample .eml bytes."""
    return _read_sample("clean_email.eml")


@pytest.fixture
def malformed_eml():
    """Malformed .eml bytes with garbage data."""
    return _read_sample("malformed_email.eml")


@pytest.fixture
def no_urls_eml():
    """Email with no URLs."""
    return _read_sample("no_urls_email.eml")


@pytest.fixture
def unicode_eml():
    """Email with unicode characters."""
    return _read_sample("unicode_email.eml")


@pytest.fixture
def test_user(app):
    """Create and return a test user."""
    from database import db, User
    with app.app_context():
        user = User(
            email="testuser@example.com",
            username="testuser",
            role="analyst",
            is_active=True,
        )
        user.set_password("TestPass123!")
        db.session.add(user)
        db.session.commit()
        # Refresh to get the ID
        db.session.refresh(user)
        yield user


@pytest.fixture
def admin_user(app):
    """Return the auto-created admin user (or create one if missing)."""
    from database import db, User
    with app.app_context():
        user = User.query.filter_by(role="admin").first()
        if not user:
            user = User(
                email="admin@example.com",
                username="admin_test",
                role="admin",
                is_active=True,
            )
            user.set_password("AdminPass123!")
            db.session.add(user)
            db.session.commit()
        else:
            # Ensure we know the password for tests
            user.set_password("AdminPass123!")
            db.session.commit()
        db.session.refresh(user)
        yield user


@pytest.fixture
def auth_client(app, test_user):
    """Authenticated test client (analyst role)."""
    client = app.test_client()
    client.post("/login", data={
        "email": "testuser@example.com",
        "password": "TestPass123!",
    })
    return client


@pytest.fixture
def admin_client(app, admin_user):
    """Authenticated test client (admin role)."""
    client = app.test_client()
    client.post("/login", data={
        "email": admin_user.email,
        "password": "AdminPass123!",
    })
    return client


@pytest.fixture
def mock_report_dict():
    """A realistic report dict for testing."""
    return {
        "report_id": "abc123def456",
        "filename": "test_email.eml",
        "analyzed_at": "2025-01-15 10:30:00 UTC",
        "headers": {
            "from_address": "attacker@evil.com",
            "from_display": "Microsoft Support",
            "to_addresses": ["victim@company.com"],
            "subject": "Urgent: Verify Your Account",
            "spf_result": "fail",
            "dkim_result": "fail",
            "dmarc_result": "fail",
            "reply_to_mismatch": True,
            "display_name_spoofed": True,
            "anomalies": ["SPF failed", "DKIM failed"],
            "forged_headers": ["X-Mailer: PhpMailer"],
            "received_chain": [
                {"from": "mail.evil.com", "by": "mx.company.com", "timestamp": "2025-01-15T10:00:00Z"}
            ],
            "originating_ip": "185.220.101.34",
        },
        "body": {
            "text_content": "Please verify your account immediately or it will be suspended.",
            "html_content": "<p>Please <a href='http://evil.com/login'>verify</a> your account.</p>",
            "urgency_keywords_found": ["verify", "suspended", "immediately"],
        },
        "urls": [
            {
                "url": "http://evil.com/login",
                "domain": "evil.com",
                "risk_score": 35,
                "known_phishing": True,
                "is_shortened": False,
                "redirect_chain": [],
            }
        ],
        "attachments": [],
        "score": {
            "total": 78,
            "level": "critical",
            "level_color": "#ef4444",
            "level_label": "Critical — Highly Likely Phishing",
            "breakdown": [
                {"reason": "SPF failed", "points": 15, "category": "authentication"},
                {"reason": "DKIM failed", "points": 15, "category": "authentication"},
                {"reason": "Known phishing URL", "points": 20, "category": "url"},
                {"reason": "Display name spoofed", "points": 10, "category": "header"},
                {"reason": "Reply-to mismatch", "points": 8, "category": "header"},
                {"reason": "Urgency language", "points": 8, "category": "content"},
            ],
        },
        "iocs": {
            "ip_addresses": ["185.220.101.34"],
            "domains": ["evil.com"],
            "urls": ["http://evil.com/login"],
            "email_addresses": ["attacker@evil.com"],
            "hashes": [],
        },
        "mitre_mappings": [],
        "attack_summary": {},
        "whois": {},
    }
