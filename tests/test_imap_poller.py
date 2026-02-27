"""Tests for imap_poller.py — IMAP inbox polling for forwarded emails."""

import email
import pytest
from unittest.mock import patch, MagicMock, PropertyMock

from imap_poller import (
    poll_inbox, extract_forwarded_email,
    attribute_to_user, send_analysis_reply,
    test_connection as imap_test_connection,
)


class TestPollInbox:
    @patch("imap_poller.config")
    def test_disabled(self, mock_config):
        mock_config.IMAP_ENABLED = False
        app = MagicMock()
        result = poll_inbox(app)
        assert result["status"] == "disabled"
        assert result["emails_found"] == 0

    @patch("imap_poller._log_poll")
    @patch("imap_poller._process_message")
    @patch("imap_poller.imaplib.IMAP4_SSL")
    @patch("imap_poller.config")
    def test_no_messages(self, mock_config, mock_imap_cls, mock_process, mock_log):
        mock_config.IMAP_ENABLED = True
        mock_config.IMAP_USE_SSL = True
        mock_config.IMAP_HOST = "imap.example.com"
        mock_config.IMAP_PORT = 993
        mock_config.IMAP_USER = "user"
        mock_config.IMAP_PASS = "pass"
        mock_config.IMAP_FOLDER = "INBOX"

        mock_conn = MagicMock()
        mock_imap_cls.return_value = mock_conn
        mock_conn.search.return_value = ("OK", [b""])

        app = MagicMock()
        result = poll_inbox(app)
        assert result["emails_found"] == 0
        mock_process.assert_not_called()

    @patch("imap_poller._log_poll")
    @patch("imap_poller._process_message")
    @patch("imap_poller.imaplib.IMAP4_SSL")
    @patch("imap_poller.config")
    def test_processes_messages(self, mock_config, mock_imap_cls, mock_process, mock_log):
        mock_config.IMAP_ENABLED = True
        mock_config.IMAP_USE_SSL = True
        mock_config.IMAP_HOST = "imap.example.com"
        mock_config.IMAP_PORT = 993
        mock_config.IMAP_USER = "user"
        mock_config.IMAP_PASS = "pass"
        mock_config.IMAP_FOLDER = "INBOX"

        mock_conn = MagicMock()
        mock_imap_cls.return_value = mock_conn
        mock_conn.search.return_value = ("OK", [b"1 2 3"])

        app = MagicMock()
        result = poll_inbox(app)
        assert result["emails_found"] == 3
        assert mock_process.call_count == 3

    @patch("imap_poller._log_poll")
    @patch("imap_poller.imaplib.IMAP4_SSL")
    @patch("imap_poller.config")
    def test_connection_error(self, mock_config, mock_imap_cls, mock_log):
        import imaplib
        mock_config.IMAP_ENABLED = True
        mock_config.IMAP_USE_SSL = True
        mock_config.IMAP_HOST = "bad-host"
        mock_config.IMAP_PORT = 993
        mock_config.IMAP_USER = "user"
        mock_config.IMAP_PASS = "pass"

        mock_imap_cls.side_effect = imaplib.IMAP4.error("Connection refused")

        app = MagicMock()
        result = poll_inbox(app)
        assert result["status"] == "error"
        assert len(result["errors"]) > 0

    @patch("imap_poller._log_poll")
    @patch("imap_poller._process_message")
    @patch("imap_poller.imaplib.IMAP4_SSL")
    @patch("imap_poller.config")
    def test_process_message_error_recorded(self, mock_config, mock_imap_cls, mock_process, mock_log):
        mock_config.IMAP_ENABLED = True
        mock_config.IMAP_USE_SSL = True
        mock_config.IMAP_HOST = "imap.example.com"
        mock_config.IMAP_PORT = 993
        mock_config.IMAP_USER = "user"
        mock_config.IMAP_PASS = "pass"
        mock_config.IMAP_FOLDER = "INBOX"

        mock_conn = MagicMock()
        mock_imap_cls.return_value = mock_conn
        mock_conn.search.return_value = ("OK", [b"1"])
        mock_process.side_effect = RuntimeError("parse error")

        app = MagicMock()
        result = poll_inbox(app)
        assert len(result["errors"]) == 1
        assert result["emails_processed"] == 0


class TestExtractForwardedEmail:
    def test_rfc822_attachment(self):
        """Test extraction from message/rfc822 attachment."""
        inner = email.message.EmailMessage()
        inner["From"] = "original@sender.com"
        inner["Subject"] = "Original subject"
        inner.set_content("Original body")

        outer = email.message.EmailMessage()
        outer["From"] = "forwarder@company.com"
        outer["Subject"] = "Fwd: Original subject"
        outer.make_mixed()
        outer.add_attachment(inner)

        result = extract_forwarded_email(outer)
        assert result is not None
        assert len(result) > 0

    def test_eml_file_attachment(self):
        """Test extraction from .eml file attachment."""
        outer = email.mime.multipart.MIMEMultipart()
        outer["From"] = "forwarder@company.com"
        outer["Subject"] = "Fwd: Suspicious"

        from email.mime.base import MIMEBase
        from email import encoders
        attachment = MIMEBase("message", "rfc822")
        attachment.set_payload(b"From: attacker@evil.com\nSubject: Phish\n\nClick here")
        attachment.add_header("Content-Disposition", "attachment", filename="suspicious.eml")
        outer.attach(attachment)

        result = extract_forwarded_email(outer)
        assert result is not None

    def test_fallback_to_whole_message(self):
        """When no forwarded content found, falls back to whole message."""
        msg = email.message_from_string(
            "From: user@example.com\nSubject: Not a forward\n\nJust a plain email."
        )
        result = extract_forwarded_email(msg)
        assert result is not None  # Returns the whole message as bytes

    def test_plain_text_message(self):
        msg = email.message_from_string(
            "From: user@example.com\nSubject: Plain\n\nHello world"
        )
        result = extract_forwarded_email(msg)
        assert result is not None


class TestAttributeToUser:
    def test_known_user(self, app):
        from database import db, User
        with app.app_context():
            user = User(email="known@company.com", username="known", role="analyst", is_active=True)
            user.set_password("test123")
            db.session.add(user)
            db.session.commit()

            result = attribute_to_user("known@company.com", app)
            assert result is not None
            assert result.email == "known@company.com"

    def test_unknown_user_falls_back_to_admin(self, app):
        from database import db, User
        with app.app_context():
            admin = User(email="admin@company.com", username="admin2", role="admin", is_active=True)
            admin.set_password("test123")
            db.session.add(admin)
            db.session.commit()

            result = attribute_to_user("unknown@external.com", app)
            assert result is not None
            assert result.role == "admin"

    def test_unknown_user_gets_fallback(self, app):
        # _ensure_admin creates a default admin at startup, so there's always
        # at least one user.  attribute_to_user falls back to admin.
        result = attribute_to_user("nobody@nowhere.com", app)
        # Should get the default admin as fallback
        assert result is not None
        assert result.role == "admin"


class TestSendAnalysisReply:
    @patch("imap_poller.config")
    def test_smtp_disabled(self, mock_config):
        mock_config.SMTP_ENABLED = False
        result = send_analysis_reply("user@example.com", {"score": {"level": "clean", "total": 5}})
        assert result is False

    @patch("imap_poller.smtplib.SMTP")
    @patch("imap_poller.config")
    def test_reply_sent(self, mock_config, mock_smtp_cls):
        mock_config.SMTP_ENABLED = True
        mock_config.SMTP_USE_TLS = True
        mock_config.SMTP_HOST = "smtp.example.com"
        mock_config.SMTP_PORT = 587
        mock_config.SMTP_FROM = "noreply@phishguard.local"
        mock_config.SMTP_USER = "user"
        mock_config.SMTP_PASS = "pass"
        mock_config.APP_BASE_URL = "http://localhost:5000"

        mock_server = MagicMock()
        mock_smtp_cls.return_value = mock_server

        report_dict = {
            "report_id": "rpt-001",
            "filename": "test.eml",
            "score": {
                "level": "high",
                "total": 72,
                "level_color": "#f97316",
                "breakdown": [{"reason": "SPF fail", "points": 15}],
            },
        }
        result = send_analysis_reply("user@example.com", report_dict)
        assert result is True
        mock_server.sendmail.assert_called_once()


class TestTestConnection:
    @patch("imap_poller.config")
    def test_disabled(self, mock_config):
        mock_config.IMAP_ENABLED = False
        result = imap_test_connection()
        assert result["success"] is False

    @patch("imap_poller.imaplib.IMAP4_SSL")
    @patch("imap_poller.config")
    def test_successful_connection(self, mock_config, mock_imap_cls):
        mock_config.IMAP_ENABLED = True
        mock_config.IMAP_USE_SSL = True
        mock_config.IMAP_HOST = "imap.example.com"
        mock_config.IMAP_PORT = 993
        mock_config.IMAP_USER = "user"
        mock_config.IMAP_PASS = "pass"
        mock_config.IMAP_FOLDER = "INBOX"

        mock_conn = MagicMock()
        mock_imap_cls.return_value = mock_conn
        mock_conn.list.return_value = ("OK", [b"INBOX"])
        mock_conn.search.side_effect = [
            ("OK", [b"1 2 3"]),   # ALL
            ("OK", [b"3"]),        # UNSEEN
        ]

        result = imap_test_connection()
        assert result["success"] is True
        assert result["total_messages"] == 3
        assert result["unseen_messages"] == 1

    @patch("imap_poller.imaplib.IMAP4_SSL")
    @patch("imap_poller.config")
    def test_connection_failure(self, mock_config, mock_imap_cls):
        mock_config.IMAP_ENABLED = True
        mock_config.IMAP_USE_SSL = True
        mock_config.IMAP_HOST = "bad-host"
        mock_config.IMAP_PORT = 993
        mock_config.IMAP_USER = "user"
        mock_config.IMAP_PASS = "pass"

        mock_imap_cls.side_effect = ConnectionRefusedError("refused")

        result = imap_test_connection()
        assert result["success"] is False
        assert "error" in result
