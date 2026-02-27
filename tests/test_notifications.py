"""Tests for notifications.py — email, Slack, and in-app notifications."""

import pytest
from unittest.mock import patch, MagicMock

from notifications import (
    send_email_alert, send_slack_alert,
    _build_threat_email, _build_weekly_email, _build_slack_blocks,
)


class TestSendEmailAlert:
    @patch("notifications.config")
    def test_smtp_disabled(self, mock_config):
        mock_config.SMTP_ENABLED = False
        result = send_email_alert("user@example.com", "Test", "<p>Body</p>")
        assert result is False

    @patch("notifications.config")
    @patch("notifications.smtplib.SMTP")
    def test_email_sent_tls(self, mock_smtp_cls, mock_config):
        mock_config.SMTP_ENABLED = True
        mock_config.SMTP_USE_TLS = True
        mock_config.SMTP_HOST = "smtp.example.com"
        mock_config.SMTP_PORT = 587
        mock_config.SMTP_FROM = "noreply@phishguard.local"
        mock_config.SMTP_USER = "user"
        mock_config.SMTP_PASS = "pass"

        mock_server = MagicMock()
        mock_smtp_cls.return_value = mock_server

        result = send_email_alert("user@example.com", "Alert", "<p>Threat!</p>")
        assert result is True
        mock_server.starttls.assert_called_once()
        mock_server.sendmail.assert_called_once()
        mock_server.quit.assert_called_once()

    @patch("notifications.config")
    @patch("notifications.smtplib.SMTP_SSL")
    def test_email_sent_ssl(self, mock_smtp_cls, mock_config):
        mock_config.SMTP_ENABLED = True
        mock_config.SMTP_USE_TLS = False
        mock_config.SMTP_HOST = "smtp.example.com"
        mock_config.SMTP_PORT = 465
        mock_config.SMTP_FROM = "noreply@phishguard.local"
        mock_config.SMTP_USER = "user"
        mock_config.SMTP_PASS = "pass"

        mock_server = MagicMock()
        mock_smtp_cls.return_value = mock_server

        result = send_email_alert("user@example.com", "Alert", "<p>Threat!</p>")
        assert result is True
        mock_server.sendmail.assert_called_once()

    @patch("notifications.config")
    @patch("notifications.smtplib.SMTP")
    def test_smtp_exception_handled(self, mock_smtp_cls, mock_config):
        mock_config.SMTP_ENABLED = True
        mock_config.SMTP_USE_TLS = True
        mock_config.SMTP_HOST = "smtp.example.com"
        mock_config.SMTP_PORT = 587
        mock_config.SMTP_FROM = "noreply@phishguard.local"
        mock_config.SMTP_USER = ""
        mock_config.SMTP_PASS = ""

        mock_smtp_cls.side_effect = ConnectionRefusedError("SMTP down")

        result = send_email_alert("user@example.com", "Alert", "<p>Body</p>")
        assert result is False


class TestSendSlackAlert:
    def test_no_webhook(self):
        result = send_slack_alert("", "test message")
        assert result is False

    def test_successful_post(self):
        mock_requests = MagicMock()
        mock_requests.post.return_value = MagicMock(status_code=200)
        with patch.dict("sys.modules", {"requests": mock_requests}):
            result = send_slack_alert("https://hooks.slack.com/test", "Alert!")
        assert result is True
        mock_requests.post.assert_called_once()

    def test_with_blocks(self):
        mock_requests = MagicMock()
        mock_requests.post.return_value = MagicMock(status_code=200)
        blocks = [{"type": "section", "text": {"type": "mrkdwn", "text": "test"}}]
        with patch.dict("sys.modules", {"requests": mock_requests}):
            result = send_slack_alert("https://hooks.slack.com/test", "Alert!", blocks=blocks)
        assert result is True
        call_kwargs = mock_requests.post.call_args
        payload = call_kwargs.kwargs.get("json") or call_kwargs[1].get("json", {})
        assert "blocks" in payload

    def test_webhook_error(self):
        mock_requests = MagicMock()
        mock_requests.post.return_value = MagicMock(status_code=500, text="Internal Error")
        with patch.dict("sys.modules", {"requests": mock_requests}):
            result = send_slack_alert("https://hooks.slack.com/test", "Alert!")
        assert result is False

    def test_timeout(self):
        mock_requests = MagicMock()
        mock_requests.post.side_effect = Exception("timed out")
        with patch.dict("sys.modules", {"requests": mock_requests}):
            result = send_slack_alert("https://hooks.slack.com/test", "Alert!")
        assert result is False


class TestBuildThreatEmail:
    def test_critical_email(self):
        html = _build_threat_email("evil.eml", "critical", 92, "rpt-001")
        assert "CRITICAL" in html
        assert "92" in html
        assert "evil.eml" in html
        assert "rpt-001" in html
        assert "password" in html.lower()  # recommended action

    def test_high_email(self):
        html = _build_threat_email("suspicious.eml", "high", 65, "rpt-002")
        assert "HIGH" in html
        assert "suspicious.eml" in html

    def test_medium_email(self):
        html = _build_threat_email("maybe.eml", "medium", 35, "rpt-003")
        assert "MEDIUM" in html

    def test_contains_report_link(self):
        html = _build_threat_email("test.eml", "high", 60, "abc123")
        assert "/report/abc123" in html

    def test_contains_actions(self):
        html = _build_threat_email("test.eml", "critical", 85, "rpt-001")
        assert "Recommended Actions" in html


class TestBuildWeeklyEmail:
    def test_basic_summary(self):
        html = _build_weekly_email("testuser", 10, 2, 3, 1, 4)
        assert "testuser" in html
        assert "10" in html  # total
        assert "Weekly" in html

    def test_zero_threats(self):
        html = _build_weekly_email("user", 5, 0, 0, 0, 5)
        assert "No threats" in html or "strong" in html.lower()

    def test_critical_highlight(self):
        html = _build_weekly_email("user", 10, 5, 2, 1, 2)
        assert "critical" in html.lower()

    def test_contains_dashboard_link(self):
        html = _build_weekly_email("user", 10, 1, 2, 3, 4)
        assert "/dashboard" in html


class TestBuildSlackBlocks:
    def test_block_structure(self):
        blocks = _build_slack_blocks("test.eml", "critical", 90, "rpt-001")
        assert isinstance(blocks, list)
        assert len(blocks) >= 2

    def test_contains_file_info(self):
        blocks = _build_slack_blocks("evil.eml", "high", 70, "rpt-002")
        # Flatten to text to check content
        text = str(blocks)
        assert "evil.eml" in text
        assert "70" in text

    def test_critical_style(self):
        blocks = _build_slack_blocks("test.eml", "critical", 95, "rpt-001")
        text = str(blocks)
        assert "danger" in text  # button style
