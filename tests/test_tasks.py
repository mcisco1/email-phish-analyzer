"""Tests for tasks.py — Celery background tasks."""

import pytest
from unittest.mock import patch, MagicMock

try:
    import celery  # noqa: F401
    HAS_CELERY = True
except ImportError:
    HAS_CELERY = False

pytestmark = pytest.mark.skipif(not HAS_CELERY, reason="celery not installed")


class TestAnalyzeEmailTask:
    @patch("tasks.save_report")
    @patch("tasks.get_attack_summary")
    @patch("tasks.map_findings_to_mitre")
    @patch("tasks.calculate_score")
    @patch("tasks.extract_iocs")
    @patch("tasks.analyze_all_attachments")
    @patch("tasks.analyze_all_urls")
    @patch("tasks.analyze_headers")
    @patch("tasks.parse_eml")
    def test_successful_analysis(self, mock_parse, mock_headers, mock_urls,
                                  mock_atts, mock_iocs, mock_score,
                                  mock_mitre, mock_summary, mock_save, app):
        from tasks import analyze_email_task

        # Setup mocks
        mock_msg = MagicMock()
        mock_hdr = MagicMock()
        mock_hdr.from_address = "test@example.com"
        mock_hdr.subject = "Test"
        mock_body = MagicMock()
        mock_body.text_content = "Test body"
        mock_body.html_content = ""
        mock_parse.return_value = (mock_msg, mock_hdr, mock_body, [])
        mock_headers.return_value = mock_hdr
        mock_urls.return_value = []
        mock_atts.return_value = []
        mock_iocs.return_value = MagicMock(
            ip_addresses=[], domains=[], urls=[], email_addresses=[], hashes=[],
        )

        mock_score_obj = MagicMock()
        mock_score_obj.level = "clean"
        mock_score_obj.total = 5
        mock_score_obj.breakdown = []
        mock_score.return_value = mock_score_obj

        mock_mitre.return_value = []
        mock_summary.return_value = {}

        # Create an AnalysisReport mock
        with patch("tasks.AnalysisReport") as MockReport:
            mock_report = MagicMock()
            mock_report.to_dict.return_value = {
                "report_id": "test123",
                "filename": "test.eml",
                "headers": {},
                "body": {},
                "urls": [],
                "attachments": [],
                "iocs": {},
                "score": {"level": "clean", "total": 5, "breakdown": []},
            }
            MockReport.return_value = mock_report

            with patch("tasks.Analysis") as MockAnalysis:
                MockAnalysis.query.filter_by.return_value.first.return_value = None
                with patch("tasks.enrich_url_findings", return_value={}):
                    with patch("tasks.notify_on_analysis"):
                        # Call task directly (not via celery)
                        raw_hex = b"From: test@example.com\nSubject: Test\n\nBody".hex()
                        task = analyze_email_task
                        task.request = MagicMock()
                        task.request.id = "celery-task-123"

                        with app.app_context():
                            result = task.run(raw_hex, "test.eml", user_id="user1")

                        assert result["status"] == "complete"
                        assert result["filename"] == "test.eml"
                        mock_save.assert_called_once()

    @patch("tasks.parse_eml")
    def test_analysis_failure_retries(self, mock_parse, app):
        from tasks import analyze_email_task

        mock_parse.side_effect = ValueError("Bad EML data")

        with patch("tasks.Analysis") as MockAnalysis:
            MockAnalysis.query.filter_by.return_value.first.return_value = None
            task = analyze_email_task
            task.request = MagicMock()
            task.request.id = "celery-task-fail"
            task.retry = MagicMock(side_effect=ValueError("retry"))

            with app.app_context():
                with pytest.raises(ValueError):
                    task.run("deadbeef", "bad.eml")

            task.retry.assert_called_once()


class TestPollImapTask:
    @patch("tasks.config")
    def test_disabled(self, mock_config):
        mock_config.IMAP_ENABLED = False
        from tasks import poll_imap_task
        result = poll_imap_task()
        assert result["status"] == "disabled"

    @patch("tasks._flask_app", None)
    @patch("tasks.config")
    def test_no_app(self, mock_config):
        mock_config.IMAP_ENABLED = True
        from tasks import poll_imap_task
        result = poll_imap_task()
        assert result["status"] == "error"

    @patch("tasks.poll_inbox")
    @patch("tasks.config")
    def test_successful_poll(self, mock_config, mock_poll):
        mock_config.IMAP_ENABLED = True
        mock_poll.return_value = {"emails_found": 3, "emails_processed": 2, "status": "success"}

        from tasks import poll_imap_task, set_flask_app
        mock_app = MagicMock()
        set_flask_app(mock_app)

        result = poll_imap_task()
        assert result["emails_found"] == 3
        mock_poll.assert_called_once_with(mock_app)

        # Cleanup
        set_flask_app(None)

    @patch("tasks.poll_inbox")
    @patch("tasks.config")
    def test_poll_exception(self, mock_config, mock_poll):
        mock_config.IMAP_ENABLED = True
        mock_poll.side_effect = ConnectionError("IMAP down")

        from tasks import poll_imap_task, set_flask_app
        mock_app = MagicMock()
        set_flask_app(mock_app)

        result = poll_imap_task()
        assert result["status"] == "error"

        set_flask_app(None)


class TestWeeklySummaryTask:
    @patch("tasks._flask_app", None)
    def test_no_app(self):
        from tasks import weekly_summary_task
        result = weekly_summary_task()
        assert result["status"] == "error"

    @patch("tasks.send_weekly_summary")
    def test_successful_summary(self, mock_send):
        from tasks import weekly_summary_task, set_flask_app
        mock_app = MagicMock()
        set_flask_app(mock_app)

        result = weekly_summary_task()
        assert result["status"] == "success"
        mock_send.assert_called_once_with(mock_app)

        set_flask_app(None)

    @patch("tasks.send_weekly_summary")
    def test_summary_exception(self, mock_send):
        mock_send.side_effect = RuntimeError("SMTP error")

        from tasks import weekly_summary_task, set_flask_app
        mock_app = MagicMock()
        set_flask_app(mock_app)

        result = weekly_summary_task()
        assert result["status"] == "error"

        set_flask_app(None)


class TestCeleryConfig:
    def test_celery_app_exists(self):
        from tasks import celery_app
        assert celery_app is not None
        assert celery_app.main == "phishguard"

    def test_beat_schedule(self):
        from tasks import celery_app
        schedule = celery_app.conf.beat_schedule
        assert "poll-imap-inbox" in schedule
        assert "weekly-threat-summary" in schedule

    def test_init_celery(self, app):
        from tasks import init_celery, celery_app
        result = init_celery(app)
        assert result is celery_app
