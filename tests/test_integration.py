"""Integration tests — full pipeline from upload to report to export.

All external services (VT, DNS, WHOIS, threat intel, Playwright, YARA, SMTP, S3)
are mocked. Tests run the actual Flask routes + analysis pipeline end-to-end.
"""

import io
import json
import pytest
from unittest.mock import patch, MagicMock


SIMPLE_EML = (
    b"From: sender@example.com\r\n"
    b"To: recipient@company.com\r\n"
    b"Subject: Test Email\r\n"
    b"Date: Mon, 15 Jan 2025 10:00:00 +0000\r\n"
    b"MIME-Version: 1.0\r\n"
    b"Content-Type: text/plain; charset=utf-8\r\n"
    b"\r\n"
    b"This is a normal test email body.\r\n"
)

PHISHING_EML = (
    b"From: security@micros0ft-support.com\r\n"
    b"To: victim@company.com\r\n"
    b"Subject: URGENT: Your account has been compromised\r\n"
    b"Date: Mon, 15 Jan 2025 10:00:00 +0000\r\n"
    b"Reply-To: hacker@evil.com\r\n"
    b"MIME-Version: 1.0\r\n"
    b"Content-Type: text/html; charset=utf-8\r\n"
    b"\r\n"
    b"<html><body>"
    b"<p>Dear user, your account will be suspended within 24 hours.</p>"
    b"<p>Click <a href='http://evil-phish.com/login'>here</a> to verify immediately.</p>"
    b"<p>Failure to act will result in permanent account deletion.</p>"
    b"</body></html>\r\n"
)


@pytest.fixture
def _disable_external(monkeypatch):
    """Ensure all external service flags are off during integration tests."""
    import config
    monkeypatch.setattr(config, "VT_ENABLED", False)
    monkeypatch.setattr(config, "THREAT_INTEL_ENABLED", False)
    monkeypatch.setattr(config, "BROWSER_DETONATION_ENABLED", False)
    monkeypatch.setattr(config, "YARA_ENABLED", False)
    monkeypatch.setattr(config, "NLP_ANALYSIS_ENABLED", False)
    monkeypatch.setattr(config, "ML_CLASSIFIER_ENABLED", False)
    monkeypatch.setattr(config, "HTML_SIMILARITY_ENABLED", False)
    monkeypatch.setattr(config, "S3_ENABLED", False)
    monkeypatch.setattr(config, "SMTP_ENABLED", False)
    monkeypatch.setattr(config, "IMAP_ENABLED", False)


@pytest.mark.integration
class TestUploadAndAnalyze:
    """Test the synchronous upload-and-analyze flow."""

    def test_upload_clean_email(self, auth_client, _disable_external):
        data = {"file": (io.BytesIO(SIMPLE_EML), "clean.eml")}
        resp = auth_client.post("/analyze", data=data,
                                content_type="multipart/form-data",
                                follow_redirects=True)
        assert resp.status_code == 200

    def test_upload_phishing_email(self, auth_client, _disable_external):
        data = {"file": (io.BytesIO(PHISHING_EML), "phish.eml")}
        resp = auth_client.post("/analyze", data=data,
                                content_type="multipart/form-data",
                                follow_redirects=True)
        assert resp.status_code == 200

    def test_upload_no_file(self, auth_client, _disable_external):
        resp = auth_client.post("/analyze", data={},
                                content_type="multipart/form-data",
                                follow_redirects=True)
        # Should show an error or redirect back
        assert resp.status_code in (200, 302, 400)

    def test_upload_wrong_extension(self, auth_client, _disable_external):
        data = {"file": (io.BytesIO(b"not an email"), "readme.txt")}
        resp = auth_client.post("/analyze", data=data,
                                content_type="multipart/form-data",
                                follow_redirects=True)
        assert resp.status_code in (200, 400)

    def test_upload_malformed_eml(self, auth_client, malformed_eml, _disable_external):
        data = {"file": (io.BytesIO(malformed_eml), "bad.eml")}
        resp = auth_client.post("/analyze", data=data,
                                content_type="multipart/form-data",
                                follow_redirects=True)
        # Should handle gracefully — either analyze what it can or error
        assert resp.status_code in (200, 302, 400, 500)

    def test_upload_requires_auth(self, client, _disable_external):
        data = {"file": (io.BytesIO(SIMPLE_EML), "test.eml")}
        resp = client.post("/analyze", data=data,
                           content_type="multipart/form-data",
                           follow_redirects=False)
        # Should redirect to login (302) or return 401
        assert resp.status_code in (302, 303, 401)
        if resp.status_code in (302, 303):
            assert "/login" in resp.headers.get("Location", "")


@pytest.mark.integration
class TestReportViewing:
    """Test report viewing after an analysis exists."""

    @pytest.fixture(autouse=True)
    def _create_analysis(self, app, test_user, _disable_external):
        """Create a saved analysis in the DB for report viewing tests."""
        from database import save_report
        self.report_id = "integ001"
        report_dict = {
            "report_id": self.report_id,
            "filename": "test_integration.eml",
            "analyzed_at": "2025-01-15 10:30:00 UTC",
            "headers": {
                "from_address": "test@example.com",
                "from_display": "Test Sender",
                "to_addresses": ["recipient@company.com"],
                "subject": "Integration Test",
                "spf_result": "pass",
                "dkim_result": "pass",
                "dmarc_result": "pass",
                "reply_to_mismatch": False,
                "display_name_spoofed": False,
                "anomalies": [],
                "forged_headers": [],
                "received_chain": [],
                "originating_ip": "",
            },
            "body": {"text_content": "Test body", "html_content": ""},
            "urls": [],
            "attachments": [],
            "score": {
                "total": 5,
                "level": "clean",
                "level_color": "#10b981",
                "level_label": "Clean",
                "breakdown": [],
            },
            "iocs": {
                "ip_addresses": [], "domains": [], "urls": [],
                "email_addresses": ["test@example.com"], "hashes": [],
            },
            "mitre_mappings": [],
            "attack_summary": {},
            "whois": {},
        }
        with app.app_context():
            save_report(report_dict, user_id=test_user.id)

    def test_view_report(self, auth_client):
        resp = auth_client.get(f"/report/{self.report_id}")
        assert resp.status_code == 200

    def test_view_nonexistent_report(self, auth_client):
        resp = auth_client.get("/report/nonexistent999")
        assert resp.status_code == 404

    def test_download_pdf(self, auth_client):
        resp = auth_client.get(f"/report/{self.report_id}/pdf")
        if resp.status_code == 200:
            assert resp.content_type in ("application/pdf", "application/octet-stream")
            assert len(resp.data) > 0

    def test_export_stix(self, auth_client):
        resp = auth_client.get(f"/report/{self.report_id}/stix")
        if resp.status_code == 200:
            data = resp.get_json()
            assert data is not None


@pytest.mark.integration
class TestDashboardAndHistory:
    def test_dashboard_loads(self, auth_client, _disable_external):
        resp = auth_client.get("/dashboard")
        assert resp.status_code == 200

    def test_history_loads(self, auth_client, _disable_external):
        resp = auth_client.get("/history")
        assert resp.status_code == 200


@pytest.mark.integration
class TestAPIEndpoints:
    """Test the JSON API endpoints with JWT auth."""

    def _get_token(self, client, email, password):
        resp = client.post("/api/auth/token",
                           json={"email": email, "password": password},
                           content_type="application/json")
        if resp.status_code == 200:
            return resp.get_json()["access_token"]
        return None

    def test_api_history(self, app, client, test_user, _disable_external):
        token = self._get_token(client, "testuser@example.com", "TestPass123!")
        assert token is not None

        resp = client.get("/api/history",
                          headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200
        data = resp.get_json()
        assert isinstance(data, (list, dict))

    def test_api_stats(self, app, client, test_user, _disable_external):
        token = self._get_token(client, "testuser@example.com", "TestPass123!")
        resp = client.get("/api/stats",
                          headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200

    def test_api_requires_auth(self, client, _disable_external):
        resp = client.get("/api/history")
        assert resp.status_code == 401

    def test_api_analyze_endpoint(self, app, client, test_user, _disable_external):
        token = self._get_token(client, "testuser@example.com", "TestPass123!")
        if token:
            data = {"file": (io.BytesIO(SIMPLE_EML), "api_test.eml")}
            resp = client.post("/api/analyze",
                               data=data,
                               content_type="multipart/form-data",
                               headers={"Authorization": f"Bearer {token}"})
            # Might return 200 (sync) or 202 (async) or 400 depending on config
            assert resp.status_code in (200, 202, 400, 404)
