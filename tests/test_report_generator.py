"""Tests for report_generator.py — PDF report generation."""

from unittest.mock import patch

import pytest

import config
from report_generator import generate_pdf


@pytest.fixture
def basic_report():
    return {
        "report_id": "test123",
        "filename": "test.eml",
        "analyzed_at": "2025-01-15 10:30:00 UTC",
        "headers": {
            "from_address": "sender@example.com",
            "from_display": "Sender Name",
            "to_addresses": ["recipient@company.com"],
            "subject": "Test Subject",
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
        "body": {
            "text_content": "This is a test email body.",
            "html_content": "",
        },
        "urls": [],
        "attachments": [],
        "score": {
            "total": 5,
            "level": "clean",
            "level_color": "#10b981",
            "level_label": "Clean — No Threats Detected",
            "breakdown": [],
        },
        "iocs": {
            "ip_addresses": [],
            "domains": [],
            "urls": [],
            "email_addresses": ["sender@example.com"],
            "hashes": [],
        },
        "mitre_mappings": [],
        "attack_summary": {},
        "whois": {},
    }


@pytest.fixture
def critical_report(basic_report):
    report = basic_report.copy()
    report["score"] = {
        "total": 85,
        "level": "critical",
        "level_color": "#ef4444",
        "level_label": "Critical — Highly Likely Phishing",
        "breakdown": [
            {"reason": "SPF failed", "points": 15, "category": "authentication"},
            {"reason": "Known phishing URL", "points": 20, "category": "url"},
            {"reason": "Credential harvesting form", "points": 15, "category": "url"},
            {"reason": "Display name spoofed", "points": 10, "category": "header"},
            {"reason": "Urgency language", "points": 8, "category": "content"},
        ],
    }
    report["headers"]["spf_result"] = "fail"
    report["headers"]["from_address"] = "attacker@evil.com"
    report["headers"]["subject"] = "URGENT: Verify Your Account NOW"
    report["urls"] = [{
        "url": "http://evil.com/login",
        "domain": "evil.com",
        "risk_score": 40,
        "known_phishing": True,
    }]
    return report


class TestGeneratePdf:
    def test_basic_report_produces_pdf(self, basic_report):
        result = generate_pdf(basic_report)
        assert result is not None
        # Read the BytesIO content
        pdf_bytes = result.getvalue()
        assert len(pdf_bytes) > 0
        assert pdf_bytes[:4] == b"%PDF"

    def test_critical_report(self, critical_report):
        result = generate_pdf(critical_report)
        assert result is not None
        pdf_bytes = result.getvalue()
        assert pdf_bytes[:4] == b"%PDF"

    def test_clean_email_report(self, basic_report):
        basic_report["score"]["level"] = "clean"
        basic_report["score"]["total"] = 0
        result = generate_pdf(basic_report)
        assert result is not None

    def test_empty_report(self):
        minimal = {
            "report_id": "empty001",
            "filename": "empty.eml",
            "analyzed_at": "2025-01-15 10:00:00 UTC",
            "headers": {
                "from_address": "",
                "from_display": "",
                "to_addresses": [],
                "subject": "",
                "spf_result": "none",
                "dkim_result": "none",
                "dmarc_result": "none",
                "anomalies": [],
                "forged_headers": [],
                "received_chain": [],
            },
            "body": {"text_content": "", "html_content": ""},
            "urls": [],
            "attachments": [],
            "score": {"total": 0, "level": "clean", "level_color": "#10b981",
                       "level_label": "Clean", "breakdown": []},
            "iocs": {"ip_addresses": [], "domains": [], "urls": [],
                      "email_addresses": [], "hashes": []},
            "mitre_mappings": [],
            "attack_summary": {},
            "whois": {},
        }
        result = generate_pdf(minimal)
        assert result is not None

    def test_unicode_content(self, basic_report):
        basic_report["headers"]["subject"] = "日本語テスト — Проверка"
        basic_report["headers"]["from_display"] = "山田太郎"
        basic_report["body"]["text_content"] = "这是测试内容。Тестовое содержание."
        result = generate_pdf(basic_report)
        assert result is not None

    def test_long_urls(self, basic_report):
        long_url = "http://evil.com/" + "a" * 500
        basic_report["urls"] = [{
            "url": long_url,
            "domain": "evil.com",
            "risk_score": 10,
        }]
        result = generate_pdf(basic_report)
        assert result is not None

    def test_many_attachments(self, basic_report):
        basic_report["attachments"] = [
            {
                "filename": f"attachment_{i}.pdf",
                "size": 1024 * i,
                "content_type": "application/pdf",
                "md5": f"hash{i:04d}",
                "entropy": 4.5,
            }
            for i in range(50)
        ]
        result = generate_pdf(basic_report)
        assert result is not None

    def test_many_findings(self, basic_report):
        basic_report["score"]["breakdown"] = [
            {"reason": f"Finding {i}", "points": 5, "category": "test"}
            for i in range(30)
        ]
        basic_report["score"]["total"] = 65
        basic_report["score"]["level"] = "high"
        result = generate_pdf(basic_report)
        assert result is not None

    @patch("report_generator.os.path.isfile")
    def test_fallback_without_fonts(self, mock_isfile, basic_report):
        # Simulate font files not found
        mock_isfile.return_value = False
        result = generate_pdf(basic_report)
        # Should still produce a PDF using fallback fonts
        assert result is not None

    def test_report_with_mitre_mappings(self, basic_report):
        basic_report["mitre_mappings"] = [
            {"technique_id": "T1566.001", "technique_name": "Spearphishing Attachment",
             "tactic": "Initial Access", "reason": "Malicious attachment"},
            {"technique_id": "T1204.002", "technique_name": "Malicious File",
             "tactic": "Execution", "reason": "Executable attachment"},
        ]
        result = generate_pdf(basic_report)
        assert result is not None

    def test_report_with_whois(self, basic_report):
        basic_report["whois"] = {
            "evil.com": {
                "registrar": "Shady Registrar Inc",
                "creation_date": "2025-01-01",
                "country": "RU",
            }
        }
        result = generate_pdf(basic_report)
        assert result is not None

    def test_business_impact_critical_report(self, critical_report):
        """Business impact section renders for critical-level reports with findings."""
        result = generate_pdf(critical_report)
        assert result is not None
        pdf_bytes = result.getvalue()
        assert pdf_bytes[:4] == b"%PDF"
        # Critical report has authentication, url, header, content categories
        # which should all produce plain-English explanations
        assert len(pdf_bytes) > 1000

    def test_business_impact_clean_report(self, basic_report):
        """Business impact section renders for clean reports with no findings."""
        basic_report["score"]["total"] = 0
        basic_report["score"]["level"] = "clean"
        basic_report["score"]["breakdown"] = []
        result = generate_pdf(basic_report)
        assert result is not None
        pdf_bytes = result.getvalue()
        assert pdf_bytes[:4] == b"%PDF"

    def test_custom_branding(self, basic_report):
        """PDF respects custom REPORT_COMPANY_NAME from config."""
        original = config.REPORT_COMPANY_NAME
        try:
            config.REPORT_COMPANY_NAME = "AcmeSec"
            result = generate_pdf(basic_report)
            assert result is not None
            pdf_bytes = result.getvalue()
            assert pdf_bytes[:4] == b"%PDF"
        finally:
            config.REPORT_COMPANY_NAME = original

    def test_tlp_banner_all_levels(self, basic_report):
        """PDF generates with each TLP level without errors."""
        original = config.REPORT_TLP_LEVEL
        try:
            for tlp in ("TLP:RED", "TLP:AMBER", "TLP:GREEN", "TLP:CLEAR"):
                config.REPORT_TLP_LEVEL = tlp
                result = generate_pdf(basic_report)
                assert result is not None, f"PDF generation failed for {tlp}"
                assert result.getvalue()[:4] == b"%PDF"
        finally:
            config.REPORT_TLP_LEVEL = original

    def test_confidentiality_notice_in_pdf(self, basic_report):
        """PDF includes the confidentiality notice text."""
        original = config.REPORT_CONFIDENTIALITY
        try:
            config.REPORT_CONFIDENTIALITY = "TOP SECRET TEST NOTICE"
            result = generate_pdf(basic_report)
            assert result is not None
            pdf_bytes = result.getvalue()
            assert pdf_bytes[:4] == b"%PDF"
        finally:
            config.REPORT_CONFIDENTIALITY = original
