"""Tests for threat_intel.py — external threat intelligence feeds."""

import pytest
from unittest.mock import patch, MagicMock

from threat_intel import (
    check_abuseipdb, check_urlhaus, check_phishtank,
    check_otx_ip, check_otx_domain, check_vt_url,
    enrich_iocs,
)


class TestCheckAbuseIPDB:
    @patch("threat_intel._rate_wait")
    @patch("threat_intel.requests.get")
    def test_malicious_ip(self, mock_get, mock_rate):
        mock_get.return_value = MagicMock(
            status_code=200,
            json=lambda: {"data": {
                "abuseConfidenceScore": 85,
                "countryCode": "RU",
                "isp": "Evil ISP",
                "domain": "evil.com",
                "totalReports": 42,
                "isTor": False,
                "isWhitelisted": False,
            }}
        )
        result = check_abuseipdb("1.2.3.4", "test-api-key")
        assert result["abuse_confidence"] == 85
        assert result["error"] is None

    @patch("threat_intel._rate_wait")
    @patch("threat_intel.requests.get")
    def test_clean_ip(self, mock_get, mock_rate):
        mock_get.return_value = MagicMock(
            status_code=200,
            json=lambda: {"data": {
                "abuseConfidenceScore": 0,
                "totalReports": 0,
            }}
        )
        result = check_abuseipdb("8.8.8.8", "test-api-key")
        assert result["abuse_confidence"] == 0

    def test_no_api_key(self):
        result = check_abuseipdb("1.2.3.4", "")
        assert result is None

    def test_no_ip(self):
        result = check_abuseipdb("", "test-key")
        assert result is None

    @patch("threat_intel._rate_wait")
    @patch("threat_intel.requests.get")
    def test_rate_limited(self, mock_get, mock_rate):
        mock_get.return_value = MagicMock(status_code=429)
        result = check_abuseipdb("1.2.3.4", "key")
        assert result["error"] == "rate_limited"

    @patch("threat_intel._rate_wait")
    @patch("threat_intel.requests.get")
    def test_timeout(self, mock_get, mock_rate):
        import requests
        mock_get.side_effect = requests.exceptions.Timeout("timed out")
        result = check_abuseipdb("1.2.3.4", "key")
        assert result["error"] is not None
        assert "timed out" in result["error"]

    @patch("threat_intel._rate_wait")
    @patch("threat_intel.requests.get")
    def test_connection_error(self, mock_get, mock_rate):
        import requests
        mock_get.side_effect = requests.exceptions.ConnectionError("refused")
        result = check_abuseipdb("1.2.3.4", "key")
        assert result["error"] is not None

    @patch("threat_intel._rate_wait")
    @patch("threat_intel.requests.get")
    def test_server_error(self, mock_get, mock_rate):
        mock_get.return_value = MagicMock(status_code=500)
        result = check_abuseipdb("1.2.3.4", "key")
        assert "http_500" in result["error"]


class TestCheckURLhaus:
    @patch("threat_intel._rate_wait")
    @patch("threat_intel.requests.post")
    def test_malicious_url(self, mock_post, mock_rate):
        mock_post.return_value = MagicMock(
            status_code=200,
            json=lambda: {
                "query_status": "listed",
                "threat": "malware_download",
                "url_status": "online",
                "tags": ["emotet"],
                "date_added": "2025-01-01",
            }
        )
        result = check_urlhaus("http://evil.com/malware.exe")
        assert result["is_malicious"] is True
        assert result["threat_type"] == "malware_download"

    @patch("threat_intel._rate_wait")
    @patch("threat_intel.requests.post")
    def test_clean_url(self, mock_post, mock_rate):
        mock_post.return_value = MagicMock(
            status_code=200,
            json=lambda: {"query_status": "no_results"}
        )
        result = check_urlhaus("http://google.com")
        assert result["is_malicious"] is False

    def test_empty_url(self):
        assert check_urlhaus("") is None


class TestCheckPhishTank:
    @patch("threat_intel._rate_wait")
    @patch("threat_intel.requests.post")
    def test_phishing_url(self, mock_post, mock_rate):
        mock_post.return_value = MagicMock(
            status_code=200,
            json=lambda: {"results": {
                "in_database": True,
                "verified": True,
                "verified_at": "2025-01-01T00:00:00Z",
                "phish_id": "12345",
            }}
        )
        result = check_phishtank("http://evil-login.com")
        assert result["is_phishing"] is True
        assert result["verified"] is True

    @patch("threat_intel._rate_wait")
    @patch("threat_intel.requests.post")
    def test_clean_url(self, mock_post, mock_rate):
        mock_post.return_value = MagicMock(
            status_code=200,
            json=lambda: {"results": {"in_database": False}}
        )
        result = check_phishtank("http://google.com")
        assert result["is_phishing"] is False

    @patch("threat_intel._rate_wait")
    @patch("threat_intel.requests.post")
    def test_rate_limit(self, mock_post, mock_rate):
        mock_post.return_value = MagicMock(status_code=509)
        result = check_phishtank("http://example.com", "key")
        assert result["error"] == "rate_limited"


class TestCheckOTX:
    @patch("threat_intel._rate_wait")
    @patch("threat_intel.requests.get")
    def test_malicious_ip(self, mock_get, mock_rate):
        mock_get.return_value = MagicMock(
            status_code=200,
            json=lambda: {
                "pulse_info": {"count": 5},
                "reputation": -10,
                "country_code": "CN",
                "asn": "AS12345",
            }
        )
        result = check_otx_ip("1.2.3.4", "otx-key")
        assert result["is_malicious"] is True
        assert result["pulse_count"] == 5

    @patch("threat_intel._rate_wait")
    @patch("threat_intel.requests.get")
    def test_domain_lookup(self, mock_get, mock_rate):
        mock_get.return_value = MagicMock(
            status_code=200,
            json=lambda: {
                "pulse_info": {"count": 0},
                "alexa": "1000",
                "whois": "Registrar: GoDaddy",
            }
        )
        result = check_otx_domain("example.com", "otx-key")
        assert result["is_malicious"] is False

    def test_no_api_key(self):
        assert check_otx_ip("1.2.3.4", "") is None
        assert check_otx_domain("evil.com", "") is None


class TestCheckVTUrl:
    @patch("threat_intel._rate_wait")
    @patch("threat_intel.requests.get")
    def test_malicious_url(self, mock_get, mock_rate):
        mock_get.return_value = MagicMock(
            status_code=200,
            json=lambda: {"data": {"attributes": {
                "last_analysis_stats": {
                    "malicious": 12,
                    "suspicious": 3,
                    "undetected": 50,
                    "harmless": 5,
                },
                "categories": {"Forcepoint": "malicious"},
                "last_final_url": "http://evil.com/final",
                "title": "Fake Login",
            }}}
        )
        result = check_vt_url("http://evil.com", "vt-key")
        assert result["malicious"] == 15  # 12 + 3
        assert result["error"] is None

    @patch("threat_intel._rate_wait")
    @patch("threat_intel.requests.get")
    def test_url_not_found(self, mock_get, mock_rate):
        mock_get.return_value = MagicMock(status_code=404)
        result = check_vt_url("http://new-domain.com", "vt-key")
        assert result.get("is_known") is False

    def test_no_api_key(self):
        assert check_vt_url("http://example.com", "") is None


class TestEnrichIOCs:
    def test_disabled_feeds(self):
        mock_config = MagicMock()
        mock_config.THREAT_INTEL_ENABLED = False
        result = enrich_iocs(config=mock_config)
        assert result["summary"]["total_checked"] == 0

    def test_no_config(self):
        result = enrich_iocs(config=None)
        assert result["ip_results"] == {}

    @patch("threat_intel.check_urlhaus")
    @patch("threat_intel.check_urlhaus_domain")
    def test_domain_enrichment(self, mock_domain, mock_url, ):
        mock_domain.return_value = {
            "source": "URLhaus", "is_malicious": True,
            "url_count": 5, "error": None,
        }

        mock_config = MagicMock()
        mock_config.THREAT_INTEL_ENABLED = True
        mock_config.ABUSEIPDB_API_KEY = ""
        mock_config.OTX_API_KEY = ""
        mock_config.PHISHTANK_API_KEY = ""
        mock_config.VT_API_KEY = ""

        result = enrich_iocs(domains=["evil.com"], config=mock_config)
        assert result["summary"]["total_checked"] > 0
        assert "URLhaus" in result["summary"]["feeds_used"]

    def test_result_structure(self):
        mock_config = MagicMock()
        mock_config.THREAT_INTEL_ENABLED = False
        result = enrich_iocs(config=mock_config)
        assert "ip_results" in result
        assert "domain_results" in result
        assert "url_results" in result
        assert "summary" in result
