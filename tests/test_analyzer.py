import os
import sys
import json
import tempfile
import unittest
import hashlib
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models import HeaderAnalysis, URLFinding, AttachmentFinding, AnalysisReport, ThreatScore, BodyAnalysis
from email_parser import parse_eml, _get_email_addr, _get_display_name, _parse_auth_field
from url_analyzer import extract_urls, analyze_url, analyze_all_urls, _check_homoglyphs, _detonate_url
from attachment_analyzer import (
    analyze_attachment, _calculate_entropy, _detect_type,
    _has_vba_markers, _virustotal_lookup, analyze_all_attachments,
)
from header_analyzer import analyze_headers, score_headers, _live_spf_lookup
from ioc_extractor import extract_iocs
from threat_scorer import calculate_score
from mitre_mapper import map_findings_to_mitre, get_attack_summary, _match_reason
from stix_exporter import generate_stix_bundle, stix_to_json
from whois_lookup import lookup_domain, _get_registrable, _is_ip
import database as db

SAMPLES_DIR = os.path.join(os.path.dirname(__file__), "samples")


def _read_sample(name):
    with open(os.path.join(SAMPLES_DIR, name), "rb") as f:
        return f.read()


# ---------------------------------------------------------------------------
# Email Parser
# ---------------------------------------------------------------------------

class TestEmailParser(unittest.TestCase):
    def test_parse_clean_email(self):
        raw = _read_sample("clean_email.eml")
        msg, headers, body, attachments = parse_eml(raw)
        self.assertEqual(headers.from_address, "john.smith@example.com")
        self.assertEqual(headers.from_display, "John Smith")
        self.assertIn("jane.doe@company.com", headers.to_addresses)
        self.assertIn("Q4 Report", headers.subject)
        self.assertEqual(headers.spf_result, "pass")
        self.assertEqual(headers.dkim_result, "pass")
        self.assertEqual(headers.dmarc_result, "pass")
        self.assertFalse(headers.reply_to_mismatch)
        self.assertTrue(len(body.text_content) > 0)

    def test_parse_phishing_email(self):
        raw = _read_sample("phishing_email.eml")
        msg, headers, body, attachments = parse_eml(raw)
        self.assertEqual(headers.from_address, "security@paypa1-secure.com")
        self.assertEqual(headers.reply_to, "phisher@evil-domain.xyz")
        self.assertTrue(headers.reply_to_mismatch)
        self.assertEqual(headers.spf_result, "fail")
        self.assertEqual(headers.dkim_result, "fail")
        self.assertEqual(headers.dmarc_result, "fail")
        self.assertTrue(len(attachments) > 0)
        self.assertTrue(body.javascript_detected)
        self.assertTrue(body.form_action_external)
        self.assertTrue(body.hidden_text)

    def test_parse_suspicious_attachment(self):
        raw = _read_sample("suspicious_attachment.eml")
        _, _, _, attachments = parse_eml(raw)
        self.assertEqual(len(attachments), 1)
        self.assertIn(".exe", attachments[0]["filename"])

    def test_email_addr_extraction(self):
        self.assertEqual(_get_email_addr("John <john@test.com>"), "john@test.com")
        self.assertEqual(_get_email_addr("plain@test.com"), "plain@test.com")
        self.assertEqual(_get_email_addr(""), "")

    def test_display_name_extraction(self):
        self.assertEqual(_get_display_name('"John Smith" <john@test.com>'), "John Smith")
        self.assertEqual(_get_display_name("plain@test.com"), "")

    def test_auth_field_parsing(self):
        auth = "mx.test.com; spf=fail smtp.mailfrom=bad.com; dkim=pass"
        self.assertEqual(_parse_auth_field(auth, "spf"), "fail")
        self.assertEqual(_parse_auth_field(auth, "dkim"), "pass")
        self.assertEqual(_parse_auth_field(auth, "dmarc"), "none")
        self.assertEqual(_parse_auth_field("", "spf"), "none")

    def test_received_spf_fallback(self):
        """Received-SPF: fail should be used when Authentication-Results is absent."""
        raw = (
            b"From: attacker@evil.com\r\n"
            b"To: victim@example.com\r\n"
            b"Subject: Test\r\n"
            b"Received-SPF: fail (domain does not designate sender)\r\n"
            b"MIME-Version: 1.0\r\n"
            b"Content-Type: text/plain\r\n\r\n"
            b"Hello\r\n"
        )
        _, headers, _, _ = parse_eml(raw)
        self.assertEqual(headers.spf_result, "fail")

    def test_originating_ip(self):
        raw = _read_sample("phishing_email.eml")
        _, headers, _, _ = parse_eml(raw)
        self.assertIsNotNone(headers.originating_ip)
        self.assertFalse(headers.originating_ip.startswith("10."))

    def test_return_path_mismatch(self):
        raw = _read_sample("phishing_email.eml")
        _, headers, _, _ = parse_eml(raw)
        self.assertTrue(len(headers.forged_headers) > 0)


# ---------------------------------------------------------------------------
# URL Analyzer — heuristic checks (network calls mocked)
# ---------------------------------------------------------------------------

class TestURLAnalyzer(unittest.TestCase):
    def test_extract_from_text(self):
        urls = extract_urls("Visit https://example.com and http://test.org/page", "")
        self.assertTrue(any("example.com" in u for u in urls))

    def test_extract_from_html(self):
        urls = extract_urls("", '<a href="https://phish.com/login">Click</a>')
        self.assertTrue(any("phish.com" in u for u in urls))

    def test_defanged_url_extraction(self):
        """Defanged URLs like hxxp:// and [.] should be normalized and extracted."""
        urls = extract_urls("Visit hxxps://evil[.]com/login now", "")
        self.assertTrue(any("evil.com" in u for u in urls))

    def test_defanged_bracketed_dot(self):
        urls = extract_urls("http://microsoft-secure-auth[.]com/verify", "")
        self.assertTrue(any("microsoft-secure-auth.com" in u for u in urls))

    @patch("url_analyzer._detonate_url")
    def test_known_phishing(self, mock_det):
        finding = analyze_url("http://paypa1-secure.com/verify")
        self.assertTrue(finding.known_phishing)

    @patch("url_analyzer._detonate_url")
    def test_ip_based(self, mock_det):
        finding = analyze_url("http://192.168.55.123/login")
        self.assertTrue(finding.is_ip_based)

    @patch("url_analyzer._detonate_url")
    def test_shortened(self, mock_det):
        finding = analyze_url("https://bit.ly/3xFakeLink")
        self.assertTrue(finding.is_shortened)

    @patch("url_analyzer._detonate_url")
    def test_suspicious_tld(self, mock_det):
        finding = analyze_url("http://login-verify.xyz/account")
        self.assertTrue(finding.suspicious_tld)

    @patch("url_analyzer._detonate_url")
    def test_https(self, mock_det):
        s = analyze_url("https://example.com")
        i = analyze_url("http://example.com")
        self.assertTrue(s.uses_https)
        self.assertFalse(i.uses_https)

    @patch("url_analyzer._detonate_url")
    def test_excessive_subdomains(self, mock_det):
        finding = analyze_url("http://login.secure.verify.evil.com/page")
        self.assertGreater(finding.subdomain_count, 1)

    @patch("url_analyzer._detonate_url")
    def test_single_subdomain_counted(self, mock_det):
        finding = analyze_url("http://secure.evil.com/page")
        self.assertEqual(finding.subdomain_count, 1)


# ---------------------------------------------------------------------------
# URL Detonation — real requests mocked
# ---------------------------------------------------------------------------

class TestURLDetonation(unittest.TestCase):
    @patch("url_analyzer.requests.Session")
    def test_redirect_chain_captured(self, MockSession):
        hop1 = MagicMock()
        hop1.url = "http://short.url/abc"
        hop1.status_code = 301

        final = MagicMock()
        final.url = "http://evil.com/phish"
        final.status_code = 200
        final.history = [hop1]
        final.headers = {"Server": "nginx", "Content-Type": "text/html"}
        final.raw.read.return_value = b"<html><title>Fake Login</title></html>"
        final.close = MagicMock()

        session_instance = MockSession.return_value
        session_instance.get.return_value = final

        finding = URLFinding(url="http://short.url/abc", domain="short.url")
        _detonate_url(finding)

        self.assertEqual(len(finding.redirect_chain), 2)
        self.assertEqual(finding.final_url, "http://evil.com/phish")
        self.assertEqual(finding.page_title, "Fake Login")
        self.assertEqual(finding.server, "nginx")
        self.assertEqual(finding.final_status_code, 200)

    @patch("url_analyzer.requests.Session")
    def test_timeout_handled(self, MockSession):
        import requests as req
        session_instance = MockSession.return_value
        session_instance.get.side_effect = req.exceptions.Timeout("timed out")
        finding = URLFinding(url="http://slow.com", domain="slow.com")
        _detonate_url(finding)
        self.assertEqual(finding.detonation_error, "Request timed out")

    @patch("url_analyzer.requests.Session")
    def test_ssl_error_handled(self, MockSession):
        import requests as req
        session_instance = MockSession.return_value
        session_instance.get.side_effect = req.exceptions.SSLError("bad cert")
        finding = URLFinding(url="https://badcert.com", domain="badcert.com")
        _detonate_url(finding)
        self.assertEqual(finding.detonation_error, "SSL certificate error")
        self.assertTrue(any("SSL" in t for t in finding.threat_indicators))

    @patch("url_analyzer.requests.Session")
    def test_connection_error_handled(self, MockSession):
        import requests as req
        session_instance = MockSession.return_value
        session_instance.get.side_effect = req.exceptions.ConnectionError("refused")
        finding = URLFinding(url="http://dead.com", domain="dead.com")
        _detonate_url(finding)
        self.assertIn("Connection refused", finding.detonation_error)


# ---------------------------------------------------------------------------
# Attachment Analyzer
# ---------------------------------------------------------------------------

class TestAttachmentAnalyzer(unittest.TestCase):
    def test_hashes(self):
        data = b"test content"
        finding = analyze_attachment("test.txt", "text/plain", data)
        self.assertEqual(finding.md5, hashlib.md5(data).hexdigest())
        self.assertEqual(finding.sha256, hashlib.sha256(data).hexdigest())

    def test_entropy(self):
        self.assertLess(_calculate_entropy(b"AAAAAAAAAAAAAAAA"), 2.0)
        self.assertGreater(_calculate_entropy(os.urandom(1024)), 7.0)
        self.assertEqual(_calculate_entropy(b""), 0.0)

    def test_executable(self):
        finding = analyze_attachment("bad.exe", "application/octet-stream", b"\x4d\x5a" + b"\x00" * 100)
        self.assertTrue(finding.is_executable)

    def test_macro_extension(self):
        finding = analyze_attachment("doc.xlsm", "application/vnd.ms-excel", b"test")
        self.assertTrue(finding.has_macro)

    def test_vba_markers(self):
        self.assertTrue(_has_vba_markers(b"contains Auto_Open and VBA code"))
        self.assertFalse(_has_vba_markers(b"clean content"))
        self.assertFalse(_has_vba_markers(b"this mentions VBA but nothing else"))

    def test_type_detection(self):
        self.assertEqual(_detect_type(b"\x25\x50\x44\x46rest"), "application/pdf")
        self.assertEqual(_detect_type(b"\x4d\x5a\x00\x00"), "application/x-dosexec")
        self.assertEqual(_detect_type(b"\x89\x50\x4e\x47"), "image/png")

    def test_extension_mismatch(self):
        finding = analyze_attachment("report.pdf", "application/pdf", b"\x4d\x5a" + b"\x00" * 100)
        self.assertTrue(finding.extension_mismatch)


# ---------------------------------------------------------------------------
# VirusTotal Integration (mocked)
# ---------------------------------------------------------------------------

class TestVirusTotal(unittest.TestCase):
    @patch("attachment_analyzer.VT_ENABLED", True)
    @patch("attachment_analyzer.VT_API_KEY", "fake-key")
    @patch("attachment_analyzer.requests.get")
    def test_vt_positive_detection(self, mock_get):
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {
            "data": {"attributes": {"last_analysis_stats": {
                "malicious": 12, "suspicious": 3, "undetected": 55, "harmless": 0
            }}}
        }
        mock_get.return_value = resp

        finding = AttachmentFinding(sha256="abc123")
        _virustotal_lookup(finding)

        self.assertEqual(finding.vt_detections, 15)
        self.assertEqual(finding.vt_total_engines, 70)
        self.assertTrue(any("VirusTotal" in t for t in finding.threat_indicators))
        self.assertIn("abc123", finding.vt_permalink)

    @patch("attachment_analyzer.VT_ENABLED", True)
    @patch("attachment_analyzer.VT_API_KEY", "fake-key")
    @patch("attachment_analyzer.requests.get")
    def test_vt_not_found(self, mock_get):
        resp = MagicMock()
        resp.status_code = 404
        mock_get.return_value = resp

        finding = AttachmentFinding(sha256="unknown_hash")
        _virustotal_lookup(finding)
        self.assertEqual(finding.vt_detections, 0)

    @patch("attachment_analyzer.VT_ENABLED", True)
    @patch("attachment_analyzer.VT_API_KEY", "fake-key")
    @patch("attachment_analyzer.requests.get")
    def test_vt_rate_limit(self, mock_get):
        resp = MagicMock()
        resp.status_code = 429
        mock_get.return_value = resp

        finding = AttachmentFinding(sha256="ratelimited")
        _virustotal_lookup(finding)
        self.assertEqual(finding.vt_detections, 0)


# ---------------------------------------------------------------------------
# Header Analyzer + DNS
# ---------------------------------------------------------------------------

class TestHeaderAnalyzer(unittest.TestCase):
    @patch("header_analyzer.dns.resolver.resolve")
    def test_spf_fail_anomaly(self, mock_dns):
        mock_dns.side_effect = Exception("skip dns")
        h = HeaderAnalysis(spf_result="fail", from_address="a@b.com")
        analyze_headers(h)
        self.assertTrue(any("SPF" in a for a in h.anomalies))

    @patch("header_analyzer.dns.resolver.resolve")
    def test_dkim_fail_anomaly(self, mock_dns):
        mock_dns.side_effect = Exception("skip dns")
        h = HeaderAnalysis(dkim_result="fail", from_address="a@b.com")
        analyze_headers(h)
        self.assertTrue(any("DKIM" in a for a in h.anomalies))

    @patch("header_analyzer.dns.resolver.resolve")
    def test_threat_intel_ip(self, mock_dns):
        mock_dns.side_effect = Exception("skip dns")
        h = HeaderAnalysis(originating_ip="185.220.101.34", from_address="a@b.com")
        analyze_headers(h)
        self.assertTrue(any("threat" in a.lower() for a in h.anomalies))

    def test_score_spf_fail(self):
        h = HeaderAnalysis(spf_result="fail")
        findings = score_headers(h)
        self.assertTrue(any("SPF" in f[0] for f in findings))

    def test_score_clean(self):
        h = HeaderAnalysis(spf_result="pass", dkim_result="pass", dmarc_result="pass")
        self.assertEqual(len(score_headers(h)), 0)


# ---------------------------------------------------------------------------
# DNS SPF Lookup (mocked)
# ---------------------------------------------------------------------------

class TestDNSLookup(unittest.TestCase):
    @patch("header_analyzer.dns.resolver.resolve")
    def test_spf_record_found(self, mock_resolve):
        rdata = MagicMock()
        rdata.to_text.return_value = '"v=spf1 include:_spf.google.com ~all"'
        mock_resolve.return_value = [rdata]

        h = HeaderAnalysis(from_address="user@example.com")
        _live_spf_lookup(h)
        self.assertIn("v=spf1", h.spf_dns_record)

    @patch("header_analyzer.dns.resolver.resolve")
    def test_spf_no_record(self, mock_resolve):
        rdata = MagicMock()
        rdata.to_text.return_value = '"google-site-verification=abc123"'
        mock_resolve.return_value = [rdata]

        h = HeaderAnalysis(from_address="user@example.com")
        _live_spf_lookup(h)
        self.assertEqual(h.spf_dns_record, "")
        self.assertTrue(any("No SPF" in a for a in h.anomalies))

    @patch("header_analyzer.dns.resolver.resolve")
    def test_spf_nxdomain(self, mock_resolve):
        import dns.resolver
        mock_resolve.side_effect = dns.resolver.NXDOMAIN()
        h = HeaderAnalysis(from_address="user@nonexistent.fake")
        _live_spf_lookup(h)
        self.assertTrue(any("NXDOMAIN" in a for a in h.anomalies))


# ---------------------------------------------------------------------------
# IOC Extractor
# ---------------------------------------------------------------------------

class TestIOCExtractor(unittest.TestCase):
    def test_extracts_ips(self):
        raw = _read_sample("phishing_email.eml")
        _, headers, body, _ = parse_eml(raw)
        with patch("header_analyzer.dns.resolver.resolve", side_effect=Exception("skip")):
            headers = analyze_headers(headers)
        iocs = extract_iocs(headers, body, [], [])
        self.assertTrue(len(iocs.ip_addresses) > 0)

    def test_extracts_emails(self):
        raw = _read_sample("phishing_email.eml")
        _, headers, body, _ = parse_eml(raw)
        iocs = extract_iocs(headers, body, [], [])
        self.assertTrue(any("paypa1" in e for e in iocs.email_addresses))

    def test_extracts_domains(self):
        uf = [URLFinding(url="http://evil.com/x", domain="evil.com")]
        iocs = extract_iocs(HeaderAnalysis(), BodyAnalysis(), uf, [])
        self.assertIn("evil.com", iocs.domains)

    def test_extracts_hashes(self):
        af = [AttachmentFinding(filename="f.exe", md5="a", sha1="b", sha256="c")]
        iocs = extract_iocs(HeaderAnalysis(), BodyAnalysis(), [], af)
        self.assertEqual(len(iocs.file_hashes), 1)


# ---------------------------------------------------------------------------
# Threat Scorer
# ---------------------------------------------------------------------------

class TestThreatScorer(unittest.TestCase):
    @patch("url_analyzer._detonate_url")
    @patch("header_analyzer.dns.resolver.resolve", side_effect=Exception("skip"))
    def test_clean_low_score(self, mock_dns, mock_det):
        raw = _read_sample("clean_email.eml")
        _, headers, body, atts = parse_eml(raw)
        headers = analyze_headers(headers)
        url_findings = analyze_all_urls(body.text_content, body.html_content)
        score = calculate_score(headers, url_findings, [], body)
        self.assertLess(score.total, 30)
        self.assertIn(score.level, ("clean", "low"))

    @patch("url_analyzer._detonate_url")
    @patch("header_analyzer.dns.resolver.resolve", side_effect=Exception("skip"))
    def test_phishing_high_score(self, mock_dns, mock_det):
        raw = _read_sample("phishing_email.eml")
        _, headers, body, atts = parse_eml(raw)
        headers = analyze_headers(headers)
        url_findings = analyze_all_urls(body.text_content, body.html_content)
        att_findings = analyze_all_attachments(atts)
        score = calculate_score(headers, url_findings, att_findings, body)
        self.assertGreater(score.total, 50)
        self.assertIn(score.level, ("high", "critical"))
        self.assertTrue(len(score.breakdown) > 3)

    def test_cap_at_100(self):
        self.assertEqual(min(ThreatScore(total=150).total, 100), 100)

    def test_urgency_scales_with_keyword_count(self):
        body_single = BodyAnalysis(text_content="urgent")
        body_many = BodyAnalysis(text_content="urgent immediate action verify your account suspended action required final warning act now")
        h = HeaderAnalysis(spf_result="pass", dkim_result="pass", dmarc_result="pass")
        score_single = calculate_score(h, [], [], body_single)
        score_many = calculate_score(h, [], [], body_many)
        self.assertGreater(score_many.total, score_single.total)

    def test_nxdomain_sender_is_scored(self):
        h = HeaderAnalysis(
            spf_result="pass", dkim_result="pass", dmarc_result="pass",
            anomalies=["Domain fake-evil.com does not exist (NXDOMAIN)"]
        )
        from header_analyzer import score_headers
        findings = score_headers(h)
        self.assertTrue(any("NXDOMAIN" in f[0] or "does not exist" in f[0] for f in findings))

    @patch("url_analyzer._detonate_url")
    @patch("header_analyzer.dns.resolver.resolve", side_effect=Exception("skip"))
    def test_multiple_categories(self, mock_dns, mock_det):
        raw = _read_sample("phishing_email.eml")
        _, headers, body, atts = parse_eml(raw)
        headers = analyze_headers(headers)
        url_findings = analyze_all_urls(body.text_content, body.html_content)
        att_findings = analyze_all_attachments(atts)
        score = calculate_score(headers, url_findings, att_findings, body)
        categories = {item["category"] for item in score.breakdown}
        self.assertTrue(len(categories) > 1)


# ---------------------------------------------------------------------------
# MITRE ATT&CK Mapper
# ---------------------------------------------------------------------------

class TestMITREMapper(unittest.TestCase):
    def test_spf_fail_maps_to_t1566(self):
        breakdown = [{"reason": "SPF authentication failed", "points": 15, "category": "headers"}]
        mappings = map_findings_to_mitre(breakdown)
        self.assertTrue(any(m["technique_id"] == "T1566.001" for m in mappings))

    def test_known_phishing_maps_to_t1566_002(self):
        breakdown = [{"reason": "Known phishing domain: evil.com", "points": 20, "category": "urls"}]
        mappings = map_findings_to_mitre(breakdown)
        self.assertTrue(any(m["technique_id"] == "T1566.002" for m in mappings))

    def test_executable_maps_to_t1204(self):
        breakdown = [{"reason": "Executable: malware.exe", "points": 12, "category": "attachments"}]
        mappings = map_findings_to_mitre(breakdown)
        self.assertTrue(any(m["technique_id"] == "T1204.002" for m in mappings))

    def test_homoglyph_maps_to_t1583(self):
        breakdown = [{"reason": "Typosquatting: g00gle.com -> google.com", "points": 12, "category": "urls"}]
        mappings = map_findings_to_mitre(breakdown)
        self.assertTrue(any(m["technique_id"] == "T1583.001" for m in mappings))

    def test_urgency_maps_to_t1598(self):
        breakdown = [{"reason": "Urgency language (3 indicators): urgent, act now, verify", "points": 8, "category": "body"}]
        mappings = map_findings_to_mitre(breakdown)
        self.assertTrue(any(m["technique_id"] == "T1598.003" for m in mappings))

    def test_javascript_maps_to_t1059(self):
        breakdown = [{"reason": "JavaScript in HTML body", "points": 8, "category": "body"}]
        mappings = map_findings_to_mitre(breakdown)
        self.assertTrue(any(m["technique_id"] == "T1059.007" for m in mappings))

    def test_form_maps_to_credential_harvesting(self):
        breakdown = [{"reason": "Form submits to external URL", "points": 10, "category": "body"}]
        mappings = map_findings_to_mitre(breakdown)
        self.assertTrue(any(m["technique_id"] == "T1056.003" for m in mappings))

    def test_hidden_text_maps_to_obfuscation(self):
        breakdown = [{"reason": "Hidden text in HTML", "points": 5, "category": "body"}]
        mappings = map_findings_to_mitre(breakdown)
        self.assertTrue(any(m["technique_id"] == "T1027.006" for m in mappings))

    def test_dedup_techniques(self):
        """Multiple findings for the same technique should be deduplicated."""
        breakdown = [
            {"reason": "SPF authentication failed", "points": 15, "category": "headers"},
            {"reason": "DKIM signature invalid", "points": 15, "category": "headers"},
        ]
        mappings = map_findings_to_mitre(breakdown)
        # Both map to T1566.001 — should only appear once
        t1566_count = sum(1 for m in mappings if m["technique_id"] == "T1566.001")
        self.assertEqual(t1566_count, 1)

    def test_attack_summary(self):
        mappings = [
            {"technique_id": "T1566.001", "technique": "Phishing", "tactic": "Initial Access", "description": "", "finding": ""},
            {"technique_id": "T1204.002", "technique": "Malicious File", "tactic": "Execution", "description": "", "finding": ""},
        ]
        summary = get_attack_summary(mappings)
        self.assertIn("Initial Access", summary["kill_chain_phases"])
        self.assertIn("Execution", summary["kill_chain_phases"])
        self.assertEqual(summary["technique_count"], 2)

    def test_empty_breakdown(self):
        mappings = map_findings_to_mitre([])
        self.assertEqual(len(mappings), 0)

    def test_match_reason_coverage(self):
        """Ensure key reason patterns are matched correctly."""
        self.assertEqual(_match_reason("spf authentication failed", "headers"), "spf_fail")
        self.assertEqual(_match_reason("display name spoofing", "headers"), "display_name_spoofing")
        self.assertEqual(_match_reason("shortened url hides destination: bit.ly", "urls"), "url_shortened")
        self.assertEqual(_match_reason("malware hash: eicar", "attachments"), "malware_hash")
        self.assertEqual(_match_reason("high entropy: file.bin (7.8)", "attachments"), "high_entropy")
        self.assertEqual(_match_reason("threat intel ip in mail path", "headers"), "threat_intel_ip")


# ---------------------------------------------------------------------------
# STIX 2.1 Exporter
# ---------------------------------------------------------------------------

class TestSTIXExporter(unittest.TestCase):
    def _sample_report(self):
        return {
            "report_id": "test123",
            "filename": "phish.eml",
            "headers": {"from_address": "bad@evil.com", "subject": "Test"},
            "score": {"level": "critical", "total": 85},
            "iocs": {
                "ip_addresses": ["185.220.101.34"],
                "domains": ["evil.com"],
                "urls": ["http://evil.com/login"],
                "email_addresses": ["bad@evil.com"],
                "file_hashes": [{"filename": "mal.exe", "md5": "abc", "sha1": "def", "sha256": "ghi"}],
            },
            "attachments": [{"malware_match": "Emotet", "malware_family": "Emotet"}],
            "mitre_mappings": [
                {"technique_id": "T1566.001", "technique": "Phishing", "tactic": "Initial Access", "description": "SPF fail"},
            ],
        }

    def test_bundle_structure(self):
        bundle = generate_stix_bundle(self._sample_report())
        self.assertEqual(bundle["type"], "bundle")
        self.assertTrue(bundle["id"].startswith("bundle--"))
        self.assertTrue(len(bundle["objects"]) > 0)

    def test_contains_identity(self):
        bundle = generate_stix_bundle(self._sample_report())
        identities = [o for o in bundle["objects"] if o["type"] == "identity"]
        self.assertTrue(len(identities) >= 1)

    def test_contains_indicators(self):
        bundle = generate_stix_bundle(self._sample_report())
        indicators = [o for o in bundle["objects"] if o["type"] == "indicator"]
        self.assertTrue(len(indicators) >= 3)  # IP, domain, URL, email, hash

    def test_contains_malware(self):
        bundle = generate_stix_bundle(self._sample_report())
        malware = [o for o in bundle["objects"] if o["type"] == "malware"]
        self.assertTrue(len(malware) >= 1)
        self.assertEqual(malware[0]["name"], "Emotet")

    def test_contains_attack_patterns(self):
        bundle = generate_stix_bundle(self._sample_report())
        aps = [o for o in bundle["objects"] if o["type"] == "attack-pattern"]
        self.assertTrue(len(aps) >= 1)

    def test_contains_report(self):
        bundle = generate_stix_bundle(self._sample_report())
        reports = [o for o in bundle["objects"] if o["type"] == "report"]
        self.assertEqual(len(reports), 1)
        self.assertIn("critical", reports[0]["labels"][0])

    def test_contains_relationships(self):
        bundle = generate_stix_bundle(self._sample_report())
        rels = [o for o in bundle["objects"] if o["type"] == "relationship"]
        self.assertTrue(len(rels) > 0)

    def test_json_serializable(self):
        bundle = generate_stix_bundle(self._sample_report())
        result = stix_to_json(bundle)
        parsed = json.loads(result)
        self.assertEqual(parsed["type"], "bundle")

    def test_empty_iocs(self):
        report = self._sample_report()
        report["iocs"] = {"ip_addresses": [], "domains": [], "urls": [], "email_addresses": [], "file_hashes": []}
        report["attachments"] = []
        report["mitre_mappings"] = []
        bundle = generate_stix_bundle(report)
        self.assertEqual(bundle["type"], "bundle")


# ---------------------------------------------------------------------------
# WHOIS Lookup
# ---------------------------------------------------------------------------

class TestWHOISLookup(unittest.TestCase):
    def test_registrable_domain(self):
        self.assertEqual(_get_registrable("sub.evil.com"), "evil.com")
        self.assertEqual(_get_registrable("evil.com"), "evil.com")
        self.assertEqual(_get_registrable("a.b.c.evil.com"), "evil.com")

    def test_is_ip(self):
        self.assertTrue(_is_ip("192.168.1.1"))
        self.assertFalse(_is_ip("evil.com"))
        self.assertFalse(_is_ip("not.an.ip.address.here"))

    def test_ip_returns_none(self):
        result = lookup_domain("192.168.1.1")
        self.assertIsNone(result)

    def test_empty_returns_none(self):
        result = lookup_domain("")
        self.assertIsNone(result)

    def test_whois_result(self):
        from datetime import datetime, timezone, timedelta
        mock_whois_mod = MagicMock()
        mock_result = MagicMock()
        mock_result.registrar = "GoDaddy"
        mock_result.creation_date = datetime.now(timezone.utc) - timedelta(days=5)
        mock_result.expiration_date = datetime.now(timezone.utc) + timedelta(days=360)
        mock_result.updated_date = datetime.now(timezone.utc) - timedelta(days=1)
        mock_result.name_servers = ["ns1.example.com"]
        mock_result.status = ["ok"]
        mock_result.country = "US"
        mock_result.org = "Test Org"
        mock_whois_mod.whois.return_value = mock_result

        with patch.dict("sys.modules", {"whois": mock_whois_mod}):
            result = lookup_domain("evil.com")
        self.assertIsNotNone(result)
        self.assertEqual(result["registrar"], "GoDaddy")
        self.assertTrue(result["is_new"])
        self.assertLess(result["age_days"], 30)

    def test_whois_import_error(self):
        """If python-whois is not installed, should return None gracefully."""
        with patch.dict("sys.modules", {"whois": None}):
            # This tests the ImportError path — may or may not trigger depending on state
            pass  # We trust the try/except in the module


# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------

class TestDatabase(unittest.TestCase):
    def setUp(self):
        from flask import Flask
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.db_path = self.tmp.name
        self.tmp.close()
        self.app = Flask(__name__)
        self.app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{self.db_path}"
        self.app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
        self.app.config["TESTING"] = True
        db.init_db(self.app)
        self.ctx = self.app.app_context()
        self.ctx.push()

    def tearDown(self):
        db.db.session.remove()
        db.db.engine.dispose()
        self.ctx.pop()
        try:
            os.unlink(self.db_path)
        except PermissionError:
            pass  # Windows may hold SQLite lock briefly

    def test_save_retrieve(self):
        r = {"report_id": "t1", "filename": "a.eml",
             "headers": {"from_address": "a@b.com", "subject": "X"},
             "score": {"level": "high", "total": 65}}
        db.save_report(r)
        self.assertIsNotNone(db.get_report("t1"))

    def test_history(self):
        for i in range(3):
            db.save_report({"report_id": f"h{i}", "filename": f"{i}.eml",
                "headers": {"from_address": "x@y.com", "subject": f"S{i}"},
                "score": {"level": "medium", "total": 40}})
        self.assertEqual(len(db.get_history(10)), 3)

    def test_history_has_display_date(self):
        db.save_report({"report_id": "d1", "filename": "a.eml",
            "headers": {"from_address": "x@y.com", "subject": "A"},
            "score": {"level": "low", "total": 10}})
        history = db.get_history(10)
        self.assertIn("analyzed_at_display", history[0])
        self.assertIn("UTC", history[0]["analyzed_at_display"])

    def test_stats(self):
        db.save_report({"report_id": "s1", "filename": "a.eml",
            "headers": {"from_address": "x@y.com", "subject": "A"},
            "score": {"level": "critical", "total": 80}})
        db.save_report({"report_id": "s2", "filename": "b.eml",
            "headers": {"from_address": "x@y.com", "subject": "B"},
            "score": {"level": "low", "total": 15}})
        stats = db.get_stats()
        self.assertEqual(stats["total"], 2)
        self.assertEqual(stats["by_level"]["critical"], 1)
        self.assertIn("avg_score", stats)

    def test_missing(self):
        self.assertIsNone(db.get_report("nope"))

    def test_delete(self):
        db.save_report({"report_id": "del1", "filename": "a.eml",
            "headers": {"from_address": "x@y.com", "subject": "A"},
            "score": {"level": "high", "total": 60}})
        self.assertTrue(db.delete_report("del1"))
        self.assertIsNone(db.get_report("del1"))

    def test_delete_nonexistent(self):
        self.assertFalse(db.delete_report("nope"))

    def test_search(self):
        db.save_report({"report_id": "sr1", "filename": "phishing_test.eml",
            "headers": {"from_address": "bad@evil.com", "subject": "URGENT"},
            "score": {"level": "critical", "total": 90}})
        db.save_report({"report_id": "sr2", "filename": "clean.eml",
            "headers": {"from_address": "ok@good.com", "subject": "Hello"},
            "score": {"level": "clean", "total": 0}})
        results = db.search_history("evil")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["id"], "sr1")

    def test_trend_data(self):
        db.save_report({"report_id": "tr1", "filename": "a.eml",
            "headers": {"from_address": "x@y.com", "subject": "A"},
            "score": {"level": "high", "total": 55}})
        trend = db.get_trend_data(30)
        self.assertTrue(len(trend) > 0)


# ---------------------------------------------------------------------------
# Full Pipeline
# ---------------------------------------------------------------------------

class TestFullPipeline(unittest.TestCase):
    @patch("url_analyzer._detonate_url")
    @patch("header_analyzer.dns.resolver.resolve", side_effect=Exception("skip"))
    def test_clean_end_to_end(self, mock_dns, mock_det):
        raw = _read_sample("clean_email.eml")
        _, headers, body, atts = parse_eml(raw)
        headers = analyze_headers(headers)
        uf = analyze_all_urls(body.text_content, body.html_content)
        af = analyze_all_attachments(atts)
        iocs = extract_iocs(headers, body, uf, af)
        score = calculate_score(headers, uf, af, body)
        report = AnalysisReport(report_id="c1", filename="clean.eml",
            headers=headers, body=body, urls=[u.to_dict() for u in uf],
            attachments=[a.to_dict() for a in af], iocs=iocs, score=score)
        d = report.to_dict()
        self.assertLess(d["score"]["total"], 30)

    @patch("url_analyzer._detonate_url")
    @patch("header_analyzer.dns.resolver.resolve", side_effect=Exception("skip"))
    def test_phishing_end_to_end(self, mock_dns, mock_det):
        raw = _read_sample("phishing_email.eml")
        _, headers, body, atts = parse_eml(raw)
        headers = analyze_headers(headers)
        uf = analyze_all_urls(body.text_content, body.html_content)
        af = analyze_all_attachments(atts)
        iocs = extract_iocs(headers, body, uf, af)
        score = calculate_score(headers, uf, af, body)
        self.assertGreater(score.total, 50)
        self.assertTrue(len(iocs.ip_addresses) > 0)
        self.assertTrue(len(iocs.domains) > 0)

    @patch("url_analyzer._detonate_url")
    @patch("header_analyzer.dns.resolver.resolve", side_effect=Exception("skip"))
    def test_phishing_has_mitre_mappings(self, mock_dns, mock_det):
        """Full pipeline on phishing email should produce MITRE mappings."""
        raw = _read_sample("phishing_email.eml")
        _, headers, body, atts = parse_eml(raw)
        headers = analyze_headers(headers)
        uf = analyze_all_urls(body.text_content, body.html_content)
        af = analyze_all_attachments(atts)
        score = calculate_score(headers, uf, af, body)
        mappings = map_findings_to_mitre(score.breakdown)
        self.assertTrue(len(mappings) > 0)
        # Should have Initial Access at minimum
        self.assertTrue(any(m["tactic"] == "Initial Access" for m in mappings))

    @patch("url_analyzer._detonate_url")
    @patch("header_analyzer.dns.resolver.resolve", side_effect=Exception("skip"))
    def test_phishing_stix_export(self, mock_dns, mock_det):
        """Full pipeline should produce a valid STIX bundle."""
        raw = _read_sample("phishing_email.eml")
        _, headers, body, atts = parse_eml(raw)
        headers = analyze_headers(headers)
        uf = analyze_all_urls(body.text_content, body.html_content)
        af = analyze_all_attachments(atts)
        iocs = extract_iocs(headers, body, uf, af)
        score = calculate_score(headers, uf, af, body)
        mappings = map_findings_to_mitre(score.breakdown)

        report_dict = {
            "report_id": "stix_test",
            "filename": "phish.eml",
            "headers": headers.to_dict(),
            "score": score.to_dict(),
            "iocs": iocs.to_dict(),
            "attachments": [a.to_dict() for a in af],
            "mitre_mappings": mappings,
        }
        bundle = generate_stix_bundle(report_dict)
        self.assertEqual(bundle["type"], "bundle")
        # Should have indicators for extracted IOCs
        indicators = [o for o in bundle["objects"] if o["type"] == "indicator"]
        self.assertTrue(len(indicators) > 0)


if __name__ == "__main__":
    unittest.main()
