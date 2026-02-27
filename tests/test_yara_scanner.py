"""Tests for yara_scanner.py — YARA rule scanning engine."""

import pytest
from unittest.mock import patch, MagicMock

from yara_scanner import scan_data, scan_attachment, get_rule_stats


class TestScanData:
    @patch("yara_scanner.YARA_ENABLED", False)
    def test_disabled_via_config(self):
        result = scan_data(b"test data", "test.bin")
        assert result == []

    @patch("yara_scanner.YARA_ENABLED", True)
    @patch("yara_scanner._load_rules")
    def test_no_rules_loaded(self, mock_load):
        mock_load.return_value = None
        result = scan_data(b"test data", "test.bin")
        assert result == []

    @patch("yara_scanner.YARA_ENABLED", True)
    @patch("yara_scanner._load_rules")
    def test_clean_data_no_matches(self, mock_load):
        mock_rules = MagicMock()
        mock_rules.match.return_value = []
        mock_load.return_value = mock_rules

        result = scan_data(b"clean normal data", "clean.txt")
        assert result == []

    @patch("yara_scanner.YARA_ENABLED", True)
    @patch("yara_scanner._load_rules")
    def test_match_found(self, mock_load):
        mock_match = MagicMock()
        mock_match.rule = "PhishingDoc"
        mock_match.namespace = "phishing_rules"
        mock_match.meta = {
            "description": "Phishing document detected",
            "severity": "high",
            "category": "phishing",
        }
        mock_match.tags = ["phishing", "credential"]
        mock_match.strings = []

        mock_rules = MagicMock()
        mock_rules.match.return_value = [mock_match]
        mock_load.return_value = mock_rules

        result = scan_data(b"malicious content", "evil.doc")
        assert len(result) == 1
        assert result[0]["rule"] == "PhishingDoc"
        assert result[0]["severity"] == "high"
        assert result[0]["category"] == "phishing"

    @patch("yara_scanner.YARA_ENABLED", True)
    @patch("yara_scanner._load_rules")
    def test_empty_data(self, mock_load):
        mock_rules = MagicMock()
        mock_rules.match.return_value = []
        mock_load.return_value = mock_rules

        result = scan_data(b"", "empty.bin")
        assert result == []

    @patch("yara_scanner.YARA_ENABLED", True)
    @patch("yara_scanner._load_rules")
    def test_scan_exception_handled(self, mock_load):
        mock_rules = MagicMock()
        mock_rules.match.side_effect = RuntimeError("scan timeout")
        mock_load.return_value = mock_rules

        result = scan_data(b"data", "test.bin")
        assert result == []  # Should return empty, not raise

    @patch("yara_scanner.YARA_ENABLED", True)
    @patch("yara_scanner._load_rules")
    def test_multiple_matches(self, mock_load):
        match1 = MagicMock(rule="Rule1", namespace="ns1",
                           meta={"severity": "critical"}, tags=[], strings=[])
        match2 = MagicMock(rule="Rule2", namespace="ns2",
                           meta={"severity": "medium"}, tags=["macro"], strings=[])

        mock_rules = MagicMock()
        mock_rules.match.return_value = [match1, match2]
        mock_load.return_value = mock_rules

        result = scan_data(b"bad data", "evil.xlsm")
        assert len(result) == 2

    @patch("yara_scanner.YARA_ENABLED", True)
    @patch("yara_scanner._load_rules")
    def test_result_structure(self, mock_load):
        mock_match = MagicMock()
        mock_match.rule = "TestRule"
        mock_match.namespace = "test_ns"
        mock_match.meta = {"description": "Test", "severity": "low", "category": "test"}
        mock_match.tags = ["tag1"]
        mock_match.strings = []

        mock_rules = MagicMock()
        mock_rules.match.return_value = [mock_match]
        mock_load.return_value = mock_rules

        result = scan_data(b"data", "test.bin")
        match = result[0]
        assert "rule" in match
        assert "namespace" in match
        assert "description" in match
        assert "severity" in match
        assert "category" in match
        assert "tags" in match
        assert "strings_matched" in match


class TestScanAttachment:
    @patch("yara_scanner.YARA_ENABLED", False)
    def test_wrapper_calls_scan_data(self):
        result = scan_attachment("file.bin", b"data")
        assert result == []


class TestGetRuleStats:
    @patch("yara_scanner._load_rules")
    def test_no_rules(self, mock_load):
        mock_load.return_value = None
        stats = get_rule_stats()
        assert stats["available"] is False
        assert stats["rule_count"] == 0

    @patch("yara_scanner._load_rules")
    @patch("os.path.isdir")
    @patch("os.listdir")
    def test_with_rules(self, mock_listdir, mock_isdir, mock_load):
        mock_load.return_value = iter([1, 2, 3])  # 3 rules
        mock_isdir.return_value = True
        mock_listdir.return_value = ["rule1.yar", "rule2.yara", "readme.txt"]

        stats = get_rule_stats()
        assert stats["available"] is True
        assert len(stats["files"]) == 2  # only .yar/.yara


class TestCheckYara:
    @patch("yara_scanner._yara_available", None)
    def test_yara_import_fails_gracefully(self):
        import yara_scanner
        yara_scanner._yara_available = None

        with patch.dict("sys.modules", {"yara": None}):
            with patch("builtins.__import__", side_effect=ImportError("no yara")):
                # Reset cached value
                yara_scanner._yara_available = None
                result = yara_scanner._check_yara()
                assert result is False
