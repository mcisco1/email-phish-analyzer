"""Tests for nlp_analyzer.py — NLP-based phishing detection."""

import pytest

from nlp_analyzer import analyze_body, _prepare_text, _empty_result


class TestAnalyzeBody:
    def test_high_urgency_text(self):
        text = (
            "Your account will be suspended immediately! "
            "Verify your account within 24 hours or face permanent deletion. "
            "Unauthorized access has been detected."
        )
        result = analyze_body(text)
        assert result["urgency_score"] > 0
        assert len(result["findings"]) > 0
        assert result["overall_nlp_score"] > 0

    def test_clean_business_text(self):
        text = (
            "Hi team, just a reminder that our weekly standup is at 10am tomorrow. "
            "Please prepare your status updates and bring any blockers to discuss. "
            "The conference room has been booked. See you there."
        )
        result = analyze_body(text)
        assert result["urgency_score"] < 30
        assert result["threat_score"] == 0

    def test_empty_text(self):
        result = analyze_body("")
        assert result == _empty_result()
        assert result["urgency_score"] == 0
        assert result["summary"] == "No email body text to analyze."

    def test_none_text(self):
        result = analyze_body(None)
        assert result == _empty_result()

    def test_very_short_text(self):
        result = analyze_body("Hi")
        assert result == _empty_result()

    def test_impersonation_patterns(self):
        text = (
            "Dear valued customer, this is an official notification from the "
            "Customer Support Team. We have detected unusual activity on your "
            "account. Dear sir, please confirm your identity immediately."
        )
        result = analyze_body(text)
        assert result["impersonation_score"] > 0
        assert any(f["category"] == "impersonation" for f in result["findings"])

    def test_social_engineering_markers(self):
        text = (
            "Congratulations! You have been selected to receive a million dollar "
            "prize! Please provide your gift card details. Do not share this "
            "with anyone. This is confidential."
        )
        result = analyze_body(text)
        assert result["social_engineering_score"] > 0
        assert any(f["category"] == "social_engineering" for f in result["findings"])

    def test_threat_language(self):
        text = (
            "Legal action will be taken against you. Your data will be "
            "permanently deleted. You have been reported to law enforcement. "
            "Criminal charges are pending."
        )
        result = analyze_body(text)
        assert result["threat_score"] > 0
        assert any(f["category"] == "threat" for f in result["findings"])

    def test_grammar_anomalies(self):
        text = (
            "Kindly verify your account details. Please to be clicking the "
            "link below. Do the needful and revert back to us. "
            "URGENT URGENT URGENT!!!! ACT NOW!!!!"
        )
        result = analyze_body(text)
        assert result["grammar_score"] > 0

    def test_unicode_text(self):
        text = "お知らせ: アカウントの確認が必要です。This is a normal notification about your account."
        result = analyze_body(text)
        # Should not crash, should return valid result
        assert isinstance(result["urgency_score"], int)
        assert isinstance(result["findings"], list)

    def test_long_text_performance(self):
        text = "Normal business email content. " * 3000  # ~100KB
        result = analyze_body(text)
        assert isinstance(result, dict)
        assert "urgency_score" in result

    def test_html_content_analyzed(self):
        result = analyze_body(
            "",
            html_content="<p>Verify your account <a href='http://evil.com'>immediately</a></p>",
            subject="Urgent: Account Suspended"
        )
        assert result["urgency_score"] > 0

    def test_subject_analyzed(self):
        result = analyze_body(
            "Normal body text that is long enough to analyze properly.",
            subject="URGENT: Your account has been compromised"
        )
        assert result["urgency_score"] > 0

    def test_result_structure(self):
        result = analyze_body("Some text that is long enough to not be empty result for analysis.")
        assert "urgency_score" in result
        assert "threat_score" in result
        assert "impersonation_score" in result
        assert "grammar_score" in result
        assert "social_engineering_score" in result
        assert "overall_nlp_score" in result
        assert "findings" in result
        assert "summary" in result

    def test_scores_capped_at_100(self):
        # Extreme phishing text with every pattern
        text = (
            "URGENT! Your account will be suspended immediately! "
            "Unauthorized access detected! Verify your account within 1 hour! "
            "Failure to respond will result in permanent deletion! "
            "Act now! Don't delay! Time is running out! "
            "Click here immediately! Final warning!"
        ) * 5
        result = analyze_body(text)
        assert result["urgency_score"] <= 100
        assert result["threat_score"] <= 100
        assert result["overall_nlp_score"] <= 100


class TestPrepareText:
    def test_combines_subject_and_body(self):
        result = _prepare_text("body text", "", "Subject Line")
        assert "Subject Line" in result
        assert "body text" in result

    def test_strips_html_tags(self):
        result = _prepare_text("", "<p>Hello <b>world</b></p>", "")
        assert "<p>" not in result
        assert "Hello" in result
        assert "world" in result

    def test_all_empty(self):
        result = _prepare_text("", "", "")
        assert result == ""

    def test_none_inputs(self):
        result = _prepare_text(None, None, None)
        assert result == ""
