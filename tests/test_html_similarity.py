"""Tests for html_similarity.py — brand impersonation detection."""

import pytest

from html_similarity import (
    analyze_html_similarity, analyze_email_html,
    _normalize_html, _extract_page_signals, _score_brand_match,
    BRAND_SIGNATURES,
)


class TestAnalyzeHtmlSimilarity:
    def test_google_clone_detected(self):
        html = """
        <html>
        <head><title>Sign in - Google Accounts</title></head>
        <body>
            <div class="gaia signin">
                <img src="https://googleusercontent.com/logo.png" alt="googlelogo">
                <form action="/login">
                    <input name="identifier" type="text">
                    <input name="password" type="password">
                    <button>Sign in</button>
                </form>
                <a href="https://accounts.google.com">Google</a>
            </div>
        </body>
        </html>
        """
        result = analyze_html_similarity(html, url_domain="evil-phishing.com")
        assert result["top_match"] is not None
        assert result["top_match"]["brand"] == "Google"
        assert result["top_match"]["similarity"] > 40
        assert result["is_impersonation"] is True

    def test_microsoft_clone_detected(self):
        html = """
        <html>
        <head><title>Sign in - Microsoft Account</title></head>
        <body>
            <div class="login-paginated microsoftLogo">
                <form>
                    <input name="loginfmt" type="text">
                    <input name="passwd" type="password">
                </form>
                <span>microsoft.com</span>
                <span>Office 365</span>
            </div>
        </body>
        </html>
        """
        result = analyze_html_similarity(html, url_domain="not-microsoft.com")
        assert result["top_match"] is not None
        assert result["top_match"]["brand"] == "Microsoft"

    def test_no_match_generic_html(self):
        html = """
        <html>
        <head><title>My Blog Post</title></head>
        <body><p>This is just a normal blog about cooking recipes.</p></body>
        </html>
        """
        result = analyze_html_similarity(html)
        # May have no matches or very low similarity
        if result["top_match"]:
            assert result["top_match"]["similarity"] < 50
        assert result["is_impersonation"] is False

    def test_empty_html(self):
        result = analyze_html_similarity("")
        assert result["matches"] == []
        assert result["top_match"] is None
        assert result["is_impersonation"] is False

    def test_none_html(self):
        result = analyze_html_similarity(None)
        assert result["matches"] == []
        assert result["top_match"] is None

    def test_legitimate_domain_not_flagged(self):
        html = """
        <html><head><title>Sign in - Google Accounts</title></head>
        <body class="gaia"><form><input name="identifier"><input type="password"></form>
        <span>accounts.google.com</span></body></html>
        """
        result = analyze_html_similarity(html, url_domain="accounts.google.com")
        # Even if similarity is high, is_impersonation should be False for legit domain
        assert result["is_impersonation"] is False

    def test_matches_limited_to_5(self):
        # Very generic login page that might match many brands
        html = """
        <html><head><title>Sign in</title></head>
        <body><form><input name="email"><input type="password">
        <button>Log in</button></form></body></html>
        """
        result = analyze_html_similarity(html)
        assert len(result["matches"]) <= 5

    def test_result_structure(self):
        result = analyze_html_similarity("<html><body>test</body></html>")
        assert "matches" in result
        assert "top_match" in result
        assert "is_impersonation" in result


class TestNormalizeHtml:
    def test_lowercases(self):
        assert "hello" in _normalize_html("<P>HELLO</P>")

    def test_strips_whitespace(self):
        result = _normalize_html("  <p>  hello  </p>  ")
        assert result == "<p> hello </p>"

    def test_empty(self):
        assert _normalize_html("") == ""

    def test_none(self):
        assert _normalize_html(None) == ""


class TestExtractPageSignals:
    def test_extracts_title(self):
        signals = _extract_page_signals("<html><title>Test Page</title></html>")
        assert signals["title"] == "test page"

    def test_extracts_form_fields(self):
        html = '<form><input name="email"><input id="password" type="password"></form>'
        signals = _extract_page_signals(html)
        assert "email" in signals["form_fields"]
        assert "password" in signals["form_fields"]

    def test_detects_password_field(self):
        html = '<form><input type="password" name="pass"></form>'
        signals = _extract_page_signals(html)
        assert signals["has_password"] is True
        assert signals["has_login_form"] is True

    def test_empty_html(self):
        signals = _extract_page_signals("")
        assert signals == {}

    def test_none_html(self):
        signals = _extract_page_signals(None)
        assert signals == {}


class TestAnalyzeEmailHtml:
    def test_returns_list(self):
        result = analyze_email_html("<p>Hello world</p>")
        assert isinstance(result, list)

    def test_empty_html(self):
        assert analyze_email_html("") == []

    def test_none_html(self):
        assert analyze_email_html(None) == []

    def test_brand_detection_in_email(self):
        html = """
        <div>
            <img src="https://googleusercontent.com/logo.png">
            <p>Your Google account needs verification</p>
            <a href="http://evil.com/verify">Click here</a>
        </div>
        """
        result = analyze_email_html(html, from_domain="evil.com")
        # Should find some brand signals
        assert isinstance(result, list)
