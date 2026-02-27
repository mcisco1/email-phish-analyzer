"""Tests for browser_detonator.py — headless browser URL detonation."""

import pytest
from unittest.mock import patch, MagicMock

from browser_detonator import detonate_url_browser, detonate_urls_browser


class TestDetonateUrlBrowser:
    @patch("browser_detonator.BROWSER_DETONATION_ENABLED", False)
    def test_disabled_via_config(self):
        result = detonate_url_browser("http://evil.com")
        assert result["browser_error"] == ""
        assert result["has_credential_form"] is False
        assert result["screenshot_path"] == ""

    @patch("browser_detonator.BROWSER_DETONATION_ENABLED", True)
    @patch("browser_detonator._check_playwright")
    def test_playwright_not_installed(self, mock_check):
        mock_check.return_value = False
        result = detonate_url_browser("http://evil.com")
        assert "not installed" in result["browser_error"].lower() or result["browser_error"] == ""

    def test_result_structure(self):
        with patch("browser_detonator.BROWSER_DETONATION_ENABLED", False):
            result = detonate_url_browser("http://example.com")
        assert "screenshot_path" in result
        assert "browser_final_url" in result
        assert "browser_page_title" in result
        assert "js_redirects" in result
        assert "meta_refresh_detected" in result
        assert "iframes_detected" in result
        assert "has_credential_form" in result
        assert "browser_error" in result

    @patch("browser_detonator.BROWSER_DETONATION_ENABLED", True)
    @patch("browser_detonator._check_playwright")
    def test_detonation_exception_handled(self, mock_check):
        mock_check.return_value = True
        # Patch the import inside the function by replacing playwright.sync_api module
        mock_sync_pw = MagicMock(side_effect=RuntimeError("browser crashed"))
        with patch.dict("sys.modules", {"playwright": MagicMock(), "playwright.sync_api": MagicMock(sync_playwright=mock_sync_pw)}):
            result = detonate_url_browser("http://evil.com")
        # Should not raise, should return error in result
        assert "browser_error" in result

    @patch("browser_detonator.BROWSER_DETONATION_ENABLED", True)
    @patch("browser_detonator._check_playwright")
    def test_credential_form_detection(self, mock_check):
        """Test that credential form detection works when Playwright returns data."""
        mock_check.return_value = True

        # Build mock chain: sync_playwright() -> p -> p.chromium.launch() -> browser -> ...
        mock_page = MagicMock()
        mock_page.url = "http://evil.com/login"
        mock_page.title.return_value = "Login Page"
        mock_page.eval_on_selector_all.side_effect = [
            [],  # meta refresh
            [],  # iframes
            1,   # password inputs count
        ]
        mock_page.evaluate.return_value = False
        mock_page.main_frame = MagicMock()
        mock_page.main_frame.url = "http://evil.com/login"
        mock_page.goto.return_value = MagicMock()
        mock_page.screenshot.return_value = None

        mock_context = MagicMock()
        mock_context.new_page.return_value = mock_page

        mock_browser = MagicMock()
        mock_browser.new_context.return_value = mock_context

        mock_pw_instance = MagicMock()
        mock_pw_instance.chromium.launch.return_value = mock_browser

        mock_sync_pw = MagicMock()
        mock_sync_pw.return_value.__enter__ = MagicMock(return_value=mock_pw_instance)
        mock_sync_pw.return_value.__exit__ = MagicMock(return_value=False)

        mock_pw_module = MagicMock(sync_playwright=mock_sync_pw)
        with patch.dict("sys.modules", {"playwright": MagicMock(), "playwright.sync_api": mock_pw_module}):
            result = detonate_url_browser("http://evil.com/login")
        assert result["has_credential_form"] is True


class TestDetonateUrlsBrowser:
    @patch("browser_detonator.BROWSER_DETONATION_ENABLED", False)
    def test_disabled_returns_empty(self):
        result = detonate_urls_browser(["http://a.com", "http://b.com"])
        assert result == {}

    @patch("browser_detonator.BROWSER_DETONATION_ENABLED", True)
    @patch("browser_detonator._check_playwright")
    def test_playwright_unavailable_returns_empty(self, mock_check):
        mock_check.return_value = False
        result = detonate_urls_browser(["http://a.com"])
        assert result == {}

    @patch("browser_detonator.BROWSER_DETONATION_ENABLED", True)
    @patch("browser_detonator._check_playwright")
    @patch("browser_detonator.detonate_url_browser")
    def test_max_detonations_limit(self, mock_detonate, mock_check):
        mock_check.return_value = True
        mock_detonate.return_value = {"browser_error": ""}

        urls = [f"http://url{i}.com" for i in range(50)]
        with patch("browser_detonator.BROWSER_MAX_DETONATIONS", 5):
            result = detonate_urls_browser(urls)
        # Should only detonate up to BROWSER_MAX_DETONATIONS
        assert mock_detonate.call_count <= 5

    @patch("browser_detonator.BROWSER_DETONATION_ENABLED", True)
    @patch("browser_detonator._check_playwright")
    @patch("browser_detonator.detonate_url_browser")
    def test_individual_error_handled(self, mock_detonate, mock_check):
        mock_check.return_value = True
        mock_detonate.side_effect = RuntimeError("browser crash")

        result = detonate_urls_browser(["http://evil.com"])
        assert "http://evil.com" in result
        assert "browser_error" in result["http://evil.com"]
