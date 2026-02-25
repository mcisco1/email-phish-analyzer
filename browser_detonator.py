"""
Headless browser URL detonation using Playwright.

Renders URLs in a sandboxed Chromium instance to detect:
- JavaScript-based redirects (window.location, document.location)
- Meta refresh tags
- Iframe-based attacks (nested phishing content)
- Credential harvesting forms (login forms with password fields)
- Client-side page title and final URL after JS execution

Captures a screenshot of the rendered page for analyst review.
"""

import os
import re
import uuid
import logging
from urllib.parse import urlparse

from config import (
    BROWSER_DETONATION_ENABLED, BROWSER_DETONATION_TIMEOUT,
    BROWSER_SCREENSHOT_DIR, BROWSER_VIEWPORT_WIDTH, BROWSER_VIEWPORT_HEIGHT,
    BROWSER_MAX_DETONATIONS,
)

log = logging.getLogger(__name__)

# Track whether Playwright is available
_playwright_available = None


def _check_playwright():
    """Lazily check if Playwright and Chromium are installed."""
    global _playwright_available
    if _playwright_available is not None:
        return _playwright_available
    try:
        from playwright.sync_api import sync_playwright
        # Quick check that chromium binary exists
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            browser.close()
        _playwright_available = True
    except Exception as e:
        log.warning("Playwright not available: %s — browser detonation disabled", e)
        _playwright_available = False
    return _playwright_available


def detonate_url_browser(url):
    """
    Render a URL in a headless Chromium browser.

    Returns a dict with:
        screenshot_path: str - path to PNG screenshot
        browser_final_url: str - URL after JS execution
        browser_page_title: str - page title after rendering
        js_redirects: list[dict] - detected JS-based redirects
        meta_refresh_detected: bool
        meta_refresh_url: str
        iframes_detected: list[dict] - iframe src/sandbox info
        has_credential_form: bool - password input detected
        browser_error: str - error message if detonation failed
    """
    result = {
        "screenshot_path": "",
        "browser_final_url": "",
        "browser_page_title": "",
        "js_redirects": [],
        "meta_refresh_detected": False,
        "meta_refresh_url": "",
        "iframes_detected": [],
        "has_credential_form": False,
        "browser_error": "",
    }

    if not BROWSER_DETONATION_ENABLED:
        return result

    if not _check_playwright():
        result["browser_error"] = "Playwright not installed"
        return result

    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        result["browser_error"] = "Playwright not installed"
        return result

    os.makedirs(BROWSER_SCREENSHOT_DIR, exist_ok=True)

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(
                headless=True,
                args=[
                    "--no-sandbox",
                    "--disable-setuid-sandbox",
                    "--disable-dev-shm-usage",
                    "--disable-gpu",
                    "--disable-extensions",
                    "--disable-background-networking",
                    "--disable-sync",
                    "--no-first-run",
                    "--single-process",
                ],
            )
            context = browser.new_context(
                viewport={"width": BROWSER_VIEWPORT_WIDTH, "height": BROWSER_VIEWPORT_HEIGHT},
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                           "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                ignore_https_errors=True,
                java_script_enabled=True,
            )

            # Track navigation events caused by JS redirects
            js_redirects = []
            page = context.new_page()

            def _on_navigation(frame):
                if frame == page.main_frame:
                    js_redirects.append({
                        "url": frame.url,
                        "name": frame.name or "main",
                    })

            page.on("framenavigated", _on_navigation)

            try:
                # Navigate to the URL with a timeout
                response = page.goto(
                    url,
                    wait_until="networkidle",
                    timeout=BROWSER_DETONATION_TIMEOUT,
                )

                # Wait a bit more for JS to settle
                page.wait_for_timeout(2000)

                # Final URL after all redirects and JS execution
                result["browser_final_url"] = page.url
                result["browser_page_title"] = page.title() or ""

                # Capture JS redirects (filter out the initial navigation)
                original_domain = urlparse(url).hostname or ""
                for redir in js_redirects:
                    redir_domain = urlparse(redir["url"]).hostname or ""
                    if redir_domain and redir_domain != original_domain:
                        result["js_redirects"].append(redir)

                # Detect meta refresh tags
                meta_refreshes = page.eval_on_selector_all(
                    'meta[http-equiv="refresh"]',
                    """elements => elements.map(el => ({
                        content: el.getAttribute('content') || ''
                    }))"""
                )
                if meta_refreshes:
                    result["meta_refresh_detected"] = True
                    for meta in meta_refreshes:
                        content = meta.get("content", "")
                        url_match = re.search(r'url\s*=\s*["\']?([^"\';\s]+)', content, re.IGNORECASE)
                        if url_match:
                            result["meta_refresh_url"] = url_match.group(1)

                # Detect iframes
                iframes = page.eval_on_selector_all(
                    "iframe",
                    """elements => elements.map(el => ({
                        src: el.src || '',
                        sandbox: el.getAttribute('sandbox') || '',
                        width: el.offsetWidth,
                        height: el.offsetHeight,
                        visible: el.offsetWidth > 0 && el.offsetHeight > 0
                    }))"""
                )
                for iframe in iframes:
                    if iframe.get("src"):
                        iframe_domain = urlparse(iframe["src"]).hostname or ""
                        result["iframes_detected"].append({
                            "src": iframe["src"],
                            "domain": iframe_domain,
                            "sandbox": iframe.get("sandbox", ""),
                            "visible": iframe.get("visible", False),
                            "size": f"{iframe.get('width', 0)}x{iframe.get('height', 0)}",
                        })

                # Detect credential harvesting forms
                has_password = page.eval_on_selector_all(
                    'input[type="password"]',
                    "elements => elements.length"
                )
                if has_password and has_password > 0:
                    result["has_credential_form"] = True

                # Also check for login-like forms more broadly
                if not result["has_credential_form"]:
                    form_indicators = page.evaluate("""() => {
                        const forms = document.querySelectorAll('form');
                        for (const form of forms) {
                            const action = (form.action || '').toLowerCase();
                            const html = form.innerHTML.toLowerCase();
                            if (html.includes('password') || html.includes('login') ||
                                html.includes('sign in') || html.includes('credential')) {
                                return true;
                            }
                        }
                        return false;
                    }""")
                    if form_indicators:
                        result["has_credential_form"] = True

                # Take screenshot
                screenshot_filename = f"{uuid.uuid4().hex[:12]}.png"
                screenshot_path = os.path.join(BROWSER_SCREENSHOT_DIR, screenshot_filename)
                page.screenshot(path=screenshot_path, full_page=False)
                result["screenshot_path"] = screenshot_filename

            except Exception as nav_err:
                error_msg = str(nav_err)[:200]
                result["browser_error"] = error_msg
                log.warning("Browser detonation navigation error for %s: %s", url, error_msg)

                # Still try to capture a screenshot of whatever loaded
                try:
                    screenshot_filename = f"{uuid.uuid4().hex[:12]}_error.png"
                    screenshot_path = os.path.join(BROWSER_SCREENSHOT_DIR, screenshot_filename)
                    page.screenshot(path=screenshot_path, full_page=False)
                    result["screenshot_path"] = screenshot_filename
                except Exception:
                    pass

            finally:
                page.close()
                context.close()
                browser.close()

    except Exception as e:
        result["browser_error"] = str(e)[:200]
        log.error("Browser detonation failed for %s: %s", url, e)

    return result


def detonate_urls_browser(urls):
    """
    Detonate a batch of URLs with the headless browser.

    Args:
        urls: list of URL strings

    Returns:
        dict mapping url -> detonation result
    """
    if not BROWSER_DETONATION_ENABLED:
        return {}

    if not _check_playwright():
        return {}

    results = {}
    # Limit the number of browser detonations (resource-intensive)
    for url in urls[:BROWSER_MAX_DETONATIONS]:
        try:
            results[url] = detonate_url_browser(url)
        except Exception as e:
            log.error("Browser detonation batch error for %s: %s", url, e)
            results[url] = {"browser_error": str(e)[:200]}

    return results
