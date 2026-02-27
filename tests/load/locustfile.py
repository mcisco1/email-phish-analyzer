"""
Load testing for PhishGuard using Locust.

Usage:
    # Web UI mode:
    locust -f tests/load/locustfile.py --host=http://localhost:5000

    # Headless mode (CI):
    locust -f tests/load/locustfile.py --headless -u 50 -r 5 --run-time 2m \
           --host=http://localhost:5000

See tests/load/README.md for baseline capacity numbers.
"""

import os
from locust import HttpUser, task, between, events


SAMPLE_EML = (
    b"From: sender@example.com\r\n"
    b"To: recipient@company.com\r\n"
    b"Subject: Load Test Email\r\n"
    b"Date: Mon, 15 Jan 2025 10:00:00 +0000\r\n"
    b"MIME-Version: 1.0\r\n"
    b"Content-Type: text/plain; charset=utf-8\r\n"
    b"\r\n"
    b"This is a load testing email.\r\n"
)

# Credentials for test user (create this user before running load tests)
TEST_EMAIL = os.environ.get("LOAD_TEST_EMAIL", "loadtest@phishguard.local")
TEST_PASSWORD = os.environ.get("LOAD_TEST_PASSWORD", "LoadTest123!")


class PhishGuardUser(HttpUser):
    """Simulated PhishGuard user for load testing."""

    wait_time = between(1, 3)
    report_id = None

    def on_start(self):
        """Log in before starting tasks."""
        resp = self.client.post("/login", data={
            "email": TEST_EMAIL,
            "password": TEST_PASSWORD,
        }, catch_response=True)
        if resp.status_code not in (200, 302):
            resp.failure(f"Login failed: {resp.status_code}")

    @task(5)
    def view_dashboard(self):
        """GET /dashboard — most common action."""
        self.client.get("/dashboard", name="/dashboard")

    @task(3)
    def view_history(self):
        """GET /history — browse past analyses."""
        self.client.get("/history", name="/history")

    @task(3)
    def upload_and_analyze(self):
        """POST /upload — upload an .eml for synchronous analysis."""
        resp = self.client.post("/upload",
                                files={"file": ("loadtest.eml", SAMPLE_EML, "message/rfc822")},
                                name="/upload",
                                catch_response=True)
        if resp.status_code == 200:
            # Try to extract report_id from redirect or page
            if "/report/" in resp.url:
                self.report_id = resp.url.split("/report/")[-1].split("?")[0]
        elif resp.status_code in (302, 303):
            pass  # redirect is OK
        else:
            resp.failure(f"Upload failed: {resp.status_code}")

    @task(2)
    def view_report(self):
        """GET /report/<id> — view an analysis report."""
        if self.report_id:
            self.client.get(f"/report/{self.report_id}", name="/report/[id]")
        else:
            # View a random report from history
            self.client.get("/history", name="/history (fallback)")

    @task(2)
    def api_analyze(self):
        """POST /api/analyze — API-based analysis with auth header."""
        # Get JWT token
        token_resp = self.client.post("/api/auth/token",
                                      json={"email": TEST_EMAIL, "password": TEST_PASSWORD},
                                      name="/api/auth/token")
        if token_resp.status_code != 200:
            return

        token = token_resp.json().get("access_token", "")
        self.client.post("/api/analyze",
                         files={"file": ("api_test.eml", SAMPLE_EML, "message/rfc822")},
                         headers={"Authorization": f"Bearer {token}"},
                         name="/api/analyze",
                         catch_response=True)

    @task(1)
    def export_csv(self):
        """GET /export/csv — export history as CSV."""
        self.client.get("/export/csv", name="/export/csv")

    @task(1)
    def api_stats(self):
        """GET /api/stats — dashboard statistics."""
        token_resp = self.client.post("/api/auth/token",
                                      json={"email": TEST_EMAIL, "password": TEST_PASSWORD},
                                      name="/api/auth/token")
        if token_resp.status_code != 200:
            return

        token = token_resp.json().get("access_token", "")
        self.client.get("/api/stats",
                        headers={"Authorization": f"Bearer {token}"},
                        name="/api/stats")
