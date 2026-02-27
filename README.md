# PhishGuard

**Automated phishing email analysis platform** with ML classification, NLP content analysis, headless browser detonation, YARA scanning, multi-feed threat intelligence, MITRE ATT&CK mapping, a guided onboarding flow, and a Chrome browser extension.

Upload a `.eml` file, forward a suspicious email to a shared inbox, or right-click an email in Gmail/Outlook — and receive a comprehensive threat report with confidence scoring, IOC extraction, STIX 2.1 export, and downloadable PDF documentation.

---

## Table of Contents

- [Features](#features)
- [Analysis Pipeline](#analysis-pipeline)
- [Architecture](#architecture)
- [Getting Started](#getting-started)
- [Browser Extension](#browser-extension)
- [Email Forwarding (IMAP)](#email-forwarding-imap)
- [Configuration](#configuration)
- [API Reference](#api-reference)
- [Dashboard](#dashboard)
- [Team & Organization](#team--organization)
- [Notifications](#notifications)
- [Testing](#testing)
- [Custom YARA Rules](#custom-yara-rules)
- [Project Structure](#project-structure)
- [License](#license)

---

## Features

- **Multi-stage analysis pipeline** — header forensics, URL detonation, attachment scanning, ML classification, NLP analysis, browser detonation, YARA rules, threat intel feeds
- **Guided onboarding** — step-by-step wizard with sample email analysis and interactive report walkthrough with plain-English explanations of security terms
- **SOC dashboard** — area charts with gradient fills, threat velocity KPI, time period selector (7d/30d/90d), SOC narrative summary, quick action buttons
- **Browser extension** — Chrome Manifest V3 extension with right-click analysis, toolbar button injection for Gmail and Outlook Web, popup with recent results, badge notifications
- **Email forwarding** — IMAP inbox polling for automated analysis of forwarded suspicious emails with auto-reply results
- **Team management** — organizations with roles (owner/admin/member), per-member analysis stats, team activity feed, team CSV export
- **Notifications** — email alerts, Slack webhooks, in-app notifications, configurable thresholds, weekly summary reports, test notification button
- **Professional PDF reports** — cover page with branding, executive summary for management, risk visualization bar, recommended actions, full technical findings, Inter + JetBrains Mono fonts
- **Export formats** — IOC JSON, STIX 2.1, PDF report, CSV bulk export
- **Authentication** — OAuth 2.0 (Google, Microsoft), local auth with bcrypt, JWT API tokens, RBAC (admin/analyst/viewer)

---

## Analysis Pipeline

PhishGuard processes each email through a multi-stage pipeline. Every stage runs independently and fails gracefully — if a service is unavailable, the remaining stages continue unaffected.

### Header Forensics

Extracts the full Received chain, originating IP, and authentication results (SPF, DKIM, DMARC) from email headers. Performs live DNS lookups via `dnspython` to retrieve the actual SPF and DMARC TXT records for the sender's domain. Detects Reply-To mismatches, Return-Path forgery, display name spoofing against known brands, and NXDOMAIN sender domains.

### URL Analysis

Extracts every URL from plaintext and HTML body content, including defanged formats (`hxxp://`, `[.]`). Makes real HTTP requests to follow redirect chains, captures each hop's status code, and records the final URL, page title, and server header. Checks URLs against a known-phishing domain list, detects IP-based URLs, shortened links, suspicious TLDs, and typosquatting via homoglyph comparison against major brands.

### IDN Homograph Detection

Detects Internationalized Domain Name homograph attacks where attackers register domains using Cyrillic, Greek, Armenian, or other Unicode look-alike characters (e.g., Cyrillic 'a' in apple.com). Identifies mixed-script domains, decodes punycode, and maps confusable characters back to Latin equivalents to detect visual impersonation.

### Headless Browser Detonation

Renders URLs in a sandboxed Chromium instance via Playwright. Detects JavaScript-based redirects (`window.location`, `document.location`), meta refresh tags, iframe-based attacks, and credential harvesting forms (password input fields). Captures screenshots of the final rendered page for analyst review. Compares browser-rendered final URL against HTTP redirect final URL to detect JS-only redirects invisible to static analysis.

### HTML Similarity Analysis

Compares rendered phishing pages against 15 known brand login page signatures (Google, Microsoft, Apple, PayPal, Amazon, Netflix, Chase, Wells Fargo, Bank of America, DHL, FedEx, Dropbox, DocuSign, LinkedIn, Facebook). Calculates structural similarity scores based on page titles, form fields, CSS markers, DOM patterns, and brand-specific terms.

### Recursive URL Analysis

When a URL redirects through multiple hops, every intermediate domain in the chain is analyzed independently. Each hop domain is checked against phishing domain lists, suspicious TLDs, IP-based URLs, and homoglyph detection. This catches multi-stage phishing where intermediate redirectors are themselves compromised.

### Attachment Analysis

Hashes every attachment (MD5, SHA1, SHA256). Calculates Shannon entropy. Identifies file type by magic bytes and flags mismatches against the declared extension. Detects VBA macro markers and double-extension attacks. Checks hashes against a local watchlist and optionally against the VirusTotal API.

### YARA Rule Scanning

Scans all attachments against 12 bundled YARA rules: credential harvesting HTML, obfuscated JavaScript, data exfiltration forms, VBA auto-exec macros, VBA downloaders, OLE embedded executables, PDF JavaScript exploits, PDF embedded files, suspicious scripts (PowerShell/WScript), brand impersonation HTML, zip bomb indicators, and RTF exploits. Custom rules can be added to `yara_rules/`.

### ML Classification

Random Forest + Logistic Regression ensemble classifier (scikit-learn `VotingClassifier`) that extracts 38 features across four categories:

- **Header features (10):** SPF/DKIM/DMARC results, anomalies, forgery indicators
- **URL features (12):** Phishing domains, IP-based URLs, shorteners, homoglyphs, redirect depth
- **Attachment features (8):** Executables, macros, entropy, VirusTotal hits, YARA matches
- **Body features (8):** Urgency keywords, JavaScript, external forms, hidden text, content length

Returns a phishing confidence score (0-100%) alongside the rule-based scoring. The model auto-trains on first use and persists to `ml_models/`.

### NLP Body Analysis

Analyzes email text against 51 linguistic patterns across five categories:

| Category | Patterns | Examples |
|---|---|---|
| Urgency | 19 | Time pressure, deadlines, account suspension |
| Threat | 8 | Legal action, account termination, data loss |
| Impersonation | 8 | Authority claims, official department language |
| Grammar anomalies | 9 | ESL patterns, excessive formality, unusual phrasing |
| Social engineering | 7 | Prize claims, secrecy demands, emotional manipulation |

Returns per-category scores (0-100) and a weighted composite score.

### MITRE ATT&CK Mapping

49 finding-to-technique mappings covering 28 unique ATT&CK sub-techniques across 8 tactics: Reconnaissance, Resource Development, Initial Access, Execution, Persistence, Defense Evasion, Credential Access, and Command & Control. Every mapping includes a specific detection recommendation for SOC analysts.

### Multi-Feed Threat Intelligence

Enriches extracted IOCs against five external feeds:

| Feed | Data | Auth |
|---|---|---|
| AbuseIPDB | IP reputation scoring | API key (free tier) |
| URLhaus | Known malicious URL/domain lookup | None |
| PhishTank | Verified phishing URL database | API key (optional) |
| AlienVault OTX | IOC enrichment with pulse counts | API key (free tier) |
| VirusTotal | File hash + URL reputation | API key (free tier) |

All feeds are optional. Thread-safe rate limiting prevents API quota exhaustion.

### Threat Scoring

Weighted scoring engine with 55 indicator weights across headers, URLs, attachments, body content, ML classification, NLP analysis, HTML similarity, IDN homographs, and threat intelligence feeds. Score caps at 100.

| Level | Score | Interpretation |
|---|---|---|
| Critical | 70-100 | Almost certainly phishing |
| High | 50-69 | Strong phishing indicators |
| Medium | 30-49 | Suspicious, requires review |
| Low | 10-29 | Minor anomalies |
| Clean | 0-9 | No threats detected |

### Export Formats

- **IOC JSON** — Aggregated IPs, domains, URLs, email addresses, and file hashes
- **STIX 2.1** — Standards-compliant threat intelligence bundle for SIEM/SOAR ingestion (Splunk, QRadar, Sentinel, MISP, OpenCTI)
- **PDF Report** — Professional incident documentation with cover page, executive summary, risk visualization, recommended actions, and full technical findings
- **CSV** — Bulk export of all historical analysis data

---

## Architecture

```
                            .eml upload / forwarded email / browser extension
                                │
                ┌───────────────┼───────────────┐
                │               │               │
          Header Analysis   URL Analysis   Attachment Analysis
          (SPF/DKIM/DMARC   (HTTP detonation,   (Hashing, entropy,
           DNS lookups,       homoglyphs,         magic bytes, VBA,
           forgery checks)    IDN detection)      YARA scanning)
                │               │               │
                │        ┌──────┴──────┐        │
                │        │             │        │
                │   Browser        Recursive    │
                │   Detonation     URL Check    │
                │   (Playwright)   (per hop)    │
                │        │             │        │
                │        └──────┬──────┘        │
                │               │               │
                └───────────────┼───────────────┘
                                │
              ┌─────────────────┼─────────────────┐
              │                 │                 │
        NLP Analysis     ML Classification   HTML Similarity
        (51 patterns,     (38 features,       (15 brand
         5 categories)     ensemble model)      signatures)
              │                 │                 │
              └─────────────────┼─────────────────┘
                                │
                    ┌───────────┼───────────┐
                    │           │           │
              IOC Extraction  Threat     MITRE ATT&CK
              (IPs, domains,  Intel      Mapping
               URLs, hashes)  Feeds      (49 mappings)
                    │           │           │
                    └───────────┼───────────┘
                                │
                         Threat Scoring
                        (55 weighted indicators)
                                │
              ┌─────────┬──────┼──────┬─────────┐
              │         │      │      │         │
           STIX 2.1   PDF   WHOIS  Notify   Auto-Reply
           Export    Report  Enrich (email/   (IMAP
                                    slack)    forward)
```

---

## Getting Started

### Prerequisites

- Python 3.10+
- pip

### Quick Start

```bash
git clone <repository-url>
cd email-phish-analyzer
pip install -r requirements.txt
playwright install chromium
python app.py
```

Open `http://127.0.0.1:5000`. Default admin credentials: `admin@phishguard.local` / `changeme`.

### Docker Compose (Production)

```bash
cp .env.example .env
# Edit .env with your secrets and API keys
docker compose up -d
```

This starts five services:

| Service | Description | Port |
|---|---|---|
| web | Flask + Gunicorn | 5000 |
| worker | Celery background analysis with Playwright | — |
| postgres | PostgreSQL 16 | 5432 |
| redis | Redis 7 (caching, task queue, rate limiting) | 6379 |
| minio | S3-compatible object storage | 9000 |

---

## Browser Extension

The Chrome extension (Manifest V3) lets users analyze emails without leaving Gmail or Outlook Web.

### Installation

1. Open `chrome://extensions/` in Chrome
2. Enable "Developer mode"
3. Click "Load unpacked" and select the `extension/` directory

### Features

- **Right-click analysis** — select text or right-click on any email page to analyze with PhishGuard
- **Toolbar button** — injected "Analyze" button appears in Gmail and Outlook email toolbars
- **Popup** — upload `.eml` files, view last 3 analysis results, configure server connection
- **Badge notifications** — extension icon shows threat score with color-coded badge
- **Browser notifications** — desktop alerts for high/critical threats

### Configuration

Click the PhishGuard extension icon > settings link, or right-click the icon > "Options". Enter your PhishGuard server URL and API key (JWT token or legacy API key).

---

## Email Forwarding (IMAP)

PhishGuard can monitor a shared mailbox via IMAP. Users forward suspicious emails to the configured address (e.g., `analyze@yourcompany.com`), and PhishGuard automatically:

1. Polls the inbox on a configurable interval (default: 60 seconds)
2. Extracts the forwarded email (supports message/rfc822 attachments, .eml attachments, and inline forwards)
3. Runs the full analysis pipeline
4. Optionally sends an email reply with the results and a link to the full report

### Setup

Add IMAP credentials to your `.env` file:

```
IMAP_HOST=imap.gmail.com
IMAP_PORT=993
IMAP_USER=analyze@yourcompany.com
IMAP_PASS=your-app-password
IMAP_FOLDER=INBOX
IMAP_USE_SSL=true
IMAP_POLL_INTERVAL=60
IMAP_AUTO_REPLY=true
```

IMAP polling runs as a Celery Beat scheduled task. Ensure the Celery worker and beat scheduler are running:

```bash
celery -A celery_worker.celery_app worker --beat --loglevel=info
```

---

## Configuration

Copy `.env.example` to `.env` and configure. All analysis modules are enabled by default and degrade gracefully when optional dependencies or API keys are absent.

### Key Variables

```
FLASK_ENV=development                # development | staging | production
DATABASE_URL=postgresql://...        # leave empty for SQLite in development
PHISH_SECRET=<random-64-char-hex>    # Flask secret key
JWT_SECRET_KEY=<random-64-char-hex>  # JWT signing key
```

### Optional Integrations

```
VT_API_KEY=                          # VirusTotal file hash + URL reputation
ABUSEIPDB_API_KEY=                   # AbuseIPDB IP reputation
OTX_API_KEY=                         # AlienVault OTX IOC enrichment
PHISHTANK_API_KEY=                   # PhishTank verified phishing URLs
GOOGLE_CLIENT_ID=                    # OAuth 2.0 Google login
MICROSOFT_CLIENT_ID=                 # OAuth 2.0 Microsoft login
```

### Notification Config

```
SMTP_HOST=smtp.gmail.com             # SMTP server for email alerts
SMTP_PORT=587
SMTP_USER=alerts@yourcompany.com
SMTP_PASS=your-app-password
SMTP_FROM=phishguard@yourcompany.com
SLACK_WEBHOOK_URL=                   # Default Slack webhook for alerts
```

### Feature Toggles

```
BROWSER_DETONATION_ENABLED=true      # Playwright headless browser
YARA_ENABLED=true                    # YARA rule scanning
ML_CLASSIFIER_ENABLED=true           # ML phishing classification
NLP_ANALYSIS_ENABLED=true            # NLP body analysis
HTML_SIMILARITY_ENABLED=true         # Brand impersonation detection
THREAT_INTEL_ENABLED=false           # External threat intel feeds
```

---

## Authentication & Security

- **OAuth 2.0** — Google and Microsoft SSO
- **Local auth** — Email/password registration with bcrypt hashing
- **JWT API auth** — Access/refresh token flow with revocation
- **Role-based access control** — Admin, analyst, and viewer roles with RBAC decorators
- **CSRF protection** — Every form includes a CSRF token
- **Security headers** — Content Security Policy, X-Frame-Options, X-Content-Type-Options, X-XSS-Protection, HSTS (production)
- **Input validation** — Multi-step `.eml` upload validation (extension, path traversal, empty file, size limit, binary signatures, magic byte detection, RFC 5322 sanity)
- **Rate limiting** — Per-user and per-IP rate limits on API endpoints
- **Audit logging** — Every action (analyze, delete, export) logged with user, IP, and timestamp

---

## API Reference

All endpoints require JWT Bearer token or API key authentication.

### Authentication

```
POST   /api/auth/token              Get JWT access + refresh tokens
POST   /api/auth/refresh            Refresh access token
POST   /api/auth/revoke             Revoke refresh token
```

### Analysis

```
POST   /api/analyze                 Upload .eml file for analysis
POST   /api/extension/analyze       Extension analysis endpoint (JSON body)
GET    /api/job/<task_id>/status    Poll background job status
GET    /api/report/<id>             Full analysis report (JSON)
GET    /api/history                 All past analyses
DELETE /api/report/<id>             Delete an analysis
```

### Export

```
GET    /api/iocs/<id>               IOC export (JSON)
GET    /api/stix/<id>               STIX 2.1 bundle
GET    /api/mitre/<id>              MITRE ATT&CK mappings
GET    /api/export/csv              Bulk CSV export
```

### Analytics

```
GET    /api/stats                   Aggregate statistics
GET    /api/trend?days=30           Daily trend data
```

### Admin

```
POST   /api/admin/imap/test         Test IMAP connectivity (admin only)
GET    /api/admin/imap/status        IMAP polling status
```

---

## Dashboard

The SOC dashboard provides an at-a-glance view of your email security posture:

- **Time period selector** — toggle between 7-day, 30-day, and 90-day views
- **SOC narrative** — plain-English summary of the current threat landscape ("12 emails analyzed this week, 3 critical threats detected, up 50% from last week")
- **Threat velocity** — trend indicator showing whether threats are increasing, decreasing, or stable
- **Area chart** — gradient-filled trend chart showing daily threat levels over time
- **Doughnut chart** — threat level distribution breakdown
- **Quick actions** — buttons for New Analysis, Export CSV, View History

---

## Team & Organization

PhishGuard supports multi-tenant organizations:

- **Roles** — owner, admin, member with scoped permissions
- **Org-scoped analysis** — admins see all org analyses, members see their own
- **Activity feed** — org admins see recent team actions (analyze, delete, export, login)
- **Member stats** — per-member analysis counts and critical threat counts
- **Team export** — CSV export of all organization analyses

---

## Notifications

- **Email alerts** — professional HTML emails for critical/high/medium threats with recommended actions
- **Slack webhooks** — Block Kit formatted alerts with threat details and report links
- **In-app notifications** — real-time notification center with unread badges
- **Configurable thresholds** — set minimum score for alerts, choose which levels trigger email/Slack
- **Weekly summary** — automated Monday morning digest with threat breakdown, trend comparison, and inline charts
- **Test button** — verify notification delivery from the preferences page

---

## Testing

```bash
pip install pytest
python -m pytest tests/ -v
```

The test suite includes 92 tests covering email parsing, URL analysis, HTTP detonation, attachment analysis, VirusTotal integration, header forensics, DNS lookups, IOC extraction, threat scoring, MITRE ATT&CK mapping, STIX 2.1 export, WHOIS lookup, database operations, and full end-to-end pipeline validation.

---

## Custom YARA Rules

Add `.yar` or `.yara` files to the `yara_rules/` directory. Rules are automatically compiled and loaded on startup.

```yara
rule Custom_Detection
{
    meta:
        description = "What this rule detects"
        severity = "critical"
        category = "phishing"
    strings:
        $pattern = "suspicious_string"
    condition:
        $pattern
}
```

Supported severity values: `critical`, `high`, `medium`, `low`
Supported categories: `phishing`, `macro`, `exploit`, `script`, `embedded`, `evasion`

---

## Project Structure

```
email-phish-analyzer/
│
├── app.py                    Flask routes, middleware, pipeline orchestration
├── config.py                 Feature flags, scoring weights, watchlists, env config
├── models.py                 Dataclasses for all analysis entities
├── database.py               SQLAlchemy ORM models (PostgreSQL / SQLite)
├── auth.py                   OAuth 2.0, JWT, RBAC, Flask-Login integration
├── storage.py                S3 / MinIO file storage client
├── tasks.py                  Celery background tasks + Beat schedule
├── celery_worker.py          Celery worker entry point
├── helpers.py                Shared utility functions
│
├── email_parser.py           .eml parsing, header/body extraction
├── header_analyzer.py        SPF/DKIM/DMARC validation, live DNS lookups
├── url_analyzer.py           HTTP detonation, heuristics, IDN homograph, recursive analysis
├── browser_detonator.py      Playwright headless browser detonation
├── attachment_analyzer.py    File hashing, entropy, magic bytes, VBA, VirusTotal, YARA
├── yara_scanner.py           YARA rule compilation and scanning engine
│
├── ml_classifier.py          Random Forest + Logistic Regression ensemble classifier
├── nlp_analyzer.py           Urgency, threat, impersonation, grammar, social engineering
├── html_similarity.py        Brand impersonation detection (15 brand signatures)
├── threat_intel.py           AbuseIPDB, URLhaus, PhishTank, AlienVault OTX, VirusTotal
│
├── ioc_extractor.py          IOC aggregation (IPs, domains, URLs, hashes, emails)
├── threat_scorer.py          Weighted scoring engine (55 indicators)
├── mitre_mapper.py           MITRE ATT&CK mapping (49 mappings, 28 techniques)
├── stix_exporter.py          STIX 2.1 bundle generation
├── whois_lookup.py           WHOIS domain intelligence
├── report_generator.py       Professional PDF report generation
│
├── imap_poller.py            IMAP inbox polling for forwarded email analysis
├── notifications.py          Email, Slack, and in-app notification dispatch
│
├── extension/                Chrome browser extension (Manifest V3)
│   ├── manifest.json         Extension manifest
│   ├── background.js         Service worker, context menu, API calls
│   ├── content.js            Gmail/Outlook email extraction + toolbar injection
│   ├── content.css           Injected button + overlay styles
│   ├── popup.html/js         Extension popup UI
│   ├── options.html/js       Extension settings page
│   └── icons/                Extension icons (16/48/128)
│
├── static/
│   ├── css/style.css         Main stylesheet (dark theme)
│   ├── js/dashboard.js       Dashboard area + doughnut charts
│   ├── js/tooltips.js        Security term tooltips + guided walkthrough
│   ├── js/utils.js           Shared frontend utilities
│   └── fonts/                Inter + JetBrains Mono (PDF reports)
│
├── templates/                Jinja2 templates
│   ├── dashboard.html        SOC dashboard with period selector + narrative
│   ├── report.html           Analysis report with data-tip tooltips
│   ├── onboarding.html       6-step guided onboarding wizard
│   ├── team.html             Team management + activity feed
│   ├── notifications.html    Notification preferences + test button
│   ├── admin.html            Admin panel with IMAP status
│   └── ...                   Login, register, history, etc.
│
├── ml_models/                Trained ML model storage
├── yara_rules/               YARA rule files (.yar)
├── screenshots/              Browser detonation screenshots
├── tests/                    Test suite with sample .eml files
│
├── Dockerfile                Production container (Python 3.12, Playwright, YARA)
├── docker-compose.yml        Full stack: web, worker, postgres, redis, minio
├── requirements.txt          Python dependencies
├── .env.example              Environment variable reference
└── LICENSE                   MIT License
```

---

## License

MIT License. See [LICENSE](LICENSE) for details.
