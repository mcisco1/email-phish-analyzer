# PhishGuard — Phishing Email Analyzer

Upload a `.eml` file. Get a threat report with a score, MITRE ATT&CK mapping, and exportable IOCs.

## What It Does

Parses raw email files and runs them through a multi-stage analysis pipeline:

**Header Analysis** — Extracts the Received chain, originating IP, and authentication results (SPF/DKIM/DMARC) from the email headers. Performs live DNS lookups via `dnspython` to pull the actual SPF and DMARC TXT records for the sender's domain. Flags Reply-To mismatches, Return-Path forgery, and display name spoofing against known brands.

**URL Analysis** — Extracts every URL from both the plaintext and HTML body, including defanged URLs (`hxxp://`, `[.]`). Makes real HTTP requests (`requests.get` with `allow_redirects=True`) to follow redirect chains, captures each hop's status code, grabs the final URL, page title, and server header. Checks against a known-phishing domain list, detects IP-based URLs, shortened links, suspicious TLDs, and typosquatting via homoglyph comparison against major brands. URL detonation runs concurrently via `ThreadPoolExecutor` for performance.

**Attachment Analysis** — Hashes every attachment (MD5, SHA1, SHA256). Calculates Shannon entropy. Identifies file type by magic bytes and flags mismatches against the declared extension. Detects VBA macro markers and double-extension attacks. Checks hashes against a local watchlist and optionally against the **VirusTotal API** (set `VT_API_KEY` env var to enable; free tier, 4 req/min).

**MITRE ATT&CK Mapping** — Every finding is mapped to the corresponding MITRE ATT&CK technique (T-codes), tactic, and kill chain phase. The report shows which ATT&CK techniques were observed, with clickable links to the MITRE website. This enables SOC analysts to immediately classify the threat in standard terminology.

**Threat Scoring** — Weighted scoring across 25+ indicators. Caps at 100. Five levels: Critical (70+), High (50-69), Medium (30-49), Low (10-29), Clean (0-9).

**IOC Extraction** — Aggregates all IPs, domains, URLs, email addresses, and file hashes into a structured JSON export.

**STIX 2.1 Export** — One-click export of all IOCs and findings as a STIX 2.1 JSON bundle, ready for ingestion into SIEM/SOAR platforms (Splunk, QRadar, Sentinel, MISP, OpenCTI).

**WHOIS Domain Intelligence** — Performs WHOIS lookups on extracted domains to surface domain age, registrar, and registration date. Domains under 30 days old are flagged as suspicious — a high-confidence phishing indicator used by enterprise email gateways.

**PDF Report Generation** — Download professional PDF reports with full analysis details, suitable for incident documentation and management briefings.

**Dashboard & Analytics** — Interactive dashboard with Chart.js visualizations showing threat distribution, 30-day trends, and key metrics.

## Setup

```bash
pip install -r requirements.txt
python app.py
```

Open `http://127.0.0.1:5000`.

Optional:
```bash
export VT_API_KEY=your_virustotal_key_here   # enables hash reputation lookups
export PHISH_SECRET=your_session_secret       # defaults to random per-process
export PHISH_API_KEY=your_api_key_here        # require X-API-Key header on API routes
```

## Docker

```bash
docker build -t phishguard .
docker run -p 5000:5000 -e VT_API_KEY=your_key phishguard
```

## Tests

```bash
pip install pytest
python -m pytest tests/ -v
```

## API

```
POST /api/analyze              multipart form, field: eml_file
GET  /api/report/<id>          full report JSON
GET  /api/history              all past analyses
GET  /api/iocs/<id>            IOC export for SIEM ingestion
GET  /api/stix/<id>            STIX 2.1 bundle export
GET  /api/mitre/<id>           MITRE ATT&CK mappings
GET  /api/stats                aggregate statistics
GET  /api/trend?days=30        daily trend data
GET  /api/export/csv           bulk CSV export of all analyses
DELETE /api/report/<id>        delete an analysis
```

When `PHISH_API_KEY` is set, all API endpoints require `X-API-Key: <key>` header.

Rate limiting: 200 requests/hour per IP (configurable via `flask-limiter`).

## Features

| Feature | Description |
|---|---|
| Multi-stage analysis | Header forensics, URL detonation, attachment sandboxing |
| Live DNS lookups | SPF + DMARC TXT record queries via `dnspython` |
| MITRE ATT&CK mapping | Findings mapped to T-codes with kill chain visualization |
| STIX 2.1 export | Industry-standard threat intel format for SIEM/SOAR |
| WHOIS enrichment | Domain age, registrar, and creation date intelligence |
| VirusTotal integration | Hash reputation lookup (optional, free tier) |
| PDF reports | Downloadable incident documentation |
| Dashboard analytics | Chart.js visualizations with trend data |
| Bulk upload | Analyze multiple .eml files at once |
| Search & filter | Search analysis history by filename, sender, or subject |
| CSV export | Bulk export of all analysis data |
| API key auth | Optional authentication on API endpoints |
| Rate limiting | Per-IP rate limiting via flask-limiter |
| Concurrent analysis | ThreadPoolExecutor for parallel URL/attachment analysis |
| Defanged URL support | Handles `hxxp://` and `[.]` notation |
| Typosquatting detection | Homoglyph analysis against known brands |

## Limitations

- URL detonation follows real HTTP requests rather than rendering pages in a headless browser sandbox.
- SPF/DKIM/DMARC results are parsed from the `Authentication-Results` header and cross-referenced with live DNS lookups. The SPF check does not independently re-evaluate the originating IP against the SPF record.
- Attachment analysis relies on hash matching, entropy calculation, magic byte detection, and VirusTotal integration rather than YARA rules.
- The web UI does not include user authentication — deploy behind a reverse proxy with auth if needed.
- Uses SQLite for storage. For high-throughput deployments, swap to PostgreSQL or another production database.

## Structure

```
├── app.py                  Flask routes + pipeline orchestration
├── config.py               Weights, thresholds, watchlists, env config
├── models.py               Dataclasses for all analysis entities
├── email_parser.py         .eml parsing + header/body extraction
├── header_analyzer.py      Auth validation + live DNS (SPF/DMARC)
├── url_analyzer.py         Real HTTP detonation + heuristics
├── attachment_analyzer.py  Hashing + entropy + VirusTotal API
├── ioc_extractor.py        IOC aggregation
├── threat_scorer.py        Weighted scoring engine
├── mitre_mapper.py         MITRE ATT&CK technique mapping
├── stix_exporter.py        STIX 2.1 bundle generation
├── whois_lookup.py         WHOIS domain intelligence
├── report_generator.py     PDF report generation
├── database.py             SQLite storage + search + analytics
├── Dockerfile
├── .gitignore
├── requirements.txt
├── templates/              Web UI (index, report, history, dashboard)
├── static/                 CSS + JS
└── tests/                  Unit tests + sample .eml files
```
