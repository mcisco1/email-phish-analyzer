from dataclasses import dataclass, field, asdict
from typing import Optional


@dataclass
class HeaderAnalysis:
    from_address: str = ""
    from_display: str = ""
    reply_to: str = ""
    return_path: str = ""
    to_addresses: list = field(default_factory=list)
    cc_addresses: list = field(default_factory=list)
    subject: str = ""
    date: str = ""
    message_id: str = ""
    received_chain: list = field(default_factory=list)
    originating_ip: Optional[str] = None
    spf_result: str = "none"
    spf_dns_record: str = ""
    dkim_result: str = "none"
    dmarc_result: str = "none"
    dmarc_dns_record: str = ""
    auth_results_raw: str = ""
    x_mailer: str = ""
    content_type: str = ""
    reply_to_mismatch: bool = False
    display_name_spoofed: bool = False
    forged_headers: list = field(default_factory=list)
    anomalies: list = field(default_factory=list)

    def to_dict(self):
        return asdict(self)


@dataclass
class URLFinding:
    url: str = ""
    domain: str = ""
    final_url: str = ""
    redirect_chain: list = field(default_factory=list)
    status_code: int = 0
    final_status_code: int = 0
    page_title: str = ""
    content_type: str = ""
    server: str = ""
    is_ip_based: bool = False
    is_shortened: bool = False
    has_homoglyph: bool = False
    homoglyph_target: str = ""
    subdomain_count: int = 0
    uses_https: bool = False
    known_phishing: bool = False
    suspicious_tld: bool = False
    detonation_error: str = ""
    threat_indicators: list = field(default_factory=list)
    risk_score: int = 0
    # Headless browser detonation fields
    screenshot_path: str = ""
    js_redirects: list = field(default_factory=list)
    meta_refresh_detected: bool = False
    meta_refresh_url: str = ""
    iframes_detected: list = field(default_factory=list)
    has_credential_form: bool = False
    browser_final_url: str = ""
    browser_page_title: str = ""
    browser_error: str = ""
    # Recursive intermediate domain analysis
    intermediate_domains: list = field(default_factory=list)
    # IDN homograph detection
    is_idn_homograph: bool = False
    idn_details: str = ""
    # HTML similarity analysis
    html_similarity: dict = field(default_factory=dict)
    # Threat intel feed results
    threat_intel_results: list = field(default_factory=list)

    def to_dict(self):
        return asdict(self)


@dataclass
class AttachmentFinding:
    filename: str = ""
    content_type: str = ""
    size: int = 0
    md5: str = ""
    sha1: str = ""
    sha256: str = ""
    entropy: float = 0.0
    is_executable: bool = False
    has_macro: bool = False
    extension_mismatch: bool = False
    declared_type: str = ""
    actual_type: str = ""
    malware_match: Optional[str] = None
    malware_family: Optional[str] = None
    vt_detections: int = 0
    vt_total_engines: int = 0
    vt_permalink: str = ""
    threat_indicators: list = field(default_factory=list)
    risk_score: int = 0
    # YARA scanning results
    yara_matches: list = field(default_factory=list)

    def to_dict(self):
        return asdict(self)


@dataclass
class BodyAnalysis:
    text_content: str = ""
    html_content: str = ""
    urgency_keywords_found: list = field(default_factory=list)
    embedded_urls: list = field(default_factory=list)
    embedded_images: int = 0
    hidden_text: bool = False
    form_action_external: bool = False
    javascript_detected: bool = False
    # NLP analysis results
    nlp_analysis: dict = field(default_factory=dict)
    # HTML similarity (brand impersonation in email body)
    html_similarity: dict = field(default_factory=dict)

    def to_dict(self):
        return asdict(self)


@dataclass
class IOCExtraction:
    ip_addresses: list = field(default_factory=list)
    domains: list = field(default_factory=list)
    urls: list = field(default_factory=list)
    file_hashes: list = field(default_factory=list)
    email_addresses: list = field(default_factory=list)

    def to_dict(self):
        return asdict(self)


@dataclass
class ThreatScore:
    total: int = 0
    level: str = "clean"
    level_label: str = "Clean — No Threats Detected"
    level_color: str = "#10b981"
    breakdown: list = field(default_factory=list)

    def to_dict(self):
        return asdict(self)


@dataclass
class AnalysisReport:
    report_id: str = ""
    filename: str = ""
    analyzed_at: str = ""
    headers: HeaderAnalysis = field(default_factory=HeaderAnalysis)
    urls: list = field(default_factory=list)
    attachments: list = field(default_factory=list)
    body: BodyAnalysis = field(default_factory=BodyAnalysis)
    iocs: IOCExtraction = field(default_factory=IOCExtraction)
    score: ThreatScore = field(default_factory=ThreatScore)
    # ML classification
    ml_classification: dict = field(default_factory=dict)
    # Threat intel enrichment
    threat_intel: dict = field(default_factory=dict)

    def to_dict(self):
        return asdict(self)
