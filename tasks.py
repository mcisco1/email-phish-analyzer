"""
Celery background tasks for asynchronous email analysis.

Usage:
    from tasks import analyze_email_task
    result = analyze_email_task.delay(raw_bytes, filename, user_id, s3_key)
    # result.id is the Celery task ID — store it and poll for status
"""

import uuid
import logging
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor

from celery import Celery
from celery.schedules import crontab

import config

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Celery app (separate from Flask — workers import this directly)
# ---------------------------------------------------------------------------
celery_app = Celery(
    "phishguard",
    broker=config.CELERY_BROKER_URL,
    backend=config.CELERY_RESULT_BACKEND,
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    task_soft_time_limit=120,
    task_time_limit=180,
    result_expires=3600,
    broker_connection_retry_on_startup=True,
    beat_schedule={
        "poll-imap-inbox": {
            "task": "phishguard.poll_imap",
            "schedule": getattr(config, "IMAP_POLL_INTERVAL", 60),
        },
        "weekly-threat-summary": {
            "task": "phishguard.weekly_summary",
            "schedule": crontab(hour=9, minute=0, day_of_week=1),  # Monday 9 AM
        },
    },
)


def init_celery(app):
    """Bind Celery to the Flask app context so tasks can access the DB."""
    celery_app.conf.update(app.config)
    set_flask_app(app)

    class ContextTask(celery_app.Task):
        abstract = True

        def __call__(self, *args, **kwargs):
            with app.app_context():
                return self.run(*args, **kwargs)

    celery_app.Task = ContextTask
    return celery_app


@celery_app.task(bind=True, name="phishguard.analyze_email", max_retries=2,
                 default_retry_delay=10)
def analyze_email_task(self, raw_bytes_hex, filename, user_id=None, s3_key=None):
    """
    Run the full analysis pipeline in the background.

    raw_bytes_hex: hex-encoded .eml content (JSON-safe)
    filename: original filename
    user_id: optional user ID
    s3_key: optional S3 storage key
    """
    from email_parser import parse_eml
    from header_analyzer import analyze_headers
    from url_analyzer import analyze_all_urls
    from attachment_analyzer import analyze_all_attachments
    from ioc_extractor import extract_iocs
    from threat_scorer import calculate_score
    from mitre_mapper import map_findings_to_mitre, get_attack_summary
    from whois_lookup import enrich_url_findings
    from models import AnalysisReport
    from database import db as sa_db, Analysis, save_report, log_audit
    import config as task_config

    task_id = self.request.id

    # Find the existing pending record by task_id and reuse its report_id
    analysis = Analysis.query.filter_by(task_id=task_id).first()
    if analysis:
        report_id = analysis.id
        analysis.status = "processing"
        sa_db.session.commit()
    else:
        report_id = uuid.uuid4().hex[:12]

    try:
        raw_bytes = bytes.fromhex(raw_bytes_hex)

        report = AnalysisReport()
        report.report_id = report_id
        report.filename = filename
        report.analyzed_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        msg, headers, body, attachments_raw = parse_eml(raw_bytes)
        headers = analyze_headers(headers)
        report.headers = headers
        report.body = body

        url_findings = []
        att_findings = []

        with ThreadPoolExecutor(max_workers=2) as executor:
            url_future = executor.submit(analyze_all_urls, body.text_content, body.html_content)
            att_future = executor.submit(analyze_all_attachments, attachments_raw)
            url_findings = url_future.result()
            att_findings = att_future.result()

        report.urls = [uf.to_dict() for uf in url_findings]
        report.attachments = [af.to_dict() for af in att_findings]

        iocs = extract_iocs(headers, body, url_findings, att_findings)
        report.iocs = iocs

        # --- NLP body analysis ---
        nlp_result = None
        if task_config.NLP_ANALYSIS_ENABLED:
            try:
                from nlp_analyzer import analyze_body
                nlp_result = analyze_body(
                    body.text_content, body.html_content, headers.subject,
                )
                body.nlp_analysis = nlp_result
            except Exception:
                logger.debug("NLP analysis failed — continuing without it")

        # --- HTML similarity analysis on email body ---
        if task_config.HTML_SIMILARITY_ENABLED and body.html_content:
            try:
                from html_similarity import analyze_email_html
                from_domain = headers.from_address.split("@")[-1] if "@" in headers.from_address else ""
                body_brand_matches = analyze_email_html(body.html_content, from_domain)
                if body_brand_matches:
                    body.html_similarity = {"matches": body_brand_matches}
            except Exception:
                logger.debug("HTML similarity (body) failed — continuing without it")

        # --- ML classification ---
        ml_result = None
        if task_config.ML_CLASSIFIER_ENABLED:
            try:
                from ml_classifier import classify
                ml_result = classify(headers, url_findings, att_findings, body)
                report.ml_classification = ml_result
            except Exception:
                logger.debug("ML classification failed — continuing without it")

        # --- Threat intel feed enrichment ---
        threat_intel_result = None
        if task_config.THREAT_INTEL_ENABLED:
            try:
                from threat_intel import enrich_iocs as ti_enrich
                threat_intel_result = ti_enrich(
                    ip_addresses=iocs.ip_addresses if hasattr(iocs, 'ip_addresses') else iocs.get("ip_addresses", []),
                    domains=iocs.domains if hasattr(iocs, 'domains') else iocs.get("domains", []),
                    urls=iocs.urls if hasattr(iocs, 'urls') else iocs.get("urls", []),
                    config=task_config,
                )
                report.threat_intel = threat_intel_result
            except Exception:
                logger.debug("Threat intel enrichment failed — continuing without it")

        score = calculate_score(
            headers, url_findings, att_findings, body,
            ml_result=ml_result,
            nlp_result=nlp_result,
            threat_intel_result=threat_intel_result,
        )
        report.score = score

        mitre_mappings = map_findings_to_mitre(score.breakdown)
        attack_summary = get_attack_summary(mitre_mappings)

        whois_data = {}
        try:
            whois_data = enrich_url_findings(url_findings)
        except Exception:
            logger.debug("WHOIS enrichment failed — continuing without it")

        report_dict = report.to_dict()
        report_dict["mitre_mappings"] = mitre_mappings
        report_dict["attack_summary"] = attack_summary
        report_dict["whois"] = whois_data

        save_report(report_dict, user_id=user_id, s3_key=s3_key,
                    task_id=task_id, status="complete")

        # Send notifications for the completed analysis
        try:
            from notifications import notify_on_analysis
            saved_analysis = Analysis.query.get(report_id)
            if saved_analysis:
                notify_on_analysis(saved_analysis, report_dict)
        except Exception:
            logger.debug("Notification dispatch failed — continuing")

        logger.info("Background analysis complete: %s (%s) -> %s",
                     filename, report_id, score.level)

        return {
            "report_id": report_id,
            "filename": filename,
            "threat_level": score.level,
            "threat_score": score.total,
            "status": "complete",
        }

    except Exception as exc:
        logger.exception("Background analysis failed for %s", filename)
        # Mark as failed in DB
        analysis = Analysis.query.filter_by(task_id=task_id).first()
        if analysis:
            analysis.status = "failed"
            sa_db.session.commit()
        raise self.retry(exc=exc)


# ---------------------------------------------------------------------------
# Scheduled tasks
# ---------------------------------------------------------------------------

# Store a reference to the Flask app for scheduled tasks
_flask_app = None


def set_flask_app(app):
    """Called from init_celery to store the Flask app reference."""
    global _flask_app
    _flask_app = app


@celery_app.task(name="phishguard.poll_imap", ignore_result=True)
def poll_imap_task():
    """Poll the IMAP inbox for forwarded emails and analyze them."""
    if not getattr(config, "IMAP_ENABLED", False):
        return {"status": "disabled"}

    if _flask_app is None:
        logger.warning("Flask app not initialized — skipping IMAP poll")
        return {"status": "error", "reason": "no_app"}

    try:
        from imap_poller import poll_inbox
        result = poll_inbox(_flask_app)
        logger.info(
            "IMAP poll complete: %d found, %d processed",
            result.get("emails_found", 0),
            result.get("emails_processed", 0),
        )
        return result
    except Exception:
        logger.exception("IMAP poll task failed")
        return {"status": "error"}


@celery_app.task(name="phishguard.weekly_summary", ignore_result=True)
def weekly_summary_task():
    """Send weekly threat summary reports to subscribed users."""
    if _flask_app is None:
        logger.warning("Flask app not initialized — skipping weekly summary")
        return {"status": "error", "reason": "no_app"}

    try:
        from notifications import send_weekly_summary
        send_weekly_summary(_flask_app)
        logger.info("Weekly summary emails dispatched")
        return {"status": "success"}
    except Exception:
        logger.exception("Weekly summary task failed")
        return {"status": "error"}
