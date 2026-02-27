# imap_poller.py - polls shared inbox for forwarded suspicious emails
# Users forward to e.g. analyze@yourapp.com, we pick them up via IMAP

import email
import imaplib
import logging
import smtplib
import time
from datetime import datetime, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import config

logger = logging.getLogger(__name__)

# TODO: handle edge case where user account is deactivated mid-poll


def poll_inbox(app):
    # connect to IMAP, fetch UNSEEN, process forwarded emails, mark seen
    from database import db, ImapPollLog

    if not config.IMAP_ENABLED:
        logger.debug("IMAP polling disabled — skipping")
        return {"status": "disabled", "emails_found": 0, "emails_processed": 0}

    results = {
        "status": "success",
        "emails_found": 0,
        "emails_processed": 0,
        "errors": [],
    }

    conn = None
    try:
        if config.IMAP_USE_SSL:
            conn = imaplib.IMAP4_SSL(config.IMAP_HOST, config.IMAP_PORT)
        else:
            conn = imaplib.IMAP4(config.IMAP_HOST, config.IMAP_PORT)

        conn.login(config.IMAP_USER, config.IMAP_PASS)
        conn.select(config.IMAP_FOLDER)

        status, msg_ids = conn.search(None, "UNSEEN")
        if status != "OK" or not msg_ids[0]:
            logger.info("IMAP poll: no new messages")
            _log_poll(app, results)
            return results

        id_list = msg_ids[0].split()
        results["emails_found"] = len(id_list)
        print(f"[imap] found {len(id_list)} unseen messages")  # debug

        for msg_id in id_list:
            try:
                _process_message(conn, msg_id, app)
                results["emails_processed"] += 1
            except Exception as exc:
                err = f"Failed to process message {msg_id}: {exc}"
                logger.exception(err)
                results["errors"].append(err)

    except imaplib.IMAP4.error as exc:
        err = f"IMAP connection error: {exc}"
        logger.exception(err)
        results["status"] = "error"
        results["errors"].append(err)
    except Exception as exc:
        err = f"Unexpected error during IMAP poll: {exc}"
        logger.exception(err)
        results["status"] = "error"
        results["errors"].append(err)
    finally:
        if conn:
            try:
                conn.close()
                conn.logout()
            except Exception:
                pass

    _log_poll(app, results)
    return results


def _process_message(conn, msg_id, app):
    """Fetch a single message, extract forwarded email, and run analysis."""
    from database import db, User, Analysis, save_report

    status, msg_data = conn.fetch(msg_id, "(RFC822)")
    if status != "OK":
        raise RuntimeError(f"Failed to fetch message {msg_id}")

    raw = msg_data[0][1]
    msg = email.message_from_bytes(raw)

    sender_email = email.utils.parseaddr(msg.get("From", ""))[1].lower()
    subject = msg.get("Subject", "(no subject)")

    logger.info("Processing forwarded email from %s: %s", sender_email, subject)
    # print(f"raw msg size: {len(raw)}")  # was useful for debugging large attachments

    # Extract the forwarded email content
    forwarded_bytes = extract_forwarded_email(msg)
    if not forwarded_bytes:
        logger.warning("Could not extract forwarded email from message by %s", sender_email)
        # Mark as seen even if we can't process it
        conn.store(msg_id, "+FLAGS", "\\Seen")
        return

    # Attribute to a user
    user = attribute_to_user(sender_email, app)

    with app.app_context():
        # Run analysis
        from email_parser import parse_eml
        from header_analyzer import analyze_headers
        from url_analyzer import analyze_all_urls
        from attachment_analyzer import analyze_all_attachments
        from ioc_extractor import extract_iocs
        from threat_scorer import calculate_score
        from mitre_mapper import map_findings_to_mitre, get_attack_summary
        from models import AnalysisReport
        import uuid

        report = AnalysisReport()
        report.report_id = uuid.uuid4().hex[:12]
        report.filename = f"forwarded-{subject[:40]}.eml"
        report.analyzed_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        parsed_msg, headers, body, attachments_raw = parse_eml(forwarded_bytes)
        headers = analyze_headers(headers)
        report.headers = headers
        report.body = body

        url_findings = analyze_all_urls(body.text_content, body.html_content)
        att_findings = analyze_all_attachments(attachments_raw)

        report.urls = [uf.to_dict() for uf in url_findings]
        report.attachments = [af.to_dict() for af in att_findings]

        iocs = extract_iocs(headers, body, url_findings, att_findings)
        report.iocs = iocs

        # NLP analysis
        if config.NLP_ANALYSIS_ENABLED:
            try:
                from nlp_analyzer import analyze_body
                nlp_result = analyze_body(body.text_content, body.html_content, headers.subject)
                body.nlp_analysis = nlp_result
            except Exception:
                nlp_result = None
        else:
            nlp_result = None

        # ML classification
        if config.ML_CLASSIFIER_ENABLED:
            try:
                from ml_classifier import classify
                ml_result = classify(headers, url_findings, att_findings, body)
                report.ml_classification = ml_result
            except Exception:
                ml_result = None
        else:
            ml_result = None

        score = calculate_score(
            headers, url_findings, att_findings, body,
            ml_result=ml_result, nlp_result=nlp_result,
        )
        report.score = score

        mitre_mappings = map_findings_to_mitre(score.breakdown)
        attack_summary = get_attack_summary(mitre_mappings)

        report_dict = report.to_dict()
        report_dict["mitre_mappings"] = mitre_mappings
        report_dict["attack_summary"] = attack_summary
        report_dict["whois"] = {}

        save_report(
            report_dict,
            user_id=user.id if user else None,
            status="complete",
        )

        # Send notifications
        try:
            from notifications import notify_on_analysis
            saved = Analysis.query.get(report.report_id)
            if saved:
                notify_on_analysis(saved, report_dict)
        except Exception:
            logger.debug("Notification dispatch failed for forwarded email")

        # Send reply with results if configured
        if config.IMAP_AUTO_REPLY and sender_email:
            try:
                send_analysis_reply(sender_email, report_dict)
            except Exception:
                logger.exception("Failed to send analysis reply to %s", sender_email)

    # Mark as seen
    conn.store(msg_id, "+FLAGS", "\\Seen")


def extract_forwarded_email(msg):
    # tries 3 patterns to get the actual forwarded content:
    # 1) message/rfc822 attachment  2) .eml attachment  3) inline fallback

    # message/rfc822 attachment (standard forward)
    if msg.is_multipart():
        for part in msg.walk():
            ct = part.get_content_type()
            if ct == "message/rfc822":
                payload = part.get_payload()
                if isinstance(payload, list) and len(payload) > 0:
                    return payload[0].as_bytes()
                elif hasattr(payload, "as_bytes"):
                    return payload.as_bytes()

    # .eml file attachment
    if msg.is_multipart():
        for part in msg.walk():
            fn = part.get_filename()
            if fn and fn.lower().endswith(".eml"):
                payload = part.get_payload(decode=True)
                if payload:
                    return payload

    # fallback: treat the wrapper itself as the sample
    try:
        return msg.as_bytes()
    except Exception:
        return None


def attribute_to_user(sender_email, app):
    from database import User

    with app.app_context():
        usr = User.query.filter_by(email=sender_email, is_active=True).first()
        if usr:
            return usr
        # fallback to any admin account
        return User.query.filter_by(role="admin", is_active=True).first()


def send_analysis_reply(to_email, report_dict):
    """Send email reply with analysis results back to the forwarder."""
    if not config.SMTP_ENABLED:
        return False

    score = report_dict.get("score", {})
    lvl = score.get("level", "clean")
    threat_score = score.get("total", 0)
    level_color = score.get("level_color", "#6e7681")
    filename = report_dict.get("filename", "unknown")
    report_id = report_dict.get("report_id", "")

    # top findings
    findings = score.get("breakdown", [])[:5]
    findings_html = ""
    if findings:
        rows = ""
        for f in findings:
            rows += (
                f'<tr><td style="padding:4px 8px; font-size:12px; color:#c9d1d9; border-bottom:1px solid #1c2333;">{f.get("reason", "")}</td>'
                f'<td style="padding:4px 8px; font-size:12px; color:#6e7681; border-bottom:1px solid #1c2333;">+{f.get("points", 0)}</td></tr>'
            )
        findings_html = f"""
        <div style="margin-top:16px;">
            <div style="font-size:11px; color:#6e7681; text-transform:uppercase; letter-spacing:.5px; margin-bottom:8px; font-weight:700;">Key Findings</div>
            <table width="100%" cellpadding="0" cellspacing="0" border="0">{rows}</table>
        </div>
        """

    html = f"""
    <div style="font-family: 'Segoe UI', -apple-system, sans-serif; max-width:560px; margin:0 auto; background:#0d1017; border-radius:8px; overflow:hidden; border:1px solid #1c2333;">
        <div style="background:{level_color}; padding:16px 24px;">
            <h2 style="margin:0; color:#fff; font-size:16px;">PhishGuard Analysis Complete</h2>
        </div>
        <div style="padding:24px;">
            <p style="margin:0 0 16px; font-size:13px; color:#c9d1d9;">Your forwarded email has been analyzed.</p>
            <table width="100%" cellpadding="0" cellspacing="0" border="0" style="margin-bottom:16px;">
                <tr>
                    <td style="padding:14px; background:#151a26; border-radius:6px; text-align:center; width:80px;">
                        <div style="font-size:28px; font-weight:700; color:{level_color}; line-height:1;">{threat_score}</div>
                        <div style="font-size:10px; color:#6e7681;">/100</div>
                    </td>
                    <td style="padding-left:16px;">
                        <div style="font-size:14px; font-weight:600; color:#c9d1d9;">{filename}</div>
                        <div style="display:inline-block; padding:2px 8px; border-radius:3px; font-size:10px; font-weight:700; text-transform:uppercase; background:{level_color}20; color:{level_color}; margin-top:6px;">{lvl}</div>
                    </td>
                </tr>
            </table>
            {findings_html}
            <a href="{config.APP_BASE_URL}/report/{report_id}" style="display:inline-block; margin-top:16px; padding:10px 24px; background:#58a6ff; color:#000; text-decoration:none; border-radius:6px; font-weight:700; font-size:13px;">View Full Report</a>
        </div>
        <div style="padding:12px 24px; border-top:1px solid #1c2333; font-size:11px; color:#484f58;">
            Automated analysis by PhishGuard
        </div>
    </div>
    """

    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"[PhishGuard] Analysis: {lvl.upper()} - {filename}"
        msg["From"] = config.SMTP_FROM
        msg["To"] = to_email
        msg.attach(MIMEText(html, "html"))

        if config.SMTP_USE_TLS:
            server = smtplib.SMTP(config.SMTP_HOST, config.SMTP_PORT, timeout=10)
            server.starttls()
        else:
            server = smtplib.SMTP_SSL(config.SMTP_HOST, config.SMTP_PORT, timeout=10)

        if config.SMTP_USER and config.SMTP_PASS:
            server.login(config.SMTP_USER, config.SMTP_PASS)

        server.sendmail(config.SMTP_FROM, [to_email], msg.as_string())
        server.quit()
        logger.info("Analysis reply sent to %s for %s", to_email, filename)
        return True
    except Exception:
        logger.exception("Failed to send analysis reply to %s", to_email)
        return False


def test_connection():
    """Quick connectivity check — returns dict with status."""
    if not config.IMAP_ENABLED:
        return {"success": False, "error": "IMAP is not configured"}

    try:
        if config.IMAP_USE_SSL:
            conn = imaplib.IMAP4_SSL(config.IMAP_HOST, config.IMAP_PORT)
        else:
            conn = imaplib.IMAP4(config.IMAP_HOST, config.IMAP_PORT)
        conn.login(config.IMAP_USER, config.IMAP_PASS)
        _, folders = conn.list()
        conn.select(config.IMAP_FOLDER)

        _, msg_count = conn.search(None, "ALL")
        n_total = len(msg_count[0].split()) if msg_count[0] else 0
        _, unseen = conn.search(None, "UNSEEN")
        n_unseen = len(unseen[0].split()) if unseen[0] else 0

        conn.close()
        conn.logout()

        return {
            "success": True,
            "host": config.IMAP_HOST,
            "folder": config.IMAP_FOLDER,
            "total_messages": n_total,
            "unseen_messages": n_unseen,
        }
    except Exception as exc:
        return {"success": False, "error": str(exc)}


def _log_poll(app, results):
    from database import db, ImapPollLog
    try:
        with app.app_context():
            entry = ImapPollLog(
                emails_found=results["emails_found"],
                emails_processed=results["emails_processed"],
                errors="; ".join(results["errors"]) if results["errors"] else None,
                status=results["status"],
            )
            db.session.add(entry)
            db.session.commit()
    except Exception:
        logger.exception("Failed to log IMAP poll results")
