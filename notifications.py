"""
Notification service — handles email, Slack, and in-app notifications.

Sends alerts when analyses find critical/high threats.
Generates weekly summary reports.
"""

import json
import logging
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timezone, timedelta

import config

logger = logging.getLogger(__name__)


def send_email_alert(to_email, subject, html_body):
    """Send an email notification via SMTP."""
    if not config.SMTP_ENABLED:
        logger.debug("SMTP not configured — skipping email to %s", to_email)
        return False

    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = config.SMTP_FROM
        msg["To"] = to_email
        msg.attach(MIMEText(html_body, "html"))

        if config.SMTP_USE_TLS:
            server = smtplib.SMTP(config.SMTP_HOST, config.SMTP_PORT, timeout=10)
            server.starttls()
        else:
            server = smtplib.SMTP_SSL(config.SMTP_HOST, config.SMTP_PORT, timeout=10)

        if config.SMTP_USER and config.SMTP_PASS:
            server.login(config.SMTP_USER, config.SMTP_PASS)

        server.sendmail(config.SMTP_FROM, [to_email], msg.as_string())
        server.quit()
        logger.info("Email alert sent to %s: %s", to_email, subject)
        return True
    except Exception:
        logger.exception("Failed to send email to %s", to_email)
        return False


def send_slack_alert(webhook_url, message_text, blocks=None):
    """Send a Slack notification via webhook."""
    if not webhook_url:
        return False

    try:
        import requests
        payload = {"text": message_text}
        if blocks:
            payload["blocks"] = blocks

        resp = requests.post(webhook_url, json=payload, timeout=10)
        if resp.status_code == 200:
            logger.info("Slack alert sent")
            return True
        else:
            logger.warning("Slack webhook returned %s: %s", resp.status_code, resp.text)
            return False
    except Exception:
        logger.exception("Failed to send Slack alert")
        return False


def notify_on_analysis(analysis_record, report_dict):
    """
    Check notification preferences and send alerts for a completed analysis.
    Called after an analysis finishes.
    """
    from database import (
        db, User, NotificationPreference, create_notification,
    )

    threat_level = report_dict.get("score", {}).get("level", "clean")
    threat_score = report_dict.get("score", {}).get("total", 0)
    filename = report_dict.get("filename", "unknown")
    report_id = report_dict.get("report_id", "")

    if threat_level not in ("critical", "high", "medium"):
        return

    # Find users who should be notified
    # 1. The user who submitted the analysis
    user_id = analysis_record.user_id if hasattr(analysis_record, 'user_id') else None
    users_to_notify = set()

    if user_id:
        users_to_notify.add(user_id)

    # 2. If org-scoped, notify org admins for critical threats
    org_id = analysis_record.org_id if hasattr(analysis_record, 'org_id') else None
    if org_id and threat_level in ("critical", "high"):
        org_admins = User.query.filter(
            User.org_id == org_id,
            User.org_role.in_(["owner", "admin"]),
            User.is_active == True,
        ).all()
        for admin in org_admins:
            users_to_notify.add(admin.id)

    for uid in users_to_notify:
        user = User.query.get(uid)
        if not user or not user.is_active:
            continue

        prefs = user.notification_prefs
        if not prefs:
            # Create default preferences
            prefs = NotificationPreference(user_id=uid)
            db.session.add(prefs)
            db.session.commit()

        # Check threshold
        if threat_score < prefs.alert_threshold:
            continue

        level_label = threat_level.upper()
        report_url = f"/report/{report_id}"

        # In-app notification always
        should_notify = (
            (threat_level == "critical" and prefs.email_on_critical) or
            (threat_level == "high" and prefs.email_on_high) or
            (threat_level == "medium" and prefs.email_on_medium)
        )

        if should_notify:
            create_notification(
                user_id=uid,
                title=f"{level_label} Threat Detected",
                message=f'"{filename}" scored {threat_score}/100 — {threat_level} threat level.',
                category="critical" if threat_level == "critical" else "warning",
                link=report_url,
            )

        # Email notification
        should_email = (
            (threat_level == "critical" and prefs.email_on_critical) or
            (threat_level == "high" and prefs.email_on_high) or
            (threat_level == "medium" and prefs.email_on_medium)
        )
        if should_email and config.SMTP_ENABLED:
            html = _build_threat_email(filename, threat_level, threat_score, report_id)
            send_email_alert(
                user.email,
                f"[PhishGuard] {level_label} Threat: {filename}",
                html,
            )

        # Slack notification
        should_slack = (
            (threat_level == "critical" and prefs.slack_on_critical) or
            (threat_level == "high" and prefs.slack_on_high)
        )
        if should_slack and prefs.slack_webhook_url:
            blocks = _build_slack_blocks(filename, threat_level, threat_score, report_id)
            send_slack_alert(prefs.slack_webhook_url, f"{level_label} threat detected: {filename}", blocks)


def send_weekly_summary(app):
    """Generate and send weekly summary reports to subscribed users."""
    from database import (
        db, User, NotificationPreference, Analysis,
        create_notification, get_stats,
    )
    import time

    with app.app_context():
        week_ago = time.time() - (7 * 86400)

        users = User.query.filter_by(is_active=True).all()
        for user in users:
            prefs = user.notification_prefs
            if not prefs or not prefs.email_weekly_summary:
                continue

            # Get this user's weekly stats
            q = Analysis.query.filter(Analysis.analyzed_at >= week_ago)
            if user.org_id:
                if user.is_admin() or user.is_org_admin():
                    q = q.filter(Analysis.org_id == user.org_id)
                else:
                    q = q.filter(Analysis.user_id == user.id)
            elif not user.is_admin():
                q = q.filter(Analysis.user_id == user.id)

            total = q.count()
            if total == 0:
                continue

            critical = q.filter(Analysis.threat_level == "critical").count()
            high = q.filter(Analysis.threat_level == "high").count()
            medium = q.filter(Analysis.threat_level == "medium").count()
            clean = total - critical - high - medium

            # In-app notification
            create_notification(
                user_id=user.id,
                title="Weekly Threat Summary",
                message=f"This week: {total} emails analyzed. "
                        f"{critical} critical, {high} high, {medium} medium, {clean} clean/low.",
                category="summary",
                link="/dashboard",
            )

            # Email summary
            if config.SMTP_ENABLED:
                html = _build_weekly_email(user.username, total, critical, high, medium, clean)
                send_email_alert(
                    user.email,
                    "[PhishGuard] Weekly Threat Summary",
                    html,
                )


def _build_threat_email(filename, threat_level, score, report_id):
    """Build HTML email for a threat alert."""
    color = {
        "critical": "#ef4444",
        "high": "#f97316",
        "medium": "#eab308",
    }.get(threat_level, "#6b7280")

    return f"""
    <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; max-width: 500px; margin: 0 auto; background: #0d1017; color: #c9d1d9; border-radius: 8px; overflow: hidden;">
        <div style="background: {color}; padding: 16px 24px;">
            <h2 style="margin: 0; color: #fff; font-size: 18px;">{threat_level.upper()} Threat Detected</h2>
        </div>
        <div style="padding: 24px;">
            <p style="margin: 0 0 12px;"><strong>File:</strong> {filename}</p>
            <p style="margin: 0 0 12px;"><strong>Threat Score:</strong> <span style="color: {color}; font-size: 24px; font-weight: 700;">{score}/100</span></p>
            <p style="margin: 0 0 20px;"><strong>Level:</strong> <span style="color: {color};">{threat_level.upper()}</span></p>
            <a href="{config.APP_BASE_URL}/report/{report_id}" style="display: inline-block; padding: 10px 24px; background: #58a6ff; color: #000; text-decoration: none; border-radius: 6px; font-weight: 600;">View Full Report</a>
        </div>
        <div style="padding: 12px 24px; border-top: 1px solid #1c2333; font-size: 12px; color: #6e7681;">
            PhishGuard Threat Alert
        </div>
    </div>
    """


def _build_weekly_email(username, total, critical, high, medium, clean):
    """Build HTML email for weekly summary."""
    return f"""
    <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; max-width: 500px; margin: 0 auto; background: #0d1017; color: #c9d1d9; border-radius: 8px; overflow: hidden;">
        <div style="background: #58a6ff; padding: 16px 24px;">
            <h2 style="margin: 0; color: #000; font-size: 18px;">Weekly Threat Summary</h2>
        </div>
        <div style="padding: 24px;">
            <p style="margin: 0 0 16px;">Hi {username}, here's your weekly analysis overview:</p>
            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 8px; margin-bottom: 20px;">
                <div style="background: #151a26; padding: 12px; border-radius: 6px; text-align: center;">
                    <div style="font-size: 28px; font-weight: 700; color: #58a6ff;">{total}</div>
                    <div style="font-size: 11px; color: #6e7681; text-transform: uppercase;">Total Analyzed</div>
                </div>
                <div style="background: #151a26; padding: 12px; border-radius: 6px; text-align: center;">
                    <div style="font-size: 28px; font-weight: 700; color: #ef4444;">{critical}</div>
                    <div style="font-size: 11px; color: #6e7681; text-transform: uppercase;">Critical</div>
                </div>
                <div style="background: #151a26; padding: 12px; border-radius: 6px; text-align: center;">
                    <div style="font-size: 28px; font-weight: 700; color: #f97316;">{high}</div>
                    <div style="font-size: 11px; color: #6e7681; text-transform: uppercase;">High</div>
                </div>
                <div style="background: #151a26; padding: 12px; border-radius: 6px; text-align: center;">
                    <div style="font-size: 28px; font-weight: 700; color: #2ea043;">{clean}</div>
                    <div style="font-size: 11px; color: #6e7681; text-transform: uppercase;">Clean/Low</div>
                </div>
            </div>
            <a href="{config.APP_BASE_URL}/dashboard" style="display: inline-block; padding: 10px 24px; background: #58a6ff; color: #000; text-decoration: none; border-radius: 6px; font-weight: 600;">View Dashboard</a>
        </div>
        <div style="padding: 12px 24px; border-top: 1px solid #1c2333; font-size: 12px; color: #6e7681;">
            Manage notification preferences in your PhishGuard settings.
        </div>
    </div>
    """


def _build_slack_blocks(filename, threat_level, score, report_id):
    """Build Slack Block Kit message."""
    color = {
        "critical": "#ef4444",
        "high": "#f97316",
        "medium": "#eab308",
    }.get(threat_level, "#6b7280")

    emoji = {"critical": ":rotating_light:", "high": ":warning:", "medium": ":large_yellow_circle:"}.get(threat_level, ":information_source:")

    return [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": f"{emoji} {threat_level.upper()} Threat Detected"}
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*File:*\n{filename}"},
                {"type": "mrkdwn", "text": f"*Score:*\n{score}/100"},
                {"type": "mrkdwn", "text": f"*Level:*\n{threat_level.upper()}"},
            ]
        },
        {
            "type": "actions",
            "elements": [
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "View Report"},
                    "url": f"{config.APP_BASE_URL}/report/{report_id}",
                    "style": "danger" if threat_level == "critical" else "primary",
                }
            ]
        },
    ]
