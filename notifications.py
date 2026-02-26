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


def send_test_notification(user):
    """Send a test notification (in-app + email + Slack if configured)."""
    from database import create_notification

    results = {"in_app": False, "email": False, "slack": False}

    # In-app notification
    try:
        create_notification(
            user_id=user.id,
            title="Test Notification",
            message="This is a test alert from PhishGuard. If you see this, notifications are working.",
            category="info",
            link="/notifications",
        )
        results["in_app"] = True
    except Exception:
        logger.exception("Test in-app notification failed")

    # Email notification
    prefs = user.notification_prefs
    if config.SMTP_ENABLED and user.email:
        html = _build_threat_email("test-sample.eml", "high", 72, "test-000")
        results["email"] = send_email_alert(
            user.email,
            "[PhishGuard] Test Notification",
            html,
        )
    else:
        results["email"] = None  # not configured

    # Slack notification
    if prefs and prefs.slack_webhook_url:
        blocks = _build_slack_blocks("test-sample.eml", "high", 72, "test-000")
        results["slack"] = send_slack_alert(
            prefs.slack_webhook_url,
            "Test notification from PhishGuard",
            blocks,
        )
    else:
        results["slack"] = None  # not configured

    return results


def _build_threat_email(filename, threat_level, score, report_id):
    """Build professional HTML email for a threat alert."""
    color = {
        "critical": "#ef4444",
        "high": "#f97316",
        "medium": "#eab308",
    }.get(threat_level, "#6b7280")

    bg_color = {
        "critical": "#1a0505",
        "high": "#1a0f05",
        "medium": "#1a1505",
    }.get(threat_level, "#0d1017")

    actions = []
    if threat_level == "critical":
        actions = [
            "Do NOT click any links or open any attachments from this email",
            "If you entered credentials, change your password immediately",
            "Report this to your IT security team",
            "Block the sender domain across your organization",
        ]
    elif threat_level == "high":
        actions = [
            "Do not interact with links or attachments in this email",
            "Report this email to your security team for review",
            "Check if other team members received similar messages",
        ]
    else:
        actions = [
            "Exercise caution with links and attachments",
            "Verify the sender through an alternate channel if unsure",
        ]

    actions_html = "".join(
        f'<tr><td style="padding:4px 0 4px 0; font-size:13px; color:#c9d1d9; vertical-align:top;">&#8226;</td>'
        f'<td style="padding:4px 0 4px 8px; font-size:13px; color:#c9d1d9;">{a}</td></tr>'
        for a in actions
    )

    return f"""
    <div style="font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, sans-serif; max-width: 560px; margin: 0 auto; background: #0d1017; border-radius: 8px; overflow: hidden; border: 1px solid #1c2333;">
        <div style="background: {color}; padding: 20px 28px;">
            <table width="100%" cellpadding="0" cellspacing="0" border="0"><tr>
                <td><h2 style="margin: 0; color: #fff; font-size: 18px; font-weight: 700;">{threat_level.upper()} Threat Detected</h2></td>
                <td align="right" style="font-size: 12px; color: rgba(255,255,255,.7);">PhishGuard Alert</td>
            </tr></table>
        </div>
        <div style="padding: 28px;">
            <table width="100%" cellpadding="0" cellspacing="0" border="0" style="margin-bottom: 20px;">
                <tr>
                    <td style="padding: 16px; background: {bg_color}; border-radius: 6px; text-align: center; width: 100px;">
                        <div style="font-size: 36px; font-weight: 700; color: {color}; line-height: 1;">{score}</div>
                        <div style="font-size: 11px; color: #6e7681; margin-top: 2px;">/100</div>
                    </td>
                    <td style="padding-left: 20px;">
                        <div style="font-size: 12px; color: #6e7681; text-transform: uppercase; letter-spacing: .5px; margin-bottom: 4px;">Analyzed File</div>
                        <div style="font-size: 15px; font-weight: 600; color: #c9d1d9; margin-bottom: 8px;">{filename}</div>
                        <div style="display: inline-block; padding: 3px 10px; border-radius: 3px; font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: .3px; background: {color}20; color: {color};">{threat_level}</div>
                    </td>
                </tr>
            </table>

            <div style="margin-bottom: 20px;">
                <div style="font-size: 12px; font-weight: 700; color: #6e7681; text-transform: uppercase; letter-spacing: .5px; margin-bottom: 10px;">Recommended Actions</div>
                <table cellpadding="0" cellspacing="0" border="0">
                    {actions_html}
                </table>
            </div>

            <a href="{config.APP_BASE_URL}/report/{report_id}" style="display: inline-block; padding: 12px 28px; background: #58a6ff; color: #000; text-decoration: none; border-radius: 6px; font-weight: 700; font-size: 14px;">View Full Report</a>
        </div>
        <div style="padding: 14px 28px; border-top: 1px solid #1c2333; font-size: 11px; color: #484f58;">
            This alert was sent by PhishGuard based on your notification preferences.
            <a href="{config.APP_BASE_URL}/notifications" style="color: #58a6ff; text-decoration: none;">Manage preferences</a>
        </div>
    </div>
    """


def _build_weekly_email(username, total, critical, high, medium, clean):
    """Build professional HTML email for weekly summary."""
    threat_total = critical + high + medium
    threat_pct = round((threat_total / total * 100), 1) if total > 0 else 0

    # CSS bar widths for inline chart
    max_val = max(critical, high, medium, clean, 1)
    crit_w = round(critical / max_val * 100)
    high_w = round(high / max_val * 100)
    med_w = round(medium / max_val * 100)
    clean_w = round(clean / max_val * 100)

    trend_text = ""
    if threat_total == 0:
        trend_text = "No threats were detected this week. Your email security posture looks strong."
    elif critical > 0:
        trend_text = f"{critical} critical threat{'s' if critical != 1 else ''} detected this week. Review flagged emails immediately."
    elif threat_total > 0:
        trend_text = f"{threat_total} suspicious email{'s' if threat_total != 1 else ''} flagged. Review the details on your dashboard."

    return f"""
    <div style="font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, sans-serif; max-width: 560px; margin: 0 auto; background: #0d1017; border-radius: 8px; overflow: hidden; border: 1px solid #1c2333;">
        <div style="background: linear-gradient(135deg, #1a3a5c 0%, #0d1017 100%); padding: 24px 28px;">
            <table width="100%" cellpadding="0" cellspacing="0" border="0"><tr>
                <td>
                    <div style="font-size: 11px; color: #58a6ff; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 4px;">PhishGuard</div>
                    <h2 style="margin: 0; color: #c9d1d9; font-size: 20px; font-weight: 700;">Weekly Threat Summary</h2>
                </td>
                <td align="right" style="font-size: 11px; color: #484f58; vertical-align: bottom;">7-day report</td>
            </tr></table>
        </div>
        <div style="padding: 28px;">
            <p style="margin: 0 0 8px; font-size: 14px; color: #c9d1d9;">Hi {username},</p>
            <p style="margin: 0 0 24px; font-size: 13px; color: #6e7681; line-height: 1.6;">{trend_text}</p>

            <table width="100%" cellpadding="0" cellspacing="8" border="0" style="margin-bottom: 24px;">
                <tr>
                    <td width="50%" style="background: #151a26; padding: 16px; border-radius: 6px; text-align: center;">
                        <div style="font-size: 32px; font-weight: 700; color: #58a6ff; line-height: 1;">{total}</div>
                        <div style="font-size: 10px; color: #6e7681; text-transform: uppercase; letter-spacing: .5px; margin-top: 4px;">Total Analyzed</div>
                    </td>
                    <td width="50%" style="background: #151a26; padding: 16px; border-radius: 6px; text-align: center;">
                        <div style="font-size: 32px; font-weight: 700; color: {'#ef4444' if threat_pct > 30 else '#2ea043'}; line-height: 1;">{threat_pct}%</div>
                        <div style="font-size: 10px; color: #6e7681; text-transform: uppercase; letter-spacing: .5px; margin-top: 4px;">Threat Rate</div>
                    </td>
                </tr>
            </table>

            <div style="margin-bottom: 24px;">
                <div style="font-size: 12px; font-weight: 700; color: #6e7681; text-transform: uppercase; letter-spacing: .5px; margin-bottom: 12px;">Breakdown</div>
                <table width="100%" cellpadding="0" cellspacing="0" border="0">
                    <tr>
                        <td style="padding: 6px 0; font-size: 12px; color: #c9d1d9; width: 70px;">Critical</td>
                        <td style="padding: 6px 0;">
                            <div style="background: #1c2333; border-radius: 3px; height: 16px; overflow: hidden;">
                                <div style="background: #ef4444; height: 100%; width: {crit_w}%; min-width: {'4px' if critical > 0 else '0'}; border-radius: 3px;"></div>
                            </div>
                        </td>
                        <td style="padding: 6px 0 6px 10px; font-size: 13px; font-weight: 700; color: #ef4444; width: 32px; text-align: right;">{critical}</td>
                    </tr>
                    <tr>
                        <td style="padding: 6px 0; font-size: 12px; color: #c9d1d9;">High</td>
                        <td style="padding: 6px 0;">
                            <div style="background: #1c2333; border-radius: 3px; height: 16px; overflow: hidden;">
                                <div style="background: #f97316; height: 100%; width: {high_w}%; min-width: {'4px' if high > 0 else '0'}; border-radius: 3px;"></div>
                            </div>
                        </td>
                        <td style="padding: 6px 0 6px 10px; font-size: 13px; font-weight: 700; color: #f97316; width: 32px; text-align: right;">{high}</td>
                    </tr>
                    <tr>
                        <td style="padding: 6px 0; font-size: 12px; color: #c9d1d9;">Medium</td>
                        <td style="padding: 6px 0;">
                            <div style="background: #1c2333; border-radius: 3px; height: 16px; overflow: hidden;">
                                <div style="background: #eab308; height: 100%; width: {med_w}%; min-width: {'4px' if medium > 0 else '0'}; border-radius: 3px;"></div>
                            </div>
                        </td>
                        <td style="padding: 6px 0 6px 10px; font-size: 13px; font-weight: 700; color: #eab308; width: 32px; text-align: right;">{medium}</td>
                    </tr>
                    <tr>
                        <td style="padding: 6px 0; font-size: 12px; color: #c9d1d9;">Clean/Low</td>
                        <td style="padding: 6px 0;">
                            <div style="background: #1c2333; border-radius: 3px; height: 16px; overflow: hidden;">
                                <div style="background: #2ea043; height: 100%; width: {clean_w}%; min-width: {'4px' if clean > 0 else '0'}; border-radius: 3px;"></div>
                            </div>
                        </td>
                        <td style="padding: 6px 0 6px 10px; font-size: 13px; font-weight: 700; color: #2ea043; width: 32px; text-align: right;">{clean}</td>
                    </tr>
                </table>
            </div>

            <a href="{config.APP_BASE_URL}/dashboard" style="display: inline-block; padding: 12px 28px; background: #58a6ff; color: #000; text-decoration: none; border-radius: 6px; font-weight: 700; font-size: 14px;">View Dashboard</a>
        </div>
        <div style="padding: 14px 28px; border-top: 1px solid #1c2333; font-size: 11px; color: #484f58;">
            Sent weekly to subscribed users.
            <a href="{config.APP_BASE_URL}/notifications" style="color: #58a6ff; text-decoration: none;">Manage preferences</a>
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
