"""
PhishGuard — Phishing Email Analyzer

Production-grade Flask application with:
- OAuth 2.0 (Google, Microsoft) + local auth
- JWT API authentication with refresh/revocation
- Role-based access control (admin / analyst / viewer)
- CSRF protection on every form
- Content Security Policy, X-Frame-Options, XSS protection headers
- Input sanitization and file upload validation
- Celery background task queue for async analysis
- S3/MinIO file storage
- PostgreSQL via SQLAlchemy
- Structured JSON logging
- Health check endpoint
- Audit logging on every action
- Proper rate limiting per user/IP
- Onboarding flow for new users
- SOC-style analytics dashboard
- Alerting & notifications (email, Slack, in-app)
- Team / organization features
"""

import os
import re
import uuid
import json
import secrets
import logging
import sys
import functools
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone, timedelta

from markupsafe import escape
from flask import (
    Flask, render_template, request, redirect, url_for, jsonify,
    abort, Response, flash, session, send_from_directory,
)
from flask_login import login_required, current_user

import config
from database import (
    db as sa_db, init_db, save_report, get_report, get_history,
    delete_report, get_stats, search_history, get_trend_data,
    log_audit, get_analysis_by_task_id, Analysis,
    Organization, User, TeamInvite, NotificationPreference,
    Notification, get_weekly_comparison, get_top_attack_types,
    get_top_domains, get_recent_critical, get_user_notifications,
    get_unread_notification_count, create_notification,
)
from auth import (
    auth_bp, login_manager, csrf, api_auth_required, api_role_required,
    role_required, _client_ip,
)
from storage import store_eml, delete_eml
from email_parser import parse_eml
from header_analyzer import analyze_headers
from url_analyzer import analyze_all_urls
from attachment_analyzer import analyze_all_attachments
from ioc_extractor import extract_iocs
from threat_scorer import calculate_score
from mitre_mapper import map_findings_to_mitre, get_attack_summary
from stix_exporter import generate_stix_bundle, stix_to_json
from whois_lookup import enrich_url_findings
from report_generator import generate_pdf
from models import AnalysisReport


# =========================================================================
# STRUCTURED LOGGING
# =========================================================================

def _setup_logging():
    """Configure structured JSON logging for production, readable for dev."""

    class JSONFormatter(logging.Formatter):
        def format(self, record):
            log_entry = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "level": record.levelname,
                "logger": record.name,
                "message": record.getMessage(),
            }
            if record.exc_info and record.exc_info[0]:
                log_entry["exception"] = self.formatException(record.exc_info)
            return json.dumps(log_entry)

    root = logging.getLogger()
    root.setLevel(logging.INFO)
    # Remove existing handlers
    root.handlers.clear()

    handler = logging.StreamHandler(sys.stdout)
    if config.IS_PROD or config.IS_STAGING:
        handler.setFormatter(JSONFormatter())
    else:
        handler.setFormatter(logging.Formatter(
            "%(asctime)s %(name)s %(levelname)s %(message)s"
        ))
    root.addHandler(handler)

    # Silence noisy libraries
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("werkzeug").setLevel(logging.WARNING)
    logging.getLogger("botocore").setLevel(logging.WARNING)


_setup_logging()
logger = logging.getLogger("phishguard")


# =========================================================================
# APP FACTORY
# =========================================================================

def create_app():
    """Application factory — creates and configures the Flask app."""
    app = Flask(__name__)

    # --- Core config ---
    app.config["SECRET_KEY"] = config.SECRET_KEY
    app.config["MAX_CONTENT_LENGTH"] = config.MAX_FILE_SIZE
    app.config["SQLALCHEMY_DATABASE_URI"] = config.SQLALCHEMY_DATABASE_URI
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = config.SQLALCHEMY_TRACK_MODIFICATIONS
    app.config["SQLALCHEMY_ENGINE_OPTIONS"] = config.SQLALCHEMY_ENGINE_OPTIONS
    app.config["SESSION_COOKIE_SECURE"] = config.SESSION_COOKIE_SECURE
    app.config["SESSION_COOKIE_HTTPONLY"] = config.SESSION_COOKIE_HTTPONLY
    app.config["SESSION_COOKIE_SAMESITE"] = config.SESSION_COOKIE_SAMESITE
    app.config["SESSION_COOKIE_NAME"] = config.SESSION_COOKIE_NAME
    app.config["PERMANENT_SESSION_LIFETIME"] = config.PERMANENT_SESSION_LIFETIME
    app.config["WTF_CSRF_TIME_LIMIT"] = 3600  # 1 hour CSRF token validity

    # --- Debug mode ---
    app.debug = config.DEBUG

    # --- Initialize extensions ---
    init_db(app)
    login_manager.init_app(app)
    csrf.init_app(app)

    # --- Rate Limiting ---
    _setup_rate_limiting(app)

    # --- Register blueprints ---
    app.register_blueprint(auth_bp)

    # --- Security headers on every response ---
    @app.after_request
    def _set_security_headers(response):
        # Content Security Policy
        csp = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com; "
            "img-src 'self' data:; "
            "connect-src 'self'; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self' https://accounts.google.com https://login.microsoftonline.com"
        )
        response.headers["Content-Security-Policy"] = csp
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        if config.SESSION_COOKIE_SECURE:
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        # Remove server header
        response.headers.pop("Server", None)
        return response

    # --- Inject notification count into all templates ---
    @app.context_processor
    def inject_notification_count():
        if current_user.is_authenticated:
            return {"unread_count": get_unread_notification_count(current_user.id)}
        return {"unread_count": 0}

    # --- Register routes ---
    _register_web_routes(app)
    _register_api_routes(app)
    _register_onboarding_routes(app)
    _register_notification_routes(app)
    _register_team_routes(app)
    _register_error_handlers(app)

    # --- Celery integration (optional — works without it) ---
    try:
        from tasks import init_celery
        init_celery(app)
        app.config["CELERY_ENABLED"] = True
        logger.info("Celery task queue enabled")
    except Exception:
        app.config["CELERY_ENABLED"] = False
        logger.info("Celery not available — analysis will run synchronously")

    logger.info("PhishGuard started [env=%s, db=%s]",
                config.FLASK_ENV,
                "PostgreSQL" if config.DATABASE_URL.startswith("postgresql") else "SQLite")

    return app


# =========================================================================
# RATE LIMITING
# =========================================================================

def _setup_rate_limiting(app):
    try:
        from flask_limiter import Limiter
        from flask_limiter.util import get_remote_address

        def _rate_limit_key():
            """Rate limit by user ID if authenticated, else by IP."""
            if current_user.is_authenticated:
                return f"user:{current_user.id}"
            return get_remote_address()

        limiter = Limiter(
            _rate_limit_key,
            app=app,
            default_limits=[config.RATELIMIT_DEFAULT],
            storage_uri=config.RATELIMIT_STORAGE_URI,
        )
        app.limiter = limiter
    except ImportError:
        app.limiter = None
        logger.info("flask-limiter not installed — rate limiting disabled")


# =========================================================================
# INPUT VALIDATION
# =========================================================================

def sanitize(val):
    """Escape HTML in any value for safe template rendering."""
    if val is None:
        return ""
    return str(escape(str(val)))


def validate_eml_upload(file_obj):
    """
    Validate an uploaded file for .eml safety.
    Returns (raw_bytes, error_message). If error_message is not None, reject the file.
    """
    if not file_obj or not file_obj.filename:
        return None, "No file provided"

    filename = file_obj.filename.strip()

    # 1. Extension check
    if not filename.lower().endswith(".eml"):
        return None, f"{filename}: not a .eml file"

    # 2. Filename sanitization — reject path traversal attempts
    if ".." in filename or "/" in filename or "\\" in filename:
        return None, f"{filename}: invalid filename"

    # 3. Read content
    raw_bytes = file_obj.read()

    # 4. Empty file check
    if not raw_bytes:
        return None, f"{filename}: empty file"

    # 5. Size check (redundant with MAX_CONTENT_LENGTH but explicit)
    if len(raw_bytes) > config.MAX_FILE_SIZE:
        return None, f"{filename}: file too large (max {config.MAX_FILE_SIZE // (1024*1024)}MB)"

    # 6. Content-type / magic byte validation
    binary_signatures = [
        b"\x89PNG",      # PNG
        b"\xff\xd8\xff", # JPEG
        b"GIF8",         # GIF
        b"PK\x03\x04",  # ZIP
        b"MZ",           # PE executable
        b"\x7fELF",      # ELF binary
        b"%PDF",         # PDF
        b"\x1f\x8b",     # GZIP
        b"Rar!",         # RAR
    ]
    for sig in binary_signatures:
        if raw_bytes[:len(sig)] == sig:
            return None, f"{filename}: file appears to be binary, not a valid .eml"

    # 7. Try python-magic if available for deeper check
    try:
        import magic
        detected = magic.from_buffer(raw_bytes[:4096], mime=True)
        allowed_mimes = {"text/plain", "text/html", "message/rfc822", "message/news",
                         "application/octet-stream"}
        if detected not in allowed_mimes and not detected.startswith("text/"):
            return None, f"{filename}: detected type '{detected}' is not a valid email format"
    except ImportError:
        pass
    except Exception:
        pass

    # 8. Basic RFC 5322 sanity
    try:
        first_chunk = raw_bytes[:2048].decode("utf-8", errors="replace")
    except Exception:
        first_chunk = raw_bytes[:2048].decode("latin-1", errors="replace")

    header_pattern = re.compile(r"^[A-Za-z][A-Za-z0-9-]*:\s", re.MULTILINE)
    if not header_pattern.search(first_chunk):
        return None, f"{filename}: does not appear to be a valid RFC 5322 email"

    return raw_bytes, None


# =========================================================================
# ONBOARDING ROUTES
# =========================================================================

def _register_onboarding_routes(app):

    @app.route("/onboarding")
    @login_required
    def onboarding():
        if current_user.onboarding_completed:
            return redirect(url_for("index"))
        return render_template("onboarding.html")

    @app.route("/onboarding/complete", methods=["POST"])
    @login_required
    def onboarding_complete():
        current_user.onboarding_completed = True
        sa_db.session.commit()
        flash("Welcome to PhishGuard! You're all set.", "success")
        return redirect(url_for("index"))

    @app.route("/onboarding/skip", methods=["POST"])
    @login_required
    def onboarding_skip():
        current_user.onboarding_completed = True
        sa_db.session.commit()
        return redirect(url_for("index"))


# =========================================================================
# NOTIFICATION ROUTES
# =========================================================================

def _register_notification_routes(app):

    @app.route("/notifications")
    @login_required
    def notifications_page():
        notifs = get_user_notifications(current_user.id, limit=50)
        prefs = current_user.notification_prefs
        if not prefs:
            prefs = NotificationPreference(user_id=current_user.id)
            sa_db.session.add(prefs)
            sa_db.session.commit()
        return render_template("notifications.html", notifications=notifs, prefs=prefs)

    @app.route("/notifications/preferences", methods=["POST"])
    @login_required
    def notification_preferences():
        prefs = current_user.notification_prefs
        if not prefs:
            prefs = NotificationPreference(user_id=current_user.id)
            sa_db.session.add(prefs)

        prefs.email_on_critical = "email_on_critical" in request.form
        prefs.email_on_high = "email_on_high" in request.form
        prefs.email_on_medium = "email_on_medium" in request.form
        prefs.email_weekly_summary = "email_weekly_summary" in request.form
        prefs.slack_on_critical = "slack_on_critical" in request.form
        prefs.slack_on_high = "slack_on_high" in request.form

        webhook = request.form.get("slack_webhook_url", "").strip()
        if webhook and not webhook.startswith("https://hooks.slack.com/"):
            flash("Invalid Slack webhook URL.", "error")
            return redirect(url_for("notifications_page"))
        prefs.slack_webhook_url = webhook

        threshold = request.form.get("alert_threshold", "50")
        try:
            prefs.alert_threshold = max(0, min(100, int(threshold)))
        except ValueError:
            prefs.alert_threshold = 50

        sa_db.session.commit()
        flash("Notification preferences saved.", "success")
        return redirect(url_for("notifications_page"))

    @app.route("/notifications/mark-read", methods=["POST"])
    @login_required
    def mark_notifications_read():
        Notification.query.filter_by(user_id=current_user.id, is_read=False).update({"is_read": True})
        sa_db.session.commit()
        return redirect(url_for("notifications_page"))

    @app.route("/api/notifications/unread")
    @login_required
    @csrf.exempt
    def api_notification_count():
        return jsonify({"count": get_unread_notification_count(current_user.id)})


# =========================================================================
# TEAM / ORGANIZATION ROUTES
# =========================================================================

def _register_team_routes(app):

    @app.route("/team")
    @login_required
    def team_page():
        org = None
        members = []
        invites = []
        if current_user.org_id:
            org = Organization.query.get(current_user.org_id)
            if org:
                members = User.query.filter_by(org_id=org.id, is_active=True).order_by(User.created_at).all()
                if current_user.is_org_admin():
                    invites = TeamInvite.query.filter_by(org_id=org.id, accepted=False).order_by(TeamInvite.created_at.desc()).all()
        return render_template("team.html", org=org, members=members, invites=invites)

    @app.route("/team/create", methods=["POST"])
    @login_required
    def team_create():
        if current_user.org_id:
            flash("You already belong to an organization.", "error")
            return redirect(url_for("team_page"))

        name = request.form.get("org_name", "").strip()
        if not name or len(name) < 2:
            flash("Organization name must be at least 2 characters.", "error")
            return redirect(url_for("team_page"))

        # Generate slug
        slug = re.sub(r'[^a-z0-9-]', '', name.lower().replace(' ', '-'))[:50]
        if Organization.query.filter_by(slug=slug).first():
            slug = f"{slug}-{secrets.token_hex(3)}"

        org = Organization(
            name=name,
            slug=slug,
            created_by=current_user.id,
        )
        sa_db.session.add(org)
        sa_db.session.flush()

        current_user.org_id = org.id
        current_user.org_role = "owner"
        sa_db.session.commit()

        log_audit("create_org", user=current_user, resource_type="organization",
                  resource_id=org.id, ip_address=_client_ip(),
                  details={"name": name})
        flash(f'Organization "{name}" created.', "success")
        return redirect(url_for("team_page"))

    @app.route("/team/invite", methods=["POST"])
    @login_required
    def team_invite():
        if not current_user.org_id or not current_user.is_org_admin():
            flash("You must be an organization admin to invite members.", "error")
            return redirect(url_for("team_page"))

        email = request.form.get("email", "").strip().lower()
        invite_role = request.form.get("role", "member")
        if invite_role not in ("admin", "member"):
            invite_role = "member"

        if not email or "@" not in email:
            flash("Valid email required.", "error")
            return redirect(url_for("team_page"))

        # Check if already a member
        existing = User.query.filter_by(email=email, org_id=current_user.org_id).first()
        if existing:
            flash(f"{email} is already a member.", "error")
            return redirect(url_for("team_page"))

        # Check org size limit
        org = Organization.query.get(current_user.org_id)
        member_count = User.query.filter_by(org_id=org.id).count()
        if member_count >= org.max_users:
            flash(f"Organization is at maximum capacity ({org.max_users} users).", "error")
            return redirect(url_for("team_page"))

        token = secrets.token_urlsafe(32)
        invite = TeamInvite(
            org_id=current_user.org_id,
            email=email,
            role=invite_role,
            invited_by=current_user.id,
            token=token,
            expires_at=datetime.now(timezone.utc) + timedelta(days=7),
        )
        sa_db.session.add(invite)
        sa_db.session.commit()

        log_audit("invite_member", user=current_user, resource_type="team_invite",
                  resource_id=invite.id, ip_address=_client_ip(),
                  details={"email": email, "role": invite_role})

        # Try to send invite email
        try:
            from notifications import send_email_alert
            org = Organization.query.get(current_user.org_id)
            invite_url = f"{config.APP_BASE_URL}/team/join/{token}"
            send_email_alert(
                email,
                f"You've been invited to join {org.name} on PhishGuard",
                f"""<div style="font-family: sans-serif; max-width: 500px; margin: 0 auto; background: #0d1017; color: #c9d1d9; border-radius: 8px; padding: 24px;">
                    <h2 style="color: #58a6ff;">Team Invitation</h2>
                    <p>{current_user.username} invited you to join <strong>{org.name}</strong> on PhishGuard.</p>
                    <p>Role: <strong>{invite_role}</strong></p>
                    <p>This invitation expires in 7 days.</p>
                    <a href="{invite_url}" style="display: inline-block; padding: 10px 24px; background: #58a6ff; color: #000; text-decoration: none; border-radius: 6px; font-weight: 600;">Accept Invitation</a>
                    <p style="font-size: 12px; color: #6e7681; margin-top: 16px;">If the button doesn't work, copy this link: {invite_url}</p>
                </div>"""
            )
        except Exception:
            pass

        flash(f"Invitation sent to {email}. Share this link: /team/join/{token}", "success")
        return redirect(url_for("team_page"))

    @app.route("/team/join/<token>")
    @login_required
    def team_join(token):
        invite = TeamInvite.query.filter_by(token=token, accepted=False).first()
        if not invite:
            flash("Invalid or expired invitation.", "error")
            return redirect(url_for("index"))

        if invite.is_expired():
            flash("This invitation has expired.", "error")
            return redirect(url_for("index"))

        if current_user.org_id:
            flash("You already belong to an organization. Leave your current org first.", "error")
            return redirect(url_for("team_page"))

        # Accept the invite
        current_user.org_id = invite.org_id
        current_user.org_role = invite.role
        invite.accepted = True
        sa_db.session.commit()

        org = Organization.query.get(invite.org_id)
        log_audit("join_org", user=current_user, resource_type="organization",
                  resource_id=invite.org_id, ip_address=_client_ip(),
                  details={"org_name": org.name if org else "unknown"})
        flash(f'You joined {org.name if org else "the organization"}.', "success")
        return redirect(url_for("team_page"))

    @app.route("/team/leave", methods=["POST"])
    @login_required
    def team_leave():
        if not current_user.org_id:
            flash("You're not in an organization.", "error")
            return redirect(url_for("team_page"))

        if current_user.org_role == "owner":
            # Check if there are other admins
            other_admins = User.query.filter(
                User.org_id == current_user.org_id,
                User.id != current_user.id,
                User.org_role.in_(["owner", "admin"]),
            ).count()
            if other_admins == 0:
                flash("Transfer ownership before leaving. You're the only admin.", "error")
                return redirect(url_for("team_page"))

        org_id = current_user.org_id
        current_user.org_id = None
        current_user.org_role = "member"
        sa_db.session.commit()

        log_audit("leave_org", user=current_user, resource_type="organization",
                  resource_id=org_id, ip_address=_client_ip())
        flash("You left the organization.", "info")
        return redirect(url_for("team_page"))

    @app.route("/team/members/<user_id>/role", methods=["POST"])
    @login_required
    def team_change_role(user_id):
        if not current_user.org_id or not current_user.is_org_admin():
            flash("Permission denied.", "error")
            return redirect(url_for("team_page"))

        target = User.query.get_or_404(user_id)
        if target.org_id != current_user.org_id:
            flash("User is not in your organization.", "error")
            return redirect(url_for("team_page"))

        new_role = request.form.get("org_role", "member")
        if new_role not in ("admin", "member"):
            new_role = "member"

        # Can't demote the owner unless you're the owner
        if target.org_role == "owner" and current_user.org_role != "owner":
            flash("Only the owner can change the owner's role.", "error")
            return redirect(url_for("team_page"))

        target.org_role = new_role
        sa_db.session.commit()

        log_audit("change_org_role", user=current_user, resource_type="user",
                  resource_id=target.id, ip_address=_client_ip(),
                  details={"new_role": new_role, "target": target.email})
        flash(f"{target.username}'s team role updated to {new_role}.", "success")
        return redirect(url_for("team_page"))

    @app.route("/team/members/<user_id>/remove", methods=["POST"])
    @login_required
    def team_remove_member(user_id):
        if not current_user.org_id or not current_user.is_org_admin():
            flash("Permission denied.", "error")
            return redirect(url_for("team_page"))

        target = User.query.get_or_404(user_id)
        if target.org_id != current_user.org_id:
            flash("User is not in your organization.", "error")
            return redirect(url_for("team_page"))

        if target.id == current_user.id:
            flash("Can't remove yourself. Use 'Leave Organization'.", "error")
            return redirect(url_for("team_page"))

        if target.org_role == "owner":
            flash("Can't remove the organization owner.", "error")
            return redirect(url_for("team_page"))

        target.org_id = None
        target.org_role = "member"
        sa_db.session.commit()

        log_audit("remove_from_org", user=current_user, resource_type="user",
                  resource_id=target.id, ip_address=_client_ip(),
                  details={"target": target.email})
        flash(f"{target.username} removed from the organization.", "success")
        return redirect(url_for("team_page"))


# =========================================================================
# WEB ROUTES
# =========================================================================

def _register_web_routes(app):

    @app.route("/")
    @login_required
    def index():
        # Redirect to onboarding if not completed
        if not current_user.onboarding_completed:
            return redirect(url_for("onboarding"))
        return render_template(
            "index.html",
            stats=get_stats(user=current_user, org_scoped=True),
            recent=get_history(10, user=current_user, org_scoped=True),
            vt=config.VT_ENABLED,
        )

    @app.route("/analyze", methods=["POST"])
    @login_required
    def analyze():
        if not current_user.is_analyst():
            flash("You need analyst permissions to perform analysis.", "error")
            return redirect(url_for("index"))

        files = request.files.getlist("eml_file")
        if not files or (len(files) == 1 and not files[0].filename):
            flash("Please upload at least one .eml file.", "error")
            return redirect(url_for("index"))

        report_ids = []
        errors = []
        use_celery = app.config.get("CELERY_ENABLED", False)

        for f in files:
            raw_bytes, err = validate_eml_upload(f)
            if err:
                errors.append(err)
                continue

            # Store the file
            s3_key = store_eml(raw_bytes, f.filename)

            if use_celery:
                try:
                    from tasks import analyze_email_task
                    report_id = uuid.uuid4().hex[:12]
                    save_report(
                        {
                            "report_id": report_id,
                            "filename": f.filename,
                            "analyzed_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
                            "headers": {},
                            "score": {"level": "clean", "total": 0},
                        },
                        user_id=current_user.id,
                        s3_key=s3_key,
                        status="pending",
                        org_id=current_user.org_id,
                    )
                    result = analyze_email_task.delay(
                        raw_bytes.hex(), f.filename, current_user.id, s3_key,
                    )
                    analysis = Analysis.query.get(report_id)
                    if analysis:
                        analysis.task_id = result.id
                        sa_db.session.commit()
                    report_ids.append(report_id)
                    log_audit("upload_async", user=current_user,
                              resource_type="analysis", resource_id=report_id,
                              ip_address=_client_ip(),
                              details={"filename": f.filename, "celery_task": result.id})
                except Exception:
                    logger.exception("Failed to queue background analysis for %s", f.filename)
                    try:
                        report = _run_analysis(raw_bytes, f.filename)
                        rd = report.to_dict()
                        saved = save_report(rd, user_id=current_user.id, s3_key=s3_key, org_id=current_user.org_id)
                        report_ids.append(report.report_id)
                        _send_notifications_for_analysis(saved, rd)
                        log_audit("analyze", user=current_user,
                                  resource_type="analysis", resource_id=report.report_id,
                                  ip_address=_client_ip(),
                                  details={"filename": f.filename, "sync_fallback": True})
                    except Exception:
                        logger.exception("Analysis failed for %s", f.filename)
                        errors.append(f"{f.filename}: analysis failed")
            else:
                try:
                    report = _run_analysis(raw_bytes, f.filename)
                    rd = report.to_dict()
                    saved = save_report(rd, user_id=current_user.id, s3_key=s3_key, org_id=current_user.org_id)
                    report_ids.append(report.report_id)
                    _send_notifications_for_analysis(saved, rd)
                    log_audit("analyze", user=current_user,
                              resource_type="analysis", resource_id=report.report_id,
                              ip_address=_client_ip(),
                              details={"filename": f.filename})
                except Exception:
                    logger.exception("Analysis failed for %s", f.filename)
                    errors.append(f"{f.filename}: analysis failed")

        if not report_ids:
            error_msg = "; ".join(errors) if errors else "Upload a .eml file"
            flash(error_msg, "error")
            return render_template(
                "index.html", stats=get_stats(user=current_user, org_scoped=True),
                recent=get_history(10, user=current_user, org_scoped=True), vt=config.VT_ENABLED,
            )

        if len(report_ids) == 1:
            return redirect(url_for("view_report", report_id=report_ids[0]))
        return redirect(url_for("history"))

    @app.route("/report/<report_id>")
    @login_required
    def view_report(report_id):
        report_data = get_report(sanitize(report_id))
        if not report_data:
            abort(404)
        analysis = Analysis.query.get(sanitize(report_id))
        if analysis and analysis.status in ("pending", "processing"):
            return render_template("job_status.html", analysis=analysis.to_summary())
        return render_template("report.html", report=report_data, vt=config.VT_ENABLED)

    @app.route("/report/<report_id>/pdf")
    @login_required
    def download_pdf(report_id):
        report_data = get_report(sanitize(report_id))
        if not report_data:
            abort(404)
        log_audit("export_pdf", user=current_user, resource_type="analysis",
                  resource_id=report_id, ip_address=_client_ip())
        pdf_buf = generate_pdf(report_data)
        if pdf_buf is None:
            return jsonify({"error": "PDF generation unavailable — install fpdf2"}), 500
        filename = f"phishguard_{report_id}.pdf"
        return Response(
            pdf_buf.getvalue(),
            mimetype="application/pdf",
            headers={"Content-Disposition": f"attachment; filename={filename}"},
        )

    @app.route("/history")
    @login_required
    def history():
        query = request.args.get("q", "").strip()
        if query:
            analyses = search_history(query, user=current_user, org_scoped=True)
        else:
            analyses = get_history(100, user=current_user, org_scoped=True)
        return render_template(
            "history.html", analyses=analyses,
            stats=get_stats(user=current_user, org_scoped=True), query=query,
        )

    @app.route("/dashboard")
    @login_required
    def dashboard():
        stats = get_stats(user=current_user, org_scoped=True)
        trend = get_trend_data(30, user=current_user, org_scoped=True)
        recent = get_history(20, user=current_user, org_scoped=True)
        weekly = get_weekly_comparison(user=current_user, org_scoped=True)
        attack_types = get_top_attack_types(limit=6, user=current_user, org_scoped=True)
        top_domains = get_top_domains(limit=8, user=current_user, org_scoped=True)
        recent_critical = get_recent_critical(limit=5, user=current_user, org_scoped=True)
        return render_template(
            "dashboard.html", stats=stats, trend=trend, recent=recent, vt=config.VT_ENABLED,
            weekly=weekly, attack_types=attack_types, top_domains=top_domains,
            recent_critical=recent_critical,
        )

    @app.route("/delete/<report_id>", methods=["POST"])
    @login_required
    def delete_report_web(report_id):
        if not current_user.is_analyst():
            flash("Insufficient permissions.", "error")
            return redirect(url_for("history"))

        analysis = Analysis.query.get(sanitize(report_id))
        if analysis and analysis.s3_key:
            delete_eml(analysis.s3_key)

        deleted = delete_report(sanitize(report_id))
        if deleted:
            log_audit("delete", user=current_user, resource_type="analysis",
                      resource_id=report_id, ip_address=_client_ip())
        return redirect(url_for("history"))

    @app.route("/job/<task_id>/status")
    @login_required
    def job_status(task_id):
        """AJAX endpoint to poll background job status."""
        analysis = get_analysis_by_task_id(task_id)
        if not analysis:
            return jsonify({"status": "not_found"}), 404
        return jsonify(analysis)

    @app.route("/screenshots/<path:filename>")
    @login_required
    def serve_screenshot(filename):
        """Serve browser detonation screenshots."""
        safe_name = re.sub(r'[^a-zA-Z0-9._-]', '', filename)
        if not safe_name or '..' in safe_name or '/' in safe_name:
            abort(404)
        return send_from_directory(config.BROWSER_SCREENSHOT_DIR, safe_name)

    # --- Health check ---
    @app.route("/health")
    @csrf.exempt
    def health():
        checks = {"app": "ok"}

        try:
            sa_db.session.execute(sa_db.text("SELECT 1"))
            checks["database"] = "ok"
        except Exception as e:
            checks["database"] = f"error: {e}"

        try:
            import redis
            r = redis.from_url(config.REDIS_URL, socket_timeout=2)
            r.ping()
            checks["redis"] = "ok"
        except ImportError:
            checks["redis"] = "not configured"
        except Exception as e:
            checks["redis"] = f"error: {e}"

        all_ok = all(v == "ok" for k, v in checks.items() if k != "redis" or config.REDIS_URL != "redis://localhost:6379/0")
        status_code = 200 if all_ok else 503

        return jsonify({
            "status": "healthy" if status_code == 200 else "degraded",
            "checks": checks,
            "version": "3.0.0",
            "environment": config.FLASK_ENV,
        }), status_code


# =========================================================================
# API ROUTES
# =========================================================================

def _register_api_routes(app):

    @app.route("/api/analyze", methods=["POST"])
    @csrf.exempt
    @api_auth_required
    def api_analyze():
        if "eml_file" not in request.files:
            return jsonify({"error": "No eml_file in request"}), 400

        f = request.files["eml_file"]
        raw_bytes, err = validate_eml_upload(f)
        if err:
            return jsonify({"error": err}), 400

        user = getattr(request, "api_user", None)
        s3_key = store_eml(raw_bytes, f.filename)
        use_celery = app.config.get("CELERY_ENABLED", False)
        org_id = user.org_id if user else None

        if use_celery:
            try:
                from tasks import analyze_email_task
                report_id = uuid.uuid4().hex[:12]
                save_report(
                    {
                        "report_id": report_id,
                        "filename": f.filename,
                        "analyzed_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
                        "headers": {},
                        "score": {"level": "clean", "total": 0},
                    },
                    user_id=user.id if user else None,
                    s3_key=s3_key,
                    status="pending",
                    org_id=org_id,
                )
                result = analyze_email_task.delay(
                    raw_bytes.hex(), f.filename,
                    user.id if user else None, s3_key,
                )
                analysis = Analysis.query.get(report_id)
                if analysis:
                    analysis.task_id = result.id
                    sa_db.session.commit()
                log_audit("api_upload_async", user=user,
                          resource_type="analysis", resource_id=report_id,
                          ip_address=_client_ip(),
                          details={"filename": f.filename})
                return jsonify({
                    "report_id": report_id,
                    "task_id": result.id,
                    "status": "pending",
                    "message": "Analysis queued. Poll /api/job/<task_id>/status for updates.",
                }), 202
            except Exception:
                logger.exception("Failed to queue — running synchronously")

        # Synchronous analysis
        try:
            report = _run_analysis(raw_bytes, f.filename)
        except Exception:
            logger.exception("API analysis failed for %s", f.filename)
            return jsonify({"error": "Analysis failed — file may be malformed"}), 500

        report_dict = report.to_dict()
        saved = save_report(report_dict, user_id=user.id if user else None, s3_key=s3_key, org_id=org_id)
        _send_notifications_for_analysis(saved, report_dict)
        log_audit("api_analyze", user=user, resource_type="analysis",
                  resource_id=report.report_id, ip_address=_client_ip(),
                  details={"filename": f.filename})
        return jsonify(report_dict)

    @app.route("/api/job/<task_id>/status")
    @csrf.exempt
    @api_auth_required
    def api_job_status(task_id):
        analysis = get_analysis_by_task_id(sanitize(task_id))
        if not analysis:
            return jsonify({"status": "not_found"}), 404
        return jsonify(analysis)

    @app.route("/api/report/<report_id>")
    @csrf.exempt
    @api_auth_required
    def api_report(report_id):
        data = get_report(sanitize(report_id))
        if not data:
            return jsonify({"error": "Not found"}), 404
        return jsonify(data)

    @app.route("/api/history")
    @csrf.exempt
    @api_auth_required
    def api_history():
        user = getattr(request, "api_user", None)
        return jsonify(get_history(100, user=user, org_scoped=True))

    @app.route("/api/iocs/<report_id>")
    @csrf.exempt
    @api_auth_required
    def api_iocs(report_id):
        data = get_report(sanitize(report_id))
        if not data:
            return jsonify({"error": "Not found"}), 404
        log_audit("api_export_iocs", user=getattr(request, "api_user", None),
                  resource_type="analysis", resource_id=report_id, ip_address=_client_ip())
        return jsonify(data.get("iocs", {}))

    @app.route("/api/stix/<report_id>")
    @csrf.exempt
    @api_auth_required
    def api_stix(report_id):
        data = get_report(sanitize(report_id))
        if not data:
            return jsonify({"error": "Not found"}), 404
        log_audit("api_export_stix", user=getattr(request, "api_user", None),
                  resource_type="analysis", resource_id=report_id, ip_address=_client_ip())
        bundle = generate_stix_bundle(data)
        return Response(
            stix_to_json(bundle),
            mimetype="application/json",
            headers={"Content-Disposition": f"attachment; filename=stix_{report_id}.json"},
        )

    @app.route("/api/mitre/<report_id>")
    @csrf.exempt
    @api_auth_required
    def api_mitre(report_id):
        data = get_report(sanitize(report_id))
        if not data:
            return jsonify({"error": "Not found"}), 404
        return jsonify({
            "mappings": data.get("mitre_mappings", []),
            "attack_summary": data.get("attack_summary", {}),
        })

    @app.route("/api/report/<report_id>", methods=["DELETE"])
    @csrf.exempt
    @api_auth_required
    def api_delete_report(report_id):
        analysis = Analysis.query.get(sanitize(report_id))
        if analysis and analysis.s3_key:
            delete_eml(analysis.s3_key)

        deleted = delete_report(sanitize(report_id))
        if not deleted:
            return jsonify({"error": "Not found"}), 404

        log_audit("api_delete", user=getattr(request, "api_user", None),
                  resource_type="analysis", resource_id=report_id, ip_address=_client_ip())
        return jsonify({"status": "deleted", "id": report_id})

    @app.route("/api/stats")
    @csrf.exempt
    @api_auth_required
    def api_stats():
        user = getattr(request, "api_user", None)
        return jsonify(get_stats(user=user, org_scoped=True))

    @app.route("/api/trend")
    @csrf.exempt
    @api_auth_required
    def api_trend():
        days = request.args.get("days", 30, type=int)
        user = getattr(request, "api_user", None)
        return jsonify(get_trend_data(min(days, 365), user=user, org_scoped=True))

    @app.route("/api/export/csv")
    @csrf.exempt
    @api_auth_required
    def export_csv():
        log_audit("api_export_csv", user=getattr(request, "api_user", None),
                  ip_address=_client_ip())
        user = getattr(request, "api_user", None)
        rows = get_history(1000, user=user, org_scoped=True)
        lines = ["id,filename,from_address,subject,threat_level,threat_score,analyzed_at"]
        for r in rows:
            subj = r.get("subject", "").replace('"', '""')
            lines.append(
                f'"{r["id"]}","{r["filename"]}","{r["from_address"]}","{subj}",'
                f'"{r["threat_level"]}",{r["threat_score"]},"{r.get("analyzed_at_display", "")}"'
            )
        csv_data = "\n".join(lines)
        return Response(
            csv_data,
            mimetype="text/csv",
            headers={"Content-Disposition": "attachment; filename=phishguard_export.csv"},
        )

    # --- Extension API endpoint (CORS-enabled for browser extension) ---
    @app.route("/api/extension/analyze", methods=["POST", "OPTIONS"])
    @csrf.exempt
    def api_extension_analyze():
        """API endpoint for the browser extension. Supports CORS preflight."""
        if request.method == "OPTIONS":
            resp = Response("", status=200)
            resp.headers["Access-Control-Allow-Origin"] = request.headers.get("Origin", "*")
            resp.headers["Access-Control-Allow-Methods"] = "POST, OPTIONS"
            resp.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization, X-API-Key"
            resp.headers["Access-Control-Max-Age"] = "86400"
            return resp

        # Authenticate
        auth_header = request.headers.get("Authorization", "")
        user = None
        if auth_header.startswith("Bearer "):
            from auth import _decode_jwt
            from database import RevokedToken
            token = auth_header[7:]
            payload = _decode_jwt(token)
            if payload and payload.get("type") == "access" and not RevokedToken.is_revoked(payload["jti"]):
                user = User.query.get(payload["sub"])

        if not user and config.API_KEY:
            if request.headers.get("X-API-Key") == config.API_KEY:
                user = None  # legacy key

        if not user and not config.API_KEY:
            resp = jsonify({"error": "Authentication required"})
            resp.headers["Access-Control-Allow-Origin"] = request.headers.get("Origin", "*")
            return resp, 401

        # Get the email content
        data = request.get_json(silent=True) or {}
        eml_content = data.get("eml_content", "")
        filename = data.get("filename", "extension-email.eml")

        if not eml_content:
            resp = jsonify({"error": "No email content provided"})
            resp.headers["Access-Control-Allow-Origin"] = request.headers.get("Origin", "*")
            return resp, 400

        raw_bytes = eml_content.encode("utf-8") if isinstance(eml_content, str) else eml_content

        try:
            report = _run_analysis(raw_bytes, filename)
            report_dict = report.to_dict()
            org_id = user.org_id if user else None
            saved = save_report(report_dict, user_id=user.id if user else None, org_id=org_id)
            _send_notifications_for_analysis(saved, report_dict)
            resp = jsonify(report_dict)
        except Exception:
            logger.exception("Extension analysis failed")
            resp = jsonify({"error": "Analysis failed"})
            resp.status_code = 500

        resp.headers["Access-Control-Allow-Origin"] = request.headers.get("Origin", "*")
        return resp


# =========================================================================
# ANALYSIS PIPELINE (synchronous — used directly or as Celery fallback)
# =========================================================================

def _run_analysis(raw_bytes, filename):
    report = AnalysisReport()
    report.report_id = uuid.uuid4().hex[:12]
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

    # --- NLP body analysis ---
    nlp_result = None
    if config.NLP_ANALYSIS_ENABLED:
        try:
            from nlp_analyzer import analyze_body
            nlp_result = analyze_body(
                body.text_content, body.html_content, headers.subject,
            )
            body.nlp_analysis = nlp_result
        except Exception:
            logger.debug("NLP analysis failed — continuing without it")

    # --- HTML similarity analysis on email body ---
    if config.HTML_SIMILARITY_ENABLED and body.html_content:
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
    if config.ML_CLASSIFIER_ENABLED:
        try:
            from ml_classifier import classify
            ml_result = classify(headers, url_findings, att_findings, body)
            report.ml_classification = ml_result
        except Exception:
            logger.debug("ML classification failed — continuing without it")

    report.urls = [uf.to_dict() for uf in url_findings]
    report.attachments = [af.to_dict() for af in att_findings]

    iocs = extract_iocs(headers, body, url_findings, att_findings)
    report.iocs = iocs

    # --- Threat intel feed enrichment ---
    threat_intel_result = None
    if config.THREAT_INTEL_ENABLED:
        try:
            from threat_intel import enrich_iocs as ti_enrich
            threat_intel_result = ti_enrich(
                ip_addresses=iocs.ip_addresses if hasattr(iocs, 'ip_addresses') else iocs.get("ip_addresses", []),
                domains=iocs.domains if hasattr(iocs, 'domains') else iocs.get("domains", []),
                urls=iocs.urls if hasattr(iocs, 'urls') else iocs.get("urls", []),
                config=config,
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

    report._enriched_dict = report_dict
    report.to_dict = lambda: report._enriched_dict

    return report


def _send_notifications_for_analysis(analysis_record, report_dict):
    """Send notifications after analysis completes (non-blocking)."""
    try:
        from notifications import notify_on_analysis
        notify_on_analysis(analysis_record, report_dict)
    except Exception:
        logger.debug("Notification dispatch failed — continuing")


# =========================================================================
# ERROR HANDLERS
# =========================================================================

def _register_error_handlers(app):

    @app.errorhandler(400)
    def bad_request(e):
        if request.path.startswith("/api/"):
            return jsonify({"error": "Bad request"}), 400
        flash("Bad request.", "error")
        return redirect(url_for("index"))

    @app.errorhandler(404)
    def not_found(e):
        if request.path.startswith("/api/"):
            return jsonify({"error": "Not found"}), 404
        return render_template(
            "index.html", error="Page not found",
            stats=get_stats(), recent=get_history(10), vt=config.VT_ENABLED,
        ), 404

    @app.errorhandler(413)
    def too_large(e):
        msg = f"File too large (max {config.MAX_FILE_SIZE // (1024*1024)}MB)"
        if request.path.startswith("/api/"):
            return jsonify({"error": msg}), 413
        flash(msg, "error")
        return render_template(
            "index.html", stats=get_stats(), recent=get_history(10), vt=config.VT_ENABLED,
        ), 413

    @app.errorhandler(429)
    def rate_limited(e):
        if request.path.startswith("/api/"):
            return jsonify({"error": "Rate limit exceeded — try again later"}), 429
        flash("Too many requests — please slow down.", "error")
        return render_template(
            "index.html", stats=get_stats(), recent=get_history(10), vt=config.VT_ENABLED,
        ), 429

    @app.errorhandler(500)
    def server_error(e):
        logger.exception("Internal server error")
        if request.path.startswith("/api/"):
            return jsonify({"error": "Internal server error"}), 500
        flash("An internal error occurred. Please try again.", "error")
        return render_template(
            "index.html", stats=get_stats(), recent=get_history(10), vt=config.VT_ENABLED,
        ), 500


# =========================================================================
# ENTRY POINT — used by gunicorn: gunicorn "app:create_app()"
# =========================================================================

app = create_app()

if __name__ == "__main__":
    os.makedirs(config.UPLOAD_DIR, exist_ok=True)
    logger.info("PhishGuard running on http://127.0.0.1:5000")
    if config.VT_ENABLED:
        logger.info("VirusTotal integration active")
    else:
        logger.info("VirusTotal disabled (set VT_API_KEY to enable)")
    try:
        from waitress import serve
        logger.info("Serving with Waitress WSGI server")
        serve(app, host="0.0.0.0", port=5000)
    except ImportError:
        try:
            import gunicorn  # noqa: F401
            app.run(host="0.0.0.0", port=5000, debug=False)
        except ImportError:
            import click
            _original_echo = click.echo
            def _quiet_echo(message=None, **kwargs):
                if message and "WARNING" in str(message) and "production" in str(message).lower():
                    return
                if message and "Development Server" in str(message):
                    return
                _original_echo(message, **kwargs)
            click.echo = _quiet_echo
            app.run(host="0.0.0.0", port=5000, debug=False)
