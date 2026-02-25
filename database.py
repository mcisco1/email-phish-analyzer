"""
Database layer — SQLAlchemy ORM with PostgreSQL (production) / SQLite (dev).

Provides the User, Analysis, AuditLog, RevokedToken, Organization,
NotificationPreference, Notification, and TeamInvite models plus all
helper functions the rest of the app uses (save_report, get_report, etc.).
"""

import json
import time
import uuid
from datetime import datetime, timezone, timedelta

from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()


# =========================================================================
# MODELS
# =========================================================================

class Organization(db.Model):
    """A company/team account that groups multiple users together."""
    __tablename__ = "organizations"

    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = db.Column(db.String(255), nullable=False)
    slug = db.Column(db.String(100), unique=True, nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    created_by = db.Column(db.String(36), nullable=True)

    # Settings
    max_users = db.Column(db.Integer, default=25)
    shared_intel = db.Column(db.Boolean, default=True)

    members = db.relationship("User", backref="organization", lazy="dynamic")
    invites = db.relationship("TeamInvite", backref="organization", lazy="dynamic")

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "slug": self.slug,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "max_users": self.max_users,
            "shared_intel": self.shared_intel,
            "member_count": self.members.count(),
        }


class User(UserMixin, db.Model):
    """Application user — supports local password, Google OAuth, Microsoft OAuth."""
    __tablename__ = "users"

    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    username = db.Column(db.String(150), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256), nullable=True)  # null for OAuth-only users
    role = db.Column(db.String(20), nullable=False, default="viewer")  # admin | analyst | viewer
    is_active = db.Column(db.Boolean, default=True)

    # OAuth provider info
    oauth_provider = db.Column(db.String(20), nullable=True)  # "google" | "microsoft" | null
    oauth_id = db.Column(db.String(255), nullable=True)

    # Onboarding
    onboarding_completed = db.Column(db.Boolean, default=False)

    # Organization / team
    org_id = db.Column(db.String(36), db.ForeignKey("organizations.id"), nullable=True)
    org_role = db.Column(db.String(20), default="member")  # owner | admin | member

    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    last_login = db.Column(db.DateTime, nullable=True)

    # Relationships
    analyses = db.relationship("Analysis", backref="user", lazy="dynamic")
    audit_logs = db.relationship("AuditLog", backref="user", lazy="dynamic")
    notification_prefs = db.relationship("NotificationPreference", backref="user", uselist=False, lazy="joined")
    notifications = db.relationship("Notification", backref="user", lazy="dynamic")

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        if not self.password_hash:
            return False
        return check_password_hash(self.password_hash, password)

    def has_role(self, *roles):
        return self.role in roles

    def is_admin(self):
        return self.role == "admin"

    def is_analyst(self):
        return self.role in ("admin", "analyst")

    def is_org_admin(self):
        return self.org_role in ("owner", "admin")

    def to_dict(self):
        return {
            "id": self.id,
            "email": self.email,
            "username": self.username,
            "role": self.role,
            "is_active": self.is_active,
            "oauth_provider": self.oauth_provider,
            "onboarding_completed": self.onboarding_completed,
            "org_id": self.org_id,
            "org_role": self.org_role,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "last_login": self.last_login.isoformat() if self.last_login else None,
        }


class Analysis(db.Model):
    """Persisted email analysis report."""
    __tablename__ = "analyses"

    id = db.Column(db.String(12), primary_key=True)
    filename = db.Column(db.String(512), nullable=False)
    analyzed_at = db.Column(db.Float, nullable=False, index=True)
    from_address = db.Column(db.String(512), default="")
    subject = db.Column(db.String(1024), default="")
    threat_level = db.Column(db.String(20), default="clean", index=True)
    threat_score = db.Column(db.Integer, default=0)
    report_json = db.Column(db.Text, nullable=False)

    # Link to user who uploaded
    user_id = db.Column(db.String(36), db.ForeignKey("users.id"), nullable=True)

    # Organization scoping
    org_id = db.Column(db.String(36), db.ForeignKey("organizations.id"), nullable=True, index=True)

    # S3 key for the original .eml file
    s3_key = db.Column(db.String(1024), nullable=True)

    # Celery task ID for background jobs
    task_id = db.Column(db.String(64), nullable=True, index=True)
    status = db.Column(db.String(20), default="complete")  # pending | processing | complete | failed

    def to_summary(self):
        analyzed_display = "Unknown"
        try:
            analyzed_display = datetime.fromtimestamp(
                self.analyzed_at, tz=timezone.utc
            ).strftime("%Y-%m-%d %H:%M UTC")
        except (TypeError, ValueError, OSError):
            pass
        return {
            "id": self.id,
            "filename": self.filename,
            "analyzed_at": self.analyzed_at,
            "analyzed_at_display": analyzed_display,
            "from_address": self.from_address,
            "subject": self.subject,
            "threat_level": self.threat_level,
            "threat_score": self.threat_score,
            "status": self.status,
            "user_id": self.user_id,
            "org_id": self.org_id,
        }

    def get_report(self):
        return json.loads(self.report_json)


class NotificationPreference(db.Model):
    """Per-user notification settings."""
    __tablename__ = "notification_preferences"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.String(36), db.ForeignKey("users.id"), unique=True, nullable=False)

    # Email notifications
    email_on_critical = db.Column(db.Boolean, default=True)
    email_on_high = db.Column(db.Boolean, default=True)
    email_on_medium = db.Column(db.Boolean, default=False)
    email_weekly_summary = db.Column(db.Boolean, default=True)

    # Slack notifications
    slack_webhook_url = db.Column(db.String(512), nullable=True)
    slack_on_critical = db.Column(db.Boolean, default=True)
    slack_on_high = db.Column(db.Boolean, default=False)

    # Threshold: minimum score to trigger alert
    alert_threshold = db.Column(db.Integer, default=50)

    def to_dict(self):
        return {
            "email_on_critical": self.email_on_critical,
            "email_on_high": self.email_on_high,
            "email_on_medium": self.email_on_medium,
            "email_weekly_summary": self.email_weekly_summary,
            "slack_webhook_url": self.slack_webhook_url or "",
            "slack_on_critical": self.slack_on_critical,
            "slack_on_high": self.slack_on_high,
            "alert_threshold": self.alert_threshold,
        }


class Notification(db.Model):
    """In-app notification record."""
    __tablename__ = "notifications"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.String(36), db.ForeignKey("users.id"), nullable=False, index=True)
    title = db.Column(db.String(255), nullable=False)
    message = db.Column(db.Text, nullable=False)
    category = db.Column(db.String(50), default="info")  # info | warning | critical | summary
    link = db.Column(db.String(512), nullable=True)
    is_read = db.Column(db.Boolean, default=False, index=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), index=True)

    def to_dict(self):
        return {
            "id": self.id,
            "title": self.title,
            "message": self.message,
            "category": self.category,
            "link": self.link,
            "is_read": self.is_read,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class TeamInvite(db.Model):
    """Pending invitations to join an organization."""
    __tablename__ = "team_invites"

    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    org_id = db.Column(db.String(36), db.ForeignKey("organizations.id"), nullable=False)
    email = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default="member")  # admin | member
    invited_by = db.Column(db.String(36), db.ForeignKey("users.id"), nullable=False)
    token = db.Column(db.String(64), unique=True, nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    expires_at = db.Column(db.DateTime, nullable=False)
    accepted = db.Column(db.Boolean, default=False)

    inviter = db.relationship("User", foreign_keys=[invited_by])

    def is_expired(self):
        return datetime.now(timezone.utc) > self.expires_at

    def to_dict(self):
        return {
            "id": self.id,
            "email": self.email,
            "role": self.role,
            "invited_by": self.inviter.username if self.inviter else "unknown",
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "accepted": self.accepted,
            "expired": self.is_expired(),
        }


class AuditLog(db.Model):
    """Immutable audit trail — every significant action is recorded."""
    __tablename__ = "audit_log"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    user_id = db.Column(db.String(36), db.ForeignKey("users.id"), nullable=True)
    username = db.Column(db.String(150), default="anonymous")
    action = db.Column(db.String(100), nullable=False)  # login, upload, analyze, export, delete, etc.
    resource_type = db.Column(db.String(50), nullable=True)  # analysis, user, etc.
    resource_id = db.Column(db.String(255), nullable=True)
    ip_address = db.Column(db.String(45), nullable=True)
    user_agent = db.Column(db.String(512), nullable=True)
    details = db.Column(db.Text, nullable=True)  # JSON extra data

    def to_dict(self):
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "user_id": self.user_id,
            "username": self.username,
            "action": self.action,
            "resource_type": self.resource_type,
            "resource_id": self.resource_id,
            "ip_address": self.ip_address,
            "details": self.details,
        }


class RevokedToken(db.Model):
    """JWT tokens that have been explicitly revoked (logout, rotation)."""
    __tablename__ = "revoked_tokens"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    jti = db.Column(db.String(128), unique=True, nullable=False, index=True)
    revoked_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    expires_at = db.Column(db.DateTime, nullable=False)  # for cleanup

    @classmethod
    def is_revoked(cls, jti):
        return cls.query.filter_by(jti=jti).first() is not None


# =========================================================================
# DATABASE INITIALIZATION
# =========================================================================

def init_db(app):
    """Create all tables. Call once at startup."""
    db.init_app(app)
    with app.app_context():
        db.create_all()
        _ensure_admin(app)


def _ensure_admin(app):
    """Create a default admin user if none exists."""
    import os
    admin = User.query.filter_by(role="admin").first()
    if not admin:
        admin_email = os.environ.get("ADMIN_EMAIL", "admin@phishguard.local")
        admin_pass = os.environ.get("ADMIN_PASSWORD", "changeme")
        admin = User(
            email=admin_email,
            username="admin",
            role="admin",
            onboarding_completed=True,
        )
        admin.set_password(admin_pass)
        db.session.add(admin)
        db.session.commit()


# =========================================================================
# AUDIT LOGGING HELPER
# =========================================================================

def log_audit(action, user=None, resource_type=None, resource_id=None,
              ip_address=None, user_agent=None, details=None):
    """Write an audit log entry."""
    entry = AuditLog(
        user_id=user.id if user else None,
        username=user.username if user else "anonymous",
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        ip_address=ip_address,
        user_agent=user_agent,
        details=json.dumps(details) if details else None,
    )
    db.session.add(entry)
    db.session.commit()


# =========================================================================
# REPORT CRUD — drop-in replacements for the old sqlite functions
# =========================================================================

def save_report(report_dict, user_id=None, s3_key=None, task_id=None, status="complete", org_id=None):
    headers = report_dict.get("headers", {})
    score = report_dict.get("score", {})
    analysis = Analysis.query.get(report_dict["report_id"])
    if analysis:
        analysis.report_json = json.dumps(report_dict)
        analysis.threat_level = score.get("level", "clean")
        analysis.threat_score = score.get("total", 0)
        analysis.status = status
    else:
        analysis = Analysis(
            id=report_dict["report_id"],
            filename=report_dict["filename"],
            analyzed_at=time.time(),
            from_address=headers.get("from_address", ""),
            subject=headers.get("subject", ""),
            threat_level=score.get("level", "clean"),
            threat_score=score.get("total", 0),
            report_json=json.dumps(report_dict),
            user_id=user_id,
            org_id=org_id,
            s3_key=s3_key,
            task_id=task_id,
            status=status,
        )
        db.session.add(analysis)
    db.session.commit()
    return analysis


def get_report(report_id):
    analysis = Analysis.query.get(report_id)
    if analysis:
        return json.loads(analysis.report_json)
    return None


def get_history(limit=50, user=None, org_scoped=False):
    query = Analysis.query
    if user and org_scoped and user.org_id:
        if user.is_admin() or user.is_org_admin():
            query = query.filter(Analysis.org_id == user.org_id)
        else:
            query = query.filter(Analysis.user_id == user.id)
    elif user and not user.is_admin():
        query = query.filter(Analysis.user_id == user.id)
    rows = query.order_by(Analysis.analyzed_at.desc()).limit(limit).all()
    return [r.to_summary() for r in rows]


def delete_report(report_id):
    analysis = Analysis.query.get(report_id)
    if analysis:
        db.session.delete(analysis)
        db.session.commit()
        return True
    return False


def get_stats(user=None, org_scoped=False):
    query = Analysis.query
    if user and org_scoped and user.org_id:
        if user.is_admin() or user.is_org_admin():
            query = query.filter(Analysis.org_id == user.org_id)
        else:
            query = query.filter(Analysis.user_id == user.id)
    elif user and not user.is_admin():
        query = query.filter(Analysis.user_id == user.id)

    total = query.count()
    by_level = {}
    base_filter = query.with_entities(Analysis.threat_level, db.func.count(Analysis.id))
    rows = base_filter.group_by(Analysis.threat_level).all()
    for level, cnt in rows:
        by_level[level] = cnt
    avg_row = query.with_entities(db.func.avg(Analysis.threat_score)).scalar()
    return {
        "total": total,
        "by_level": by_level,
        "avg_score": round(avg_row, 1) if avg_row else 0,
    }


def search_history(query_str, user=None, org_scoped=False):
    pattern = f"%{query_str}%"
    query = Analysis.query.filter(
        db.or_(
            Analysis.filename.ilike(pattern),
            Analysis.from_address.ilike(pattern),
            Analysis.subject.ilike(pattern),
        )
    )
    if user and org_scoped and user.org_id:
        if user.is_admin() or user.is_org_admin():
            query = query.filter(Analysis.org_id == user.org_id)
        else:
            query = query.filter(Analysis.user_id == user.id)
    elif user and not user.is_admin():
        query = query.filter(Analysis.user_id == user.id)

    rows = query.order_by(Analysis.analyzed_at.desc()).limit(100).all()
    return [r.to_summary() for r in rows]


def get_trend_data(days=30, user=None, org_scoped=False):
    cutoff = time.time() - (days * 86400)
    db_uri = db.engine.url.drivername
    if "postgresql" in db_uri or "postgres" in db_uri:
        day_expr = db.func.date(db.func.to_timestamp(Analysis.analyzed_at))
    else:
        day_expr = db.func.date(db.func.datetime(Analysis.analyzed_at, "unixepoch"))

    query = db.session.query(
        day_expr.label("day"),
        Analysis.threat_level,
        db.func.count(Analysis.id).label("cnt"),
    ).filter(Analysis.analyzed_at >= cutoff)

    if user and org_scoped and user.org_id:
        if user.is_admin() or user.is_org_admin():
            query = query.filter(Analysis.org_id == user.org_id)
        else:
            query = query.filter(Analysis.user_id == user.id)
    elif user and not user.is_admin():
        query = query.filter(Analysis.user_id == user.id)

    rows = query.group_by("day", Analysis.threat_level).order_by("day").all()
    return [{"day": str(r.day), "threat_level": r.threat_level, "cnt": r.cnt} for r in rows]


def get_analysis_by_task_id(task_id):
    """Look up an analysis by its Celery task ID."""
    analysis = Analysis.query.filter_by(task_id=task_id).first()
    if analysis:
        return analysis.to_summary()
    return None


# =========================================================================
# ENHANCED DASHBOARD QUERIES
# =========================================================================

def get_weekly_comparison(user=None, org_scoped=False):
    """Compare this week vs last week."""
    now = time.time()
    this_week_start = now - (7 * 86400)
    last_week_start = now - (14 * 86400)

    def _query_week(start, end):
        q = Analysis.query.filter(
            Analysis.analyzed_at >= start,
            Analysis.analyzed_at < end,
        )
        if user and org_scoped and user.org_id:
            if user.is_admin() or user.is_org_admin():
                q = q.filter(Analysis.org_id == user.org_id)
            else:
                q = q.filter(Analysis.user_id == user.id)
        elif user and not user.is_admin():
            q = q.filter(Analysis.user_id == user.id)
        return q

    this_week_q = _query_week(this_week_start, now)
    last_week_q = _query_week(last_week_start, this_week_start)

    this_total = this_week_q.count()
    last_total = last_week_q.count()
    this_critical = this_week_q.filter(Analysis.threat_level.in_(["critical", "high"])).count()
    last_critical = last_week_q.filter(Analysis.threat_level.in_(["critical", "high"])).count()

    return {
        "this_week_total": this_total,
        "last_week_total": last_total,
        "this_week_threats": this_critical,
        "last_week_threats": last_critical,
        "total_change_pct": round(((this_total - last_total) / max(last_total, 1)) * 100, 1),
        "threat_change_pct": round(((this_critical - last_critical) / max(last_critical, 1)) * 100, 1),
    }


def get_top_attack_types(limit=5, user=None, org_scoped=False):
    """Get most common attack indicators from recent analyses."""
    cutoff = time.time() - (30 * 86400)
    q = Analysis.query.filter(
        Analysis.analyzed_at >= cutoff,
        Analysis.threat_score >= 30,
    )
    if user and org_scoped and user.org_id:
        if user.is_admin() or user.is_org_admin():
            q = q.filter(Analysis.org_id == user.org_id)
        else:
            q = q.filter(Analysis.user_id == user.id)
    elif user and not user.is_admin():
        q = q.filter(Analysis.user_id == user.id)

    analyses = q.order_by(Analysis.analyzed_at.desc()).limit(200).all()

    attack_counts = {}
    for a in analyses:
        try:
            report = json.loads(a.report_json)
            breakdown = report.get("score", {}).get("breakdown", [])
            for item in breakdown:
                cat = item.get("category", "other")
                attack_counts[cat] = attack_counts.get(cat, 0) + 1
        except (json.JSONDecodeError, KeyError):
            pass

    sorted_attacks = sorted(attack_counts.items(), key=lambda x: x[1], reverse=True)
    return [{"type": t, "count": c} for t, c in sorted_attacks[:limit]]


def get_top_domains(limit=8, user=None, org_scoped=False):
    """Get domains that appear most frequently in threats."""
    cutoff = time.time() - (30 * 86400)
    q = Analysis.query.filter(
        Analysis.analyzed_at >= cutoff,
        Analysis.threat_score >= 30,
    )
    if user and org_scoped and user.org_id:
        if user.is_admin() or user.is_org_admin():
            q = q.filter(Analysis.org_id == user.org_id)
        else:
            q = q.filter(Analysis.user_id == user.id)
    elif user and not user.is_admin():
        q = q.filter(Analysis.user_id == user.id)

    analyses = q.order_by(Analysis.analyzed_at.desc()).limit(200).all()

    domain_counts = {}
    for a in analyses:
        addr = a.from_address or ""
        if "@" in addr:
            domain = addr.split("@")[-1].lower().strip()
            if domain:
                domain_counts[domain] = domain_counts.get(domain, 0) + 1

    sorted_domains = sorted(domain_counts.items(), key=lambda x: x[1], reverse=True)
    return [{"domain": d, "count": c} for d, c in sorted_domains[:limit]]


def get_recent_critical(limit=5, user=None, org_scoped=False):
    """Get the most recent critical/high threat analyses."""
    q = Analysis.query.filter(Analysis.threat_level.in_(["critical", "high"]))
    if user and org_scoped and user.org_id:
        if user.is_admin() or user.is_org_admin():
            q = q.filter(Analysis.org_id == user.org_id)
        else:
            q = q.filter(Analysis.user_id == user.id)
    elif user and not user.is_admin():
        q = q.filter(Analysis.user_id == user.id)

    rows = q.order_by(Analysis.analyzed_at.desc()).limit(limit).all()
    return [r.to_summary() for r in rows]


def get_user_notifications(user_id, unread_only=False, limit=20):
    """Get notifications for a user."""
    q = Notification.query.filter_by(user_id=user_id)
    if unread_only:
        q = q.filter_by(is_read=False)
    return q.order_by(Notification.created_at.desc()).limit(limit).all()


def get_unread_notification_count(user_id):
    """Count unread notifications."""
    return Notification.query.filter_by(user_id=user_id, is_read=False).count()


def create_notification(user_id, title, message, category="info", link=None):
    """Create an in-app notification."""
    notif = Notification(
        user_id=user_id,
        title=title,
        message=message,
        category=category,
        link=link,
    )
    db.session.add(notif)
    db.session.commit()
    return notif
