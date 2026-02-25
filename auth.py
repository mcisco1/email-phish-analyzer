"""
Authentication & authorization module.

Provides:
- Flask-Login session management
- OAuth 2.0 with Google and Microsoft
- JWT token authentication (access + refresh) with revocation
- Role-based access control decorators (admin, analyst, viewer)
- CSRF protection for all forms
- Audit logging on every auth event
"""

import functools
import json
import uuid
import logging
from datetime import datetime, timezone, timedelta

import jwt as pyjwt
from flask import (
    Blueprint, request, redirect, url_for, flash, jsonify,
    render_template, session, current_app,
)
from flask_login import (
    LoginManager, login_user, logout_user, login_required, current_user,
)
from flask_wtf.csrf import CSRFProtect

from database import db, User, RevokedToken, AuditLog, log_audit
import config

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Flask-Login setup
# ---------------------------------------------------------------------------
login_manager = LoginManager()
login_manager.login_view = "auth.login"
login_manager.login_message_category = "info"
login_manager.session_protection = "strong"

csrf = CSRFProtect()


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


# ---------------------------------------------------------------------------
# Blueprint
# ---------------------------------------------------------------------------
auth_bp = Blueprint("auth", __name__, template_folder="templates")


@auth_bp.app_context_processor
def inject_config():
    """Make config available in all templates."""
    return {"config": config}


# =========================================================================
# LOCAL AUTH — login / register / logout
# =========================================================================

@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("index"))

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not email or not password:
            flash("Email and password are required.", "error")
            return render_template("login.html"), 400

        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            if not user.is_active:
                flash("Account is disabled. Contact an administrator.", "error")
                log_audit("login_disabled", user=user, ip_address=_client_ip(),
                          user_agent=request.user_agent.string)
                return render_template("login.html"), 403

            _do_login(user)
            if not user.onboarding_completed:
                return redirect(url_for("onboarding"))
            next_page = request.args.get("next", url_for("index"))
            return redirect(next_page)
        else:
            flash("Invalid email or password.", "error")
            log_audit("login_failed", ip_address=_client_ip(),
                      user_agent=request.user_agent.string,
                      details={"email": email})
            return render_template("login.html"), 401

    return render_template("login.html")


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("index"))

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")

        errors = _validate_registration(email, username, password, confirm)
        if errors:
            for err in errors:
                flash(err, "error")
            return render_template("register.html"), 400

        user = User(
            email=email,
            username=username,
            role="viewer",  # new users start as viewers
        )
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        log_audit("register", user=user, ip_address=_client_ip(),
                  user_agent=request.user_agent.string)
        flash("Account created. Please log in.", "success")
        return redirect(url_for("auth.login"))

    return render_template("register.html")


@auth_bp.route("/logout")
@login_required
def logout():
    log_audit("logout", user=current_user, ip_address=_client_ip(),
              user_agent=request.user_agent.string)
    logout_user()
    session.clear()
    flash("Logged out.", "info")
    return redirect(url_for("auth.login"))


# =========================================================================
# OAUTH 2.0 — Google
# =========================================================================

@auth_bp.route("/oauth/google")
def oauth_google():
    if not config.GOOGLE_ENABLED:
        flash("Google login is not configured.", "error")
        return redirect(url_for("auth.login"))

    state = uuid.uuid4().hex
    session["oauth_state"] = state
    params = {
        "client_id": config.GOOGLE_CLIENT_ID,
        "redirect_uri": url_for("auth.oauth_google_callback", _external=True),
        "response_type": "code",
        "scope": "openid email profile",
        "state": state,
        "access_type": "offline",
        "prompt": "select_account",
    }
    query = "&".join(f"{k}={v}" for k, v in params.items())
    return redirect(f"https://accounts.google.com/o/oauth2/v2/auth?{query}")


@auth_bp.route("/oauth/google/callback")
def oauth_google_callback():
    if not config.GOOGLE_ENABLED:
        flash("Google login is not configured.", "error")
        return redirect(url_for("auth.login"))

    if request.args.get("state") != session.pop("oauth_state", None):
        flash("OAuth state mismatch. Try again.", "error")
        return redirect(url_for("auth.login"))

    code = request.args.get("code")
    if not code:
        flash("OAuth authorization failed.", "error")
        return redirect(url_for("auth.login"))

    import requests as http_requests
    token_resp = http_requests.post(
        "https://oauth2.googleapis.com/token",
        data={
            "code": code,
            "client_id": config.GOOGLE_CLIENT_ID,
            "client_secret": config.GOOGLE_CLIENT_SECRET,
            "redirect_uri": url_for("auth.oauth_google_callback", _external=True),
            "grant_type": "authorization_code",
        },
        timeout=10,
    )
    if token_resp.status_code != 200:
        logger.warning("Google token exchange failed: %s", token_resp.text)
        flash("Google authentication failed.", "error")
        return redirect(url_for("auth.login"))

    id_token = token_resp.json().get("id_token")
    # Decode without verification since we just got it from Google over HTTPS
    userinfo = pyjwt.decode(id_token, options={"verify_signature": False})

    return _handle_oauth_user(
        provider="google",
        oauth_id=userinfo["sub"],
        email=userinfo.get("email", "").lower(),
        name=userinfo.get("name", ""),
    )


# =========================================================================
# OAUTH 2.0 — Microsoft
# =========================================================================

@auth_bp.route("/oauth/microsoft")
def oauth_microsoft():
    if not config.MICROSOFT_ENABLED:
        flash("Microsoft login is not configured.", "error")
        return redirect(url_for("auth.login"))

    state = uuid.uuid4().hex
    session["oauth_state"] = state
    tenant = config.MICROSOFT_TENANT_ID
    params = {
        "client_id": config.MICROSOFT_CLIENT_ID,
        "redirect_uri": url_for("auth.oauth_microsoft_callback", _external=True),
        "response_type": "code",
        "scope": "openid email profile",
        "state": state,
        "response_mode": "query",
    }
    query = "&".join(f"{k}={v}" for k, v in params.items())
    return redirect(f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize?{query}")


@auth_bp.route("/oauth/microsoft/callback")
def oauth_microsoft_callback():
    if not config.MICROSOFT_ENABLED:
        flash("Microsoft login is not configured.", "error")
        return redirect(url_for("auth.login"))

    if request.args.get("state") != session.pop("oauth_state", None):
        flash("OAuth state mismatch. Try again.", "error")
        return redirect(url_for("auth.login"))

    code = request.args.get("code")
    if not code:
        flash("OAuth authorization failed.", "error")
        return redirect(url_for("auth.login"))

    import requests as http_requests
    tenant = config.MICROSOFT_TENANT_ID
    token_resp = http_requests.post(
        f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token",
        data={
            "code": code,
            "client_id": config.MICROSOFT_CLIENT_ID,
            "client_secret": config.MICROSOFT_CLIENT_SECRET,
            "redirect_uri": url_for("auth.oauth_microsoft_callback", _external=True),
            "grant_type": "authorization_code",
            "scope": "openid email profile",
        },
        timeout=10,
    )
    if token_resp.status_code != 200:
        logger.warning("Microsoft token exchange failed: %s", token_resp.text)
        flash("Microsoft authentication failed.", "error")
        return redirect(url_for("auth.login"))

    id_token = token_resp.json().get("id_token")
    userinfo = pyjwt.decode(id_token, options={"verify_signature": False})

    return _handle_oauth_user(
        provider="microsoft",
        oauth_id=userinfo.get("oid", userinfo.get("sub", "")),
        email=userinfo.get("preferred_username", userinfo.get("email", "")).lower(),
        name=userinfo.get("name", ""),
    )


# =========================================================================
# JWT API AUTHENTICATION
# =========================================================================

@auth_bp.route("/api/auth/token", methods=["POST"])
@csrf.exempt
def api_get_token():
    """Exchange email+password for JWT access + refresh tokens."""
    data = request.get_json(silent=True) or {}
    email = data.get("email", "").strip().lower()
    password = data.get("password", "")

    if not email or not password:
        return jsonify({"error": "Email and password required"}), 400

    user = User.query.filter_by(email=email).first()
    if not user or not user.check_password(password):
        log_audit("api_login_failed", ip_address=_client_ip(),
                  details={"email": email})
        return jsonify({"error": "Invalid credentials"}), 401

    if not user.is_active:
        return jsonify({"error": "Account disabled"}), 403

    access_token = _create_jwt(user, "access")
    refresh_token = _create_jwt(user, "refresh")

    log_audit("api_login", user=user, ip_address=_client_ip())

    return jsonify({
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "Bearer",
        "expires_in": int(config.JWT_ACCESS_TOKEN_EXPIRES.total_seconds()),
        "user": user.to_dict(),
    })


@auth_bp.route("/api/auth/refresh", methods=["POST"])
@csrf.exempt
def api_refresh_token():
    """Exchange a refresh token for a new access token."""
    data = request.get_json(silent=True) or {}
    refresh_token = data.get("refresh_token", "")

    if not refresh_token:
        return jsonify({"error": "Refresh token required"}), 400

    payload = _decode_jwt(refresh_token)
    if not payload:
        return jsonify({"error": "Invalid or expired refresh token"}), 401

    if payload.get("type") != "refresh":
        return jsonify({"error": "Not a refresh token"}), 400

    if RevokedToken.is_revoked(payload["jti"]):
        return jsonify({"error": "Token has been revoked"}), 401

    user = User.query.get(payload["sub"])
    if not user or not user.is_active:
        return jsonify({"error": "User not found or disabled"}), 401

    access_token = _create_jwt(user, "access")

    return jsonify({
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": int(config.JWT_ACCESS_TOKEN_EXPIRES.total_seconds()),
    })


@auth_bp.route("/api/auth/revoke", methods=["POST"])
@csrf.exempt
def api_revoke_token():
    """Revoke a token (logout from API)."""
    data = request.get_json(silent=True) or {}
    token = data.get("token", "") or data.get("refresh_token", "")

    if not token:
        return jsonify({"error": "Token required. Send {\"token\": \"...\"} or {\"refresh_token\": \"...\"}"}), 400

    payload = _decode_jwt(token)
    if payload:
        revoked = RevokedToken(
            jti=payload["jti"],
            expires_at=datetime.fromtimestamp(payload["exp"], tz=timezone.utc),
        )
        db.session.add(revoked)
        db.session.commit()

    return jsonify({"status": "revoked"})


# =========================================================================
# ROLE-BASED ACCESS CONTROL DECORATORS
# =========================================================================

def role_required(*roles):
    """Decorator: require the logged-in user to have one of the specified roles."""
    def decorator(f):
        @functools.wraps(f)
        @login_required
        def decorated_view(*args, **kwargs):
            if not current_user.has_role(*roles):
                if request.path.startswith("/api/"):
                    return jsonify({"error": "Insufficient permissions"}), 403
                flash("You do not have permission to access this page.", "error")
                return redirect(url_for("index"))
            return f(*args, **kwargs)
        return decorated_view
    return decorator


def api_auth_required(f):
    """Decorator: require JWT Bearer token OR legacy X-API-Key on API routes."""
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        # 1. Try JWT Bearer token
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:]
            payload = _decode_jwt(token)
            if not payload:
                return jsonify({"error": "Invalid or expired token"}), 401
            if payload.get("type") != "access":
                return jsonify({"error": "Not an access token"}), 401
            if RevokedToken.is_revoked(payload["jti"]):
                return jsonify({"error": "Token has been revoked"}), 401
            user = User.query.get(payload["sub"])
            if not user or not user.is_active:
                return jsonify({"error": "User not found or disabled"}), 401
            request.api_user = user
            return f(*args, **kwargs)

        # 2. Try legacy X-API-Key
        if config.API_KEY:
            provided = request.headers.get("X-API-Key", "")
            if provided == config.API_KEY:
                request.api_user = None  # legacy key has no user context
                return f(*args, **kwargs)

        # 3. Try session auth (for browser-based API calls)
        if current_user.is_authenticated:
            request.api_user = current_user
            return f(*args, **kwargs)

        return jsonify({"error": "Authentication required. Provide Bearer token or X-API-Key header."}), 401
    return decorated


def api_role_required(*roles):
    """Decorator: require specific role on API routes (use after api_auth_required)."""
    def decorator(f):
        @functools.wraps(f)
        @api_auth_required
        def decorated(*args, **kwargs):
            user = getattr(request, "api_user", None)
            if user and not user.has_role(*roles):
                return jsonify({"error": "Insufficient permissions"}), 403
            return f(*args, **kwargs)
        return decorated
    return decorator


# =========================================================================
# ADMIN — user management
# =========================================================================

@auth_bp.route("/admin/users")
@role_required("admin")
def admin_users():
    users = User.query.order_by(User.created_at.desc()).all()
    return render_template("admin.html", users=users)


@auth_bp.route("/admin/users/<user_id>/role", methods=["POST"])
@role_required("admin")
def admin_change_role(user_id):
    target_user = User.query.get_or_404(user_id)
    new_role = request.form.get("role", "viewer")
    if new_role not in ("admin", "analyst", "viewer"):
        flash("Invalid role.", "error")
        return redirect(url_for("auth.admin_users"))

    old_role = target_user.role
    target_user.role = new_role
    db.session.commit()

    log_audit("change_role", user=current_user, resource_type="user",
              resource_id=target_user.id, ip_address=_client_ip(),
              details={"old_role": old_role, "new_role": new_role, "target": target_user.email})
    flash(f"Role updated: {target_user.username} is now {new_role}.", "success")
    return redirect(url_for("auth.admin_users"))


@auth_bp.route("/admin/users/<user_id>/toggle", methods=["POST"])
@role_required("admin")
def admin_toggle_user(user_id):
    target_user = User.query.get_or_404(user_id)
    if target_user.id == current_user.id:
        flash("Cannot disable your own account.", "error")
        return redirect(url_for("auth.admin_users"))

    target_user.is_active = not target_user.is_active
    db.session.commit()

    status = "enabled" if target_user.is_active else "disabled"
    log_audit(f"user_{status}", user=current_user, resource_type="user",
              resource_id=target_user.id, ip_address=_client_ip(),
              details={"target": target_user.email})
    flash(f"User {target_user.username} {status}.", "success")
    return redirect(url_for("auth.admin_users"))


@auth_bp.route("/admin/audit")
@role_required("admin")
def admin_audit_log():
    page = request.args.get("page", 1, type=int)
    per_page = 50
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    return render_template("audit.html", logs=logs)


# =========================================================================
# INTERNAL HELPERS
# =========================================================================

def _do_login(user):
    """Perform login and update tracking fields."""
    login_user(user, remember=True, duration=config.SESSION_TIMEOUT)
    user.last_login = datetime.now(timezone.utc)
    db.session.commit()
    session.permanent = True
    log_audit("login", user=user, ip_address=_client_ip(),
              user_agent=request.user_agent.string)


def _handle_oauth_user(provider, oauth_id, email, name):
    """Find or create a user from OAuth, then log them in."""
    if not email:
        flash("OAuth provider did not return an email address.", "error")
        return redirect(url_for("auth.login"))

    user = User.query.filter_by(oauth_provider=provider, oauth_id=oauth_id).first()
    if not user:
        user = User.query.filter_by(email=email).first()
        if user:
            # Link existing account to OAuth
            user.oauth_provider = provider
            user.oauth_id = oauth_id
            db.session.commit()
        else:
            # Create new user
            username = email.split("@")[0]
            # Ensure unique username
            base_username = username
            counter = 1
            while User.query.filter_by(username=username).first():
                username = f"{base_username}{counter}"
                counter += 1
            user = User(
                email=email,
                username=username,
                role="viewer",
                oauth_provider=provider,
                oauth_id=oauth_id,
            )
            db.session.add(user)
            db.session.commit()
            log_audit("register_oauth", user=user, ip_address=_client_ip(),
                      details={"provider": provider})

    if not user.is_active:
        flash("Account is disabled.", "error")
        return redirect(url_for("auth.login"))

    _do_login(user)
    if not user.onboarding_completed:
        return redirect(url_for("onboarding"))
    return redirect(url_for("index"))


def _create_jwt(user, token_type="access"):
    """Create a signed JWT token."""
    now = datetime.now(timezone.utc)
    if token_type == "access":
        expires = now + config.JWT_ACCESS_TOKEN_EXPIRES
    else:
        expires = now + config.JWT_REFRESH_TOKEN_EXPIRES

    payload = {
        "sub": user.id,
        "email": user.email,
        "role": user.role,
        "type": token_type,
        "jti": uuid.uuid4().hex,
        "iat": now,
        "exp": expires,
    }
    return pyjwt.encode(payload, config.JWT_SECRET_KEY, algorithm=config.JWT_ALGORITHM)


def _decode_jwt(token):
    """Decode and validate a JWT token. Returns payload or None."""
    try:
        return pyjwt.decode(
            token,
            config.JWT_SECRET_KEY,
            algorithms=[config.JWT_ALGORITHM],
        )
    except (pyjwt.ExpiredSignatureError, pyjwt.InvalidTokenError):
        return None


def _client_ip():
    """Get client IP, respecting X-Forwarded-For behind a proxy."""
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr or "unknown"


def _validate_registration(email, username, password, confirm):
    """Validate registration form fields. Returns list of error strings."""
    errors = []
    if not email or "@" not in email:
        errors.append("Valid email address is required.")
    if not username or len(username) < 3:
        errors.append("Username must be at least 3 characters.")
    if len(username) > 150:
        errors.append("Username must be 150 characters or fewer.")
    if len(password) < 8:
        errors.append("Password must be at least 8 characters.")
    if password != confirm:
        errors.append("Passwords do not match.")
    if User.query.filter_by(email=email).first():
        errors.append("An account with this email already exists.")
    if User.query.filter_by(username=username).first():
        errors.append("This username is already taken.")
    return errors
