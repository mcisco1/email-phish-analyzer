"""Tests for auth.py — authentication, JWT, role decorators, registration."""

import pytest
from unittest.mock import patch, MagicMock

from database import db, User, RevokedToken


class TestLogin:
    def test_login_page_renders(self, client):
        resp = client.get("/login")
        assert resp.status_code == 200

    def test_login_valid_credentials(self, app, client, test_user):
        resp = client.post("/login", data={
            "email": "testuser@example.com",
            "password": "TestPass123!",
        }, follow_redirects=False)
        # Successful login redirects
        assert resp.status_code in (302, 303)

    def test_login_invalid_password(self, app, client, test_user):
        resp = client.post("/login", data={
            "email": "testuser@example.com",
            "password": "WrongPassword",
        })
        assert resp.status_code == 401

    def test_login_nonexistent_user(self, client):
        resp = client.post("/login", data={
            "email": "ghost@example.com",
            "password": "whatever",
        })
        assert resp.status_code == 401

    def test_login_empty_fields(self, client):
        resp = client.post("/login", data={
            "email": "",
            "password": "",
        })
        assert resp.status_code == 400

    def test_login_disabled_user(self, app, client):
        with app.app_context():
            user = User(email="disabled@example.com", username="disabled",
                        role="analyst", is_active=False)
            user.set_password("TestPass123!")
            db.session.add(user)
            db.session.commit()

        resp = client.post("/login", data={
            "email": "disabled@example.com",
            "password": "TestPass123!",
        })
        assert resp.status_code == 403


class TestRegister:
    def test_register_page_renders(self, client):
        resp = client.get("/register")
        assert resp.status_code == 200

    def test_register_valid(self, client):
        resp = client.post("/register", data={
            "email": "newuser@example.com",
            "username": "newuser",
            "password": "StrongPass123!",
            "confirm_password": "StrongPass123!",
        }, follow_redirects=False)
        assert resp.status_code in (302, 303)

    def test_register_duplicate_email(self, app, client, test_user):
        resp = client.post("/register", data={
            "email": "testuser@example.com",
            "username": "differentuser",
            "password": "StrongPass123!",
            "confirm_password": "StrongPass123!",
        })
        assert resp.status_code == 400

    def test_register_password_mismatch(self, client):
        resp = client.post("/register", data={
            "email": "mismatch@example.com",
            "username": "mismatch",
            "password": "StrongPass123!",
            "confirm_password": "DifferentPass!",
        })
        assert resp.status_code == 400

    def test_register_short_password(self, client):
        resp = client.post("/register", data={
            "email": "short@example.com",
            "username": "shortpw",
            "password": "short",
            "confirm_password": "short",
        })
        assert resp.status_code == 400

    def test_register_invalid_email(self, client):
        resp = client.post("/register", data={
            "email": "not-an-email",
            "username": "bademail",
            "password": "StrongPass123!",
            "confirm_password": "StrongPass123!",
        })
        assert resp.status_code == 400

    def test_register_short_username(self, client):
        resp = client.post("/register", data={
            "email": "ok@example.com",
            "username": "ab",
            "password": "StrongPass123!",
            "confirm_password": "StrongPass123!",
        })
        assert resp.status_code == 400

    def test_new_user_gets_viewer_role(self, app, client):
        client.post("/register", data={
            "email": "viewer@example.com",
            "username": "vieweruser",
            "password": "StrongPass123!",
            "confirm_password": "StrongPass123!",
        })
        with app.app_context():
            user = User.query.filter_by(email="viewer@example.com").first()
            assert user is not None
            assert user.role == "viewer"


class TestLogout:
    def test_logout_redirects(self, auth_client):
        resp = auth_client.get("/logout", follow_redirects=False)
        assert resp.status_code in (302, 303)


class TestJWTTokenEndpoints:
    def test_get_token_valid(self, app, client, test_user):
        resp = client.post("/api/auth/token",
                           json={"email": "testuser@example.com", "password": "TestPass123!"},
                           content_type="application/json")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "access_token" in data
        assert "refresh_token" in data
        assert data["token_type"] == "Bearer"

    def test_get_token_invalid(self, client, test_user):
        resp = client.post("/api/auth/token",
                           json={"email": "testuser@example.com", "password": "wrong"},
                           content_type="application/json")
        assert resp.status_code == 401

    def test_get_token_missing_fields(self, client):
        resp = client.post("/api/auth/token",
                           json={"email": ""},
                           content_type="application/json")
        assert resp.status_code == 400

    def test_get_token_disabled_user(self, app, client):
        with app.app_context():
            user = User(email="disabled2@example.com", username="disabled2",
                        role="analyst", is_active=False)
            user.set_password("TestPass123!")
            db.session.add(user)
            db.session.commit()

        resp = client.post("/api/auth/token",
                           json={"email": "disabled2@example.com", "password": "TestPass123!"},
                           content_type="application/json")
        assert resp.status_code == 403

    def test_refresh_token(self, app, client, test_user):
        # Get tokens first
        resp = client.post("/api/auth/token",
                           json={"email": "testuser@example.com", "password": "TestPass123!"},
                           content_type="application/json")
        tokens = resp.get_json()

        # Refresh
        resp = client.post("/api/auth/refresh",
                           json={"refresh_token": tokens["refresh_token"]},
                           content_type="application/json")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "access_token" in data

    def test_refresh_with_access_token_fails(self, app, client, test_user):
        resp = client.post("/api/auth/token",
                           json={"email": "testuser@example.com", "password": "TestPass123!"},
                           content_type="application/json")
        tokens = resp.get_json()

        # Using access token as refresh should fail
        resp = client.post("/api/auth/refresh",
                           json={"refresh_token": tokens["access_token"]},
                           content_type="application/json")
        assert resp.status_code == 400

    def test_revoke_token(self, app, client, test_user):
        resp = client.post("/api/auth/token",
                           json={"email": "testuser@example.com", "password": "TestPass123!"},
                           content_type="application/json")
        tokens = resp.get_json()

        # Revoke the refresh token
        resp = client.post("/api/auth/revoke",
                           json={"token": tokens["refresh_token"]},
                           content_type="application/json")
        assert resp.status_code == 200

        # Using revoked token to refresh should fail
        resp = client.post("/api/auth/refresh",
                           json={"refresh_token": tokens["refresh_token"]},
                           content_type="application/json")
        assert resp.status_code == 401

    def test_revoke_empty_token(self, client):
        resp = client.post("/api/auth/revoke",
                           json={},
                           content_type="application/json")
        assert resp.status_code == 400


class TestAPIAuthDecorator:
    def test_bearer_token_auth(self, app, client, test_user):
        # Get token
        resp = client.post("/api/auth/token",
                           json={"email": "testuser@example.com", "password": "TestPass123!"},
                           content_type="application/json")
        token = resp.get_json()["access_token"]

        # Use token on an API endpoint (history is a good one)
        resp = client.get("/api/history",
                          headers={"Authorization": f"Bearer {token}"})
        # Should not get 401
        assert resp.status_code != 401

    def test_invalid_bearer_rejected(self, client):
        resp = client.get("/api/history",
                          headers={"Authorization": "Bearer invalid.token.here"})
        assert resp.status_code == 401

    def test_no_auth_rejected(self, client):
        resp = client.get("/api/history")
        assert resp.status_code == 401

    @patch("config.API_KEY", "test-legacy-key")
    def test_legacy_api_key(self, client):
        resp = client.get("/api/history",
                          headers={"X-API-Key": "test-legacy-key"})
        assert resp.status_code != 401


class TestRoleRequired:
    def test_admin_route_blocks_analyst(self, auth_client):
        resp = auth_client.get("/admin/users", follow_redirects=False)
        # Analyst doesn't have admin role — should redirect or 403
        assert resp.status_code in (302, 303, 403)

    def test_admin_route_allows_admin(self, admin_client):
        resp = admin_client.get("/admin/users")
        assert resp.status_code == 200


class TestUserModel:
    def test_set_and_check_password(self, app):
        with app.app_context():
            user = User(email="pw@test.com", username="pwtest", role="viewer")
            user.set_password("mypassword")
            assert user.check_password("mypassword") is True
            assert user.check_password("wrongpassword") is False

    def test_oauth_user_no_password(self, app):
        with app.app_context():
            user = User(email="oauth@test.com", username="oauthtest",
                        role="viewer", oauth_provider="google", oauth_id="abc123")
            # No password set
            assert user.check_password("anything") is False

    def test_has_role(self, app):
        with app.app_context():
            user = User(email="role@test.com", username="roletest", role="analyst")
            assert user.has_role("analyst") is True
            assert user.has_role("admin") is False
            assert user.has_role("admin", "analyst") is True

    def test_is_admin(self, app):
        with app.app_context():
            admin = User(email="a@t.com", username="a1", role="admin")
            viewer = User(email="v@t.com", username="v1", role="viewer")
            assert admin.is_admin() is True
            assert viewer.is_admin() is False

    def test_to_dict(self, app, test_user):
        with app.app_context():
            d = test_user.to_dict()
            assert d["email"] == "testuser@example.com"
            assert d["role"] == "analyst"
            assert "id" in d
