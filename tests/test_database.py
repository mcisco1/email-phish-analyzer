"""Tests for database.py — models, CRUD operations, dashboard queries."""

import json
import time
import pytest

from database import (
    db, User, Analysis, Organization, AuditLog, RevokedToken,
    Notification, NotificationPreference, TeamInvite, ImapPollLog,
    save_report, get_report, get_history, delete_report, get_stats,
    search_history, get_trend_data, log_audit, get_threat_velocity,
    get_soc_narrative, get_team_activity, get_team_member_stats,
    create_notification, get_user_notifications, get_unread_notification_count,
)


def _make_report_dict(report_id="rpt001", level="clean", score=5,
                      from_addr="sender@example.com", subject="Test"):
    return {
        "report_id": report_id,
        "filename": "test.eml",
        "analyzed_at": "2025-01-15 10:30:00 UTC",
        "headers": {"from_address": from_addr, "subject": subject},
        "body": {"text_content": "Hello"},
        "urls": [],
        "attachments": [],
        "score": {"total": score, "level": level, "breakdown": []},
        "iocs": {},
        "mitre_mappings": [],
        "attack_summary": {},
        "whois": {},
    }


class TestSaveAndGetReport:
    def test_save_and_retrieve(self, app):
        with app.app_context():
            report_dict = _make_report_dict("save001")
            save_report(report_dict)

            result = get_report("save001")
            assert result is not None
            assert result["report_id"] == "save001"
            assert result["filename"] == "test.eml"

    def test_get_nonexistent(self, app):
        with app.app_context():
            result = get_report("nonexistent999")
            assert result is None

    def test_save_updates_existing(self, app):
        with app.app_context():
            report_dict = _make_report_dict("update001", level="clean", score=5)
            save_report(report_dict)

            # Update it
            report_dict["score"]["level"] = "critical"
            report_dict["score"]["total"] = 90
            save_report(report_dict, status="complete")

            result = get_report("update001")
            assert result["score"]["total"] == 90

    def test_save_with_user_id(self, app, test_user):
        with app.app_context():
            report_dict = _make_report_dict("user001")
            analysis = save_report(report_dict, user_id=test_user.id)
            assert analysis.user_id == test_user.id


class TestDeleteReport:
    def test_delete_existing(self, app):
        with app.app_context():
            save_report(_make_report_dict("del001"))
            result = delete_report("del001")
            assert result is True
            assert get_report("del001") is None

    def test_delete_nonexistent(self, app):
        with app.app_context():
            result = delete_report("del_missing")
            assert result is False


class TestGetHistory:
    def test_empty_history(self, app):
        with app.app_context():
            result = get_history()
            assert result == []

    def test_history_returns_analyses(self, app):
        with app.app_context():
            save_report(_make_report_dict("hist001"))
            save_report(_make_report_dict("hist002"))
            result = get_history()
            assert len(result) == 2

    def test_history_filtered_by_user(self, app, test_user):
        with app.app_context():
            save_report(_make_report_dict("histA"), user_id=test_user.id)
            save_report(_make_report_dict("histB"), user_id="other-user-id")

            result = get_history(user=test_user)
            assert len(result) == 1
            assert result[0]["id"] == "histA"

    def test_admin_sees_all(self, app, admin_user):
        with app.app_context():
            save_report(_make_report_dict("histX"), user_id="random1")
            save_report(_make_report_dict("histY"), user_id="random2")

            result = get_history(user=admin_user)
            assert len(result) == 2

    def test_history_limit(self, app):
        with app.app_context():
            for i in range(10):
                save_report(_make_report_dict(f"lim{i:03d}"))
            result = get_history(limit=5)
            assert len(result) == 5


class TestSearchHistory:
    def test_search_by_filename(self, app):
        with app.app_context():
            rd = _make_report_dict("srch001")
            rd["filename"] = "suspicious_invoice.eml"
            # Need to also set filename on Analysis
            save_report(rd)
            results = search_history("suspicious")
            # The filename in _make_report_dict is "test.eml" but we save with report_dict["filename"]
            # Analysis.filename is set from report_dict["filename"] in save_report
            found = [r for r in results if r["id"] == "srch001"]
            assert len(found) == 1

    def test_search_by_subject(self, app):
        with app.app_context():
            rd = _make_report_dict("srch002")
            rd["headers"]["subject"] = "Password Reset Required"
            save_report(rd)
            results = search_history("Password Reset")
            assert any(r["id"] == "srch002" for r in results)

    def test_search_no_results(self, app):
        with app.app_context():
            save_report(_make_report_dict("srch003"))
            results = search_history("xyznonexistent")
            assert len(results) == 0


class TestGetStats:
    def test_empty_stats(self, app):
        with app.app_context():
            stats = get_stats()
            assert stats["total"] == 0
            assert stats["avg_score"] == 0

    def test_stats_counts(self, app):
        with app.app_context():
            save_report(_make_report_dict("stat1", level="clean", score=5))
            save_report(_make_report_dict("stat2", level="critical", score=85))
            save_report(_make_report_dict("stat3", level="high", score=60))

            stats = get_stats()
            assert stats["total"] == 3
            assert stats["by_level"].get("clean", 0) == 1
            assert stats["by_level"].get("critical", 0) == 1
            assert stats["by_level"].get("high", 0) == 1
            assert stats["avg_score"] == 50.0

    def test_stats_user_scoped(self, app, test_user):
        with app.app_context():
            save_report(_make_report_dict("stat4"), user_id=test_user.id)
            save_report(_make_report_dict("stat5"), user_id="other-user")

            stats = get_stats(user=test_user)
            assert stats["total"] == 1


class TestGetTrendData:
    def test_empty_trends(self, app):
        with app.app_context():
            result = get_trend_data(days=7)
            assert result == []

    def test_trend_data_returned(self, app):
        with app.app_context():
            # Save analysis within the window
            save_report(_make_report_dict("trend1"))
            result = get_trend_data(days=30)
            assert len(result) >= 1


class TestThreatVelocity:
    def test_no_data(self, app):
        with app.app_context():
            result = get_threat_velocity()
            assert result["trend"] == "stable"
            assert result["change_pct"] == 0.0


class TestSocNarrative:
    def test_no_data(self, app):
        with app.app_context():
            narrative = get_soc_narrative()
            assert "No emails" in narrative

    def test_with_analyses(self, app):
        with app.app_context():
            save_report(_make_report_dict("nar1", level="critical", score=90))
            save_report(_make_report_dict("nar2", level="clean", score=5))
            narrative = get_soc_narrative()
            assert "analyzed" in narrative


class TestLogAudit:
    def test_log_basic(self, app, test_user):
        with app.app_context():
            log_audit("test_action", user=test_user, ip_address="127.0.0.1")
            entry = AuditLog.query.filter_by(action="test_action").first()
            assert entry is not None
            assert entry.username == test_user.username
            assert entry.ip_address == "127.0.0.1"

    def test_log_anonymous(self, app):
        with app.app_context():
            log_audit("anonymous_action", ip_address="10.0.0.1")
            entry = AuditLog.query.filter_by(action="anonymous_action").first()
            assert entry is not None
            assert entry.username == "anonymous"

    def test_log_with_details(self, app, test_user):
        with app.app_context():
            log_audit("detail_action", user=test_user,
                      details={"key": "value", "count": 42})
            entry = AuditLog.query.filter_by(action="detail_action").first()
            assert entry is not None
            parsed = json.loads(entry.details)
            assert parsed["key"] == "value"
            assert parsed["count"] == 42


class TestUserModel:
    def test_create_user(self, app):
        with app.app_context():
            user = User(email="model@test.com", username="modeltest", role="viewer")
            user.set_password("pass123")
            db.session.add(user)
            db.session.commit()

            fetched = User.query.filter_by(email="model@test.com").first()
            assert fetched is not None
            assert fetched.check_password("pass123") is True
            assert fetched.role == "viewer"

    def test_user_to_dict(self, app):
        with app.app_context():
            user = User(email="dict@test.com", username="dicttest", role="analyst")
            user.set_password("pass")
            db.session.add(user)
            db.session.commit()

            d = user.to_dict()
            assert d["email"] == "dict@test.com"
            assert d["role"] == "analyst"
            assert "id" in d

    def test_user_roles(self, app):
        with app.app_context():
            admin = User(email="r1@t.com", username="r1", role="admin")
            analyst = User(email="r2@t.com", username="r2", role="analyst")
            viewer = User(email="r3@t.com", username="r3", role="viewer")

            assert admin.is_admin() is True
            assert admin.is_analyst() is True  # admin counts as analyst
            assert analyst.is_admin() is False
            assert analyst.is_analyst() is True
            assert viewer.is_admin() is False
            assert viewer.is_analyst() is False


class TestOrganization:
    def test_create_org(self, app):
        with app.app_context():
            org = Organization(name="Test Corp", slug="test-corp")
            db.session.add(org)
            db.session.commit()

            fetched = Organization.query.filter_by(slug="test-corp").first()
            assert fetched is not None
            assert fetched.name == "Test Corp"

    def test_org_with_members(self, app):
        with app.app_context():
            org = Organization(name="Team Corp", slug="team-corp")
            db.session.add(org)
            db.session.commit()

            user = User(email="member@team.com", username="member1",
                        role="analyst", org_id=org.id, org_role="member")
            user.set_password("pass123")
            db.session.add(user)
            db.session.commit()

            d = org.to_dict()
            assert d["member_count"] == 1

    def test_org_admin_check(self, app):
        with app.app_context():
            user_owner = User(email="own@t.com", username="own",
                              role="analyst", org_role="owner")
            user_admin = User(email="oa@t.com", username="oa",
                              role="analyst", org_role="admin")
            user_member = User(email="om@t.com", username="om",
                               role="analyst", org_role="member")

            assert user_owner.is_org_admin() is True
            assert user_admin.is_org_admin() is True
            assert user_member.is_org_admin() is False


class TestRevokedToken:
    def test_revoke_and_check(self, app):
        from datetime import datetime, timezone, timedelta
        with app.app_context():
            jti = "test-jti-12345"
            token = RevokedToken(
                jti=jti,
                expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
            )
            db.session.add(token)
            db.session.commit()

            assert RevokedToken.is_revoked(jti) is True
            assert RevokedToken.is_revoked("not-revoked") is False


class TestNotifications:
    def test_create_notification(self, app, test_user):
        with app.app_context():
            notif = create_notification(
                test_user.id, "Test Alert", "Something happened", category="warning"
            )
            assert notif.id is not None
            assert notif.title == "Test Alert"

    def test_get_notifications(self, app, test_user):
        with app.app_context():
            create_notification(test_user.id, "Alert 1", "Msg 1")
            create_notification(test_user.id, "Alert 2", "Msg 2")

            results = get_user_notifications(test_user.id)
            assert len(results) == 2

    def test_unread_count(self, app, test_user):
        with app.app_context():
            create_notification(test_user.id, "Unread 1", "Msg")
            create_notification(test_user.id, "Unread 2", "Msg")

            count = get_unread_notification_count(test_user.id)
            assert count == 2

            # Mark one as read
            notif = Notification.query.filter_by(user_id=test_user.id).first()
            notif.is_read = True
            db.session.commit()

            count = get_unread_notification_count(test_user.id)
            assert count == 1

    def test_unread_only_filter(self, app, test_user):
        with app.app_context():
            n1 = create_notification(test_user.id, "Read", "Msg")
            n1.is_read = True
            db.session.commit()
            create_notification(test_user.id, "Unread", "Msg")

            all_notifs = get_user_notifications(test_user.id)
            unread_only = get_user_notifications(test_user.id, unread_only=True)
            assert len(all_notifs) == 2
            assert len(unread_only) == 1


class TestTeamActivity:
    def test_no_members(self, app):
        with app.app_context():
            org = Organization(name="Empty Org", slug="empty-org")
            db.session.add(org)
            db.session.commit()

            result = get_team_activity(org.id)
            assert result == []

    def test_team_activity_returns_logs(self, app):
        with app.app_context():
            org = Organization(name="Active Org", slug="active-org")
            db.session.add(org)
            db.session.commit()

            user = User(email="active@org.com", username="active",
                        role="analyst", org_id=org.id, is_active=True)
            user.set_password("pass")
            db.session.add(user)
            db.session.commit()

            log_audit("analyze", user=user, resource_type="analysis", resource_id="rpt1")

            result = get_team_activity(org.id)
            assert len(result) == 1
            assert result[0]["action"] == "analyze"


class TestTeamMemberStats:
    def test_member_stats(self, app):
        with app.app_context():
            org = Organization(name="Stats Org", slug="stats-org")
            db.session.add(org)
            db.session.commit()

            user = User(email="stats@org.com", username="statsuser",
                        role="analyst", org_id=org.id, is_active=True)
            user.set_password("pass")
            db.session.add(user)
            db.session.commit()

            save_report(_make_report_dict("ms1", level="critical", score=90), user_id=user.id)
            save_report(_make_report_dict("ms2", level="clean", score=5), user_id=user.id)

            stats = get_team_member_stats(org.id)
            assert len(stats) == 1
            assert stats[0]["total"] == 2
            assert stats[0]["critical"] == 1


class TestAnalysisModel:
    def test_to_summary(self, app):
        with app.app_context():
            analysis = save_report(_make_report_dict("sum001", level="high", score=65))
            summary = analysis.to_summary()
            assert summary["id"] == "sum001"
            assert summary["threat_level"] == "high"
            assert summary["threat_score"] == 65
            assert "analyzed_at_display" in summary

    def test_get_report_method(self, app):
        with app.app_context():
            report_dict = _make_report_dict("method1")
            analysis = save_report(report_dict)
            parsed = analysis.get_report()
            assert parsed["report_id"] == "method1"


class TestImapPollLog:
    def test_create_log(self, app):
        with app.app_context():
            log = ImapPollLog(
                emails_found=5,
                emails_processed=3,
                status="success",
            )
            db.session.add(log)
            db.session.commit()
            assert log.id is not None
            assert log.emails_found == 5
