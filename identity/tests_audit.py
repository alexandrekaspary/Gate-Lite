"""Regression tests for the console audit log screen and its retention policy."""

from django.contrib.auth.models import Permission, User
from django.core.management import call_command
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from .models import AuditEvent, SecurityPolicy


PASSWORD = "Strong-password-123!"


def permission(codename):
    return Permission.objects.get(content_type__app_label="identity", codename=codename)


class AuditLogPermissionTests(TestCase):
    def test_user_without_permission_is_denied(self):
        user = User.objects.create_user("no-access", password=PASSWORD)
        self.client.force_login(user)
        response = self.client.get(reverse("console:audit"))
        self.assertEqual(response.status_code, 403)

    def test_user_with_view_audit_log_permission_can_access(self):
        user = User.objects.create_user("auditor", password=PASSWORD)
        user.user_permissions.add(permission("view_audit_log"))
        self.client.force_login(user)
        response = self.client.get(reverse("console:audit"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "console/audit.html")

    def test_superuser_can_access_without_explicit_permission(self):
        admin = User.objects.create_superuser("audit-admin", "admin@example.com", PASSWORD)
        self.client.force_login(admin)
        response = self.client.get(reverse("console:audit"))
        self.assertEqual(response.status_code, 200)

    def test_nav_link_only_appears_for_users_with_the_permission(self):
        user = User.objects.create_user("dash-user", password=PASSWORD)
        user.user_permissions.add(permission("view_identity_console"))
        self.client.force_login(user)
        response = self.client.get(reverse("console:dashboard"))
        self.assertNotContains(response, reverse("console:audit"))

        user.user_permissions.add(permission("view_audit_log"))
        response = self.client.get(reverse("console:dashboard"))
        self.assertContains(response, reverse("console:audit"))


class AuditLogFilteringAndPaginationTests(TestCase):
    def setUp(self):
        self.auditor = User.objects.create_user("filter-auditor", password=PASSWORD)
        self.auditor.user_permissions.add(permission("view_audit_log"))
        self.client.force_login(self.auditor)
        self.other_user = User.objects.create_user("someone-else", password=PASSWORD)
        # force_login triggers the user_logged_in signal, which writes its own
        # AuditEvent; clear it so fixtures below start from a clean slate.
        AuditEvent.objects.all().delete()

    @staticmethod
    def actions_in(response):
        return {event.action for event in response.context["events"]}

    def test_free_text_search_matches_action_actor_target_and_ip(self):
        AuditEvent.objects.create(actor=self.other_user, action="users.updated", target_type="User", target_id="42", ip_address="10.0.0.5")
        AuditEvent.objects.create(actor=None, action="authentication.failed", target_type="system", ip_address="203.0.113.9")

        response = self.client.get(reverse("console:audit"), {"q": "someone-else"})
        self.assertEqual(self.actions_in(response), {"users.updated"})

        response = self.client.get(reverse("console:audit"), {"q": "203.0.113.9"})
        self.assertEqual(self.actions_in(response), {"authentication.failed"})

    def test_action_filter_matches_exactly(self):
        AuditEvent.objects.create(action="mfa.enabled", target_type="system")
        AuditEvent.objects.create(action="mfa.disabled", target_type="system")

        response = self.client.get(reverse("console:audit"), {"action": "mfa.enabled"})
        self.assertEqual(self.actions_in(response), {"mfa.enabled"})

    def test_date_range_filters_by_creation_date(self):
        recent = AuditEvent.objects.create(action="recent.event", target_type="system")
        old = AuditEvent.objects.create(action="old.event", target_type="system")
        AuditEvent.objects.filter(pk=old.pk).update(created_at=timezone.now() - timezone.timedelta(days=30))

        cutoff = (timezone.now() - timezone.timedelta(days=1)).date().isoformat()
        response = self.client.get(reverse("console:audit"), {"from": cutoff})
        self.assertEqual(self.actions_in(response), {"recent.event"})

    def test_results_are_paginated_at_fifty_per_page(self):
        AuditEvent.objects.bulk_create(
            AuditEvent(action=f"bulk.event.{i}", target_type="system") for i in range(60)
        )
        first_page = self.client.get(reverse("console:audit"))
        self.assertEqual(len(first_page.context["events"]), 50)
        self.assertContains(first_page, "Página 1 de 2")

        second_page = self.client.get(reverse("console:audit"), {"page": 2})
        self.assertEqual(len(second_page.context["events"]), 10)


class AuditLogRetentionCleanupTests(TestCase):
    def test_cleanup_command_removes_events_older_than_the_configured_retention(self):
        policy = SecurityPolicy.load()
        policy.audit_log_retention_days = 10
        policy.save(update_fields=["audit_log_retention_days"])

        recent = AuditEvent.objects.create(action="recent.event", target_type="system")
        old = AuditEvent.objects.create(action="old.event", target_type="system")
        AuditEvent.objects.filter(pk=old.pk).update(created_at=timezone.now() - timezone.timedelta(days=11))

        call_command("cleanup_identity")

        self.assertTrue(AuditEvent.objects.filter(pk=recent.pk).exists())
        self.assertFalse(AuditEvent.objects.filter(pk=old.pk).exists())

    def test_cleanup_respects_a_longer_configured_retention(self):
        policy = SecurityPolicy.load()
        policy.audit_log_retention_days = 400
        policy.save(update_fields=["audit_log_retention_days"])

        old_but_within_retention = AuditEvent.objects.create(action="kept.event", target_type="system")
        AuditEvent.objects.filter(pk=old_but_within_retention.pk).update(
            created_at=timezone.now() - timezone.timedelta(days=200)
        )

        call_command("cleanup_identity")

        self.assertTrue(AuditEvent.objects.filter(pk=old_but_within_retention.pk).exists())


class AutomaticCleanupMiddlewareTests(TestCase):
    def test_a_normal_request_triggers_cleanup_when_the_interval_has_elapsed(self):
        policy = SecurityPolicy.load()
        policy.audit_log_retention_days = 10
        policy.save(update_fields=["audit_log_retention_days"])
        self.assertIsNone(policy.last_cleanup_at)

        old = AuditEvent.objects.create(action="old.event", target_type="system")
        AuditEvent.objects.filter(pk=old.pk).update(created_at=timezone.now() - timezone.timedelta(days=11))

        response = self.client.get(reverse("login"))
        self.assertEqual(response.status_code, 200)

        self.assertFalse(AuditEvent.objects.filter(pk=old.pk).exists())
        self.assertIsNotNone(SecurityPolicy.load().last_cleanup_at)

    def test_cleanup_does_not_rerun_within_the_interval(self):
        policy = SecurityPolicy.load()
        policy.audit_log_retention_days = 10
        policy.last_cleanup_at = timezone.now() - timezone.timedelta(hours=1)
        policy.save(update_fields=["audit_log_retention_days", "last_cleanup_at"])
        last_run = policy.last_cleanup_at

        old = AuditEvent.objects.create(action="old.event", target_type="system")
        AuditEvent.objects.filter(pk=old.pk).update(created_at=timezone.now() - timezone.timedelta(days=11))

        self.client.get(reverse("login"))

        self.assertTrue(AuditEvent.objects.filter(pk=old.pk).exists())
        self.assertEqual(SecurityPolicy.load().last_cleanup_at, last_run)

    def test_static_requests_do_not_trigger_cleanup(self):
        policy = SecurityPolicy.load()
        self.assertIsNone(policy.last_cleanup_at)
        self.client.get("/static/css/app.css")
        self.assertIsNone(SecurityPolicy.load().last_cleanup_at)


class SecurityPolicyAuditSettingsTests(TestCase):
    def setUp(self):
        self.admin = User.objects.create_superuser("audit-settings-admin", "admin@example.com", PASSWORD)
        self.client.force_login(self.admin)

    def test_settings_page_exposes_the_audit_retention_field(self):
        response = self.client.get(reverse("console:settings"))
        self.assertContains(response, 'id="audit-retention"')
        self.assertContains(response, 'name="audit_log_retention_days"')
