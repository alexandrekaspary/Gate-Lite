"""Regression tests for the public self-registration screen and its settings."""

from django.contrib.auth.models import Group, User
from django.core import mail
from django.test import TestCase
from django.urls import reverse

from .models import AuditEvent, SecurityPolicy, UserPreferences


PASSWORD = "Strong-password-123!"


class RegistrationAvailabilityTests(TestCase):
    def test_register_page_redirects_to_login_when_disabled(self):
        response = self.client.get(reverse("register"))
        self.assertRedirects(response, reverse("login"))

    def test_register_post_is_ignored_when_disabled(self):
        response = self.client.post(
            reverse("register"),
            {
                "username": "should-not-exist",
                "first_name": "A",
                "last_name": "B",
                "email": "blocked@example.com",
                "password1": PASSWORD,
                "password2": PASSWORD,
            },
        )
        self.assertRedirects(response, reverse("login"))
        self.assertFalse(User.objects.filter(username="should-not-exist").exists())

    def test_login_page_hides_the_register_link_when_disabled(self):
        response = self.client.get(reverse("login"))
        self.assertNotContains(response, reverse("register"))

    def test_login_page_shows_the_register_link_when_enabled(self):
        policy = SecurityPolicy.load()
        policy.registration_enabled = True
        policy.save(update_fields=["registration_enabled"])
        response = self.client.get(reverse("login"))
        self.assertContains(response, reverse("register"))

    def test_authenticated_users_are_redirected_away_from_register(self):
        policy = SecurityPolicy.load()
        policy.registration_enabled = True
        policy.save(update_fields=["registration_enabled"])
        user = User.objects.create_user("already-signed-in", password=PASSWORD)
        self.client.force_login(user)
        response = self.client.get(reverse("register"))
        self.assertRedirects(response, reverse("account"))

    def test_enabled_register_page_renders_the_form(self):
        policy = SecurityPolicy.load()
        policy.registration_enabled = True
        policy.save(update_fields=["registration_enabled"])
        response = self.client.get(reverse("register"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "registration/register.html")
        self.assertTemplateUsed(response, "registration/auth_base.html")
        self.assertContains(response, 'name="username"')
        self.assertContains(response, 'name="password1"')
        self.assertContains(response, 'name="password2"')


class SelfRegistrationTests(TestCase):
    def setUp(self):
        self.policy = SecurityPolicy.load()
        self.policy.registration_enabled = True
        self.policy.default_language = "en"
        self.policy.default_timezone = "America/Sao_Paulo"
        self.policy.save(update_fields=["registration_enabled", "default_language", "default_timezone"])
        self.default_group = Group.objects.create(name="Cadastrados")
        self.policy.registration_default_groups.set([self.default_group])
        mail.outbox.clear()

    def post_registration(self, **overrides):
        data = {
            "username": "new-signup",
            "first_name": "New",
            "last_name": "Signup",
            "email": "signup@example.com",
            "password1": PASSWORD,
            "password2": PASSWORD,
        }
        data.update(overrides)
        return self.client.post(reverse("register"), data)

    def test_successful_registration_creates_an_active_user_with_policy_defaults(self):
        response = self.post_registration()
        self.assertRedirects(response, reverse("login"))
        user = User.objects.get(username="new-signup")
        self.assertTrue(user.is_active)
        self.assertTrue(user.check_password(PASSWORD))
        self.assertEqual(list(user.groups.all()), [self.default_group])
        preferences = UserPreferences.objects.get(user=user)
        self.assertEqual(preferences.language, "en")
        self.assertEqual(preferences.timezone, "America/Sao_Paulo")
        self.assertTrue(user.has_perm("identity.view_own_profile"))
        self.assertTrue(user.has_perm("identity.change_own_password"))

    def test_successful_registration_sends_the_confirmation_email_and_audits(self):
        response = self.post_registration()
        self.assertRedirects(response, reverse("login"))
        user = User.objects.get(username="new-signup")
        self.assertEqual(len(mail.outbox), 1)
        self.assertEqual(mail.outbox[0].to, ["signup@example.com"])
        self.assertTrue(
            AuditEvent.objects.filter(action="user.self_registered", target_id=str(user.pk)).exists()
        )

    def test_registration_cannot_grant_staff_superuser_or_arbitrary_groups(self):
        other_group = Group.objects.create(name="Administradores")
        self.post_registration(
            username="sneaky",
            email="sneaky@example.com",
            is_staff="on",
            is_superuser="on",
            groups=[other_group.pk],
        )
        user = User.objects.get(username="sneaky")
        self.assertFalse(user.is_staff)
        self.assertFalse(user.is_superuser)
        self.assertEqual(list(user.groups.all()), [self.default_group])

    def test_duplicate_username_is_rejected_without_creating_a_second_account(self):
        User.objects.create_user("taken", password=PASSWORD)
        response = self.post_registration(username="taken", email="another@example.com")
        self.assertEqual(response.status_code, 200)
        self.assertFalse(mail.outbox)
        self.assertEqual(User.objects.filter(username="taken").count(), 1)

    def test_duplicate_email_is_rejected_case_insensitively(self):
        User.objects.create_user("existing-owner", email="dup@example.com", password=PASSWORD)
        response = self.post_registration(username="brand-new", email="DUP@example.com")
        self.assertEqual(response.status_code, 200)
        self.assertFalse(User.objects.filter(username="brand-new").exists())

    def test_password_must_satisfy_the_configured_policy(self):
        self.policy.password_min_length = 12
        self.policy.save(update_fields=["password_min_length"])
        response = self.post_registration(
            username="weak-password", email="weak@example.com",
            password1="short1A!", password2="short1A!",
        )
        self.assertEqual(response.status_code, 200)
        self.assertFalse(User.objects.filter(username="weak-password").exists())

    def test_registration_without_default_groups_creates_a_groupless_user(self):
        self.policy.registration_default_groups.clear()
        response = self.post_registration(username="groupless", email="groupless@example.com")
        self.assertRedirects(response, reverse("login"))
        user = User.objects.get(username="groupless")
        self.assertEqual(list(user.groups.all()), [])


class SecurityPolicyRegistrationSettingsTests(TestCase):
    def setUp(self):
        self.admin = User.objects.create_superuser("settings-admin", "admin@example.com", PASSWORD)
        self.client.force_login(self.admin)

    def base_policy_fields(self):
        policy = SecurityPolicy.load()
        return {
            "password_min_length": policy.password_min_length,
            "mfa_mode": policy.mfa_mode,
            "access_token_ttl": policy.access_token_ttl,
            "id_token_ttl": policy.id_token_ttl,
            "refresh_token_ttl": policy.refresh_token_ttl,
            "sso_session_ttl": policy.sso_session_ttl,
            "client_secret_grace_period": policy.client_secret_grace_period,
            "email_confirmation_timeout": policy.email_confirmation_timeout,
            "email_confirmation_resend_seconds": policy.email_confirmation_resend_seconds,
            "password_reset_timeout": policy.password_reset_timeout,
            "password_reset_resend_seconds": policy.password_reset_resend_seconds,
            "login_max_attempts": policy.login_max_attempts,
            "login_lockout_seconds": policy.login_lockout_seconds,
            "default_language": policy.default_language,
            "default_timezone": policy.default_timezone,
            "audit_log_retention_days": policy.audit_log_retention_days,
            # The settings form is a single unified <form>; the real page always
            # submits this marker, and an unbound EmailConfigurationForm is
            # invalid, so a policy-only save must include it too.
            "email_settings_submitted": "1",
        }

    def test_settings_page_exposes_the_registration_section(self):
        Group.objects.create(name="Padrão")
        response = self.client.get(reverse("console:settings"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'id="registration"')
        self.assertContains(response, 'name="registration_enabled"')
        self.assertContains(response, 'name="registration_default_groups"')

    def test_admin_can_enable_registration_and_assign_default_groups(self):
        group = Group.objects.create(name="Padrão")
        response = self.client.post(
            reverse("console:settings"),
            {
                **self.base_policy_fields(),
                "registration_enabled": "on",
                "registration_default_groups": [group.pk],
            },
        )
        self.assertRedirects(response, reverse("console:settings"), fetch_redirect_response=False)
        policy = SecurityPolicy.load()
        self.assertTrue(policy.registration_enabled)
        self.assertEqual(list(policy.registration_default_groups.all()), [group])

    def test_admin_can_disable_registration(self):
        policy = SecurityPolicy.load()
        policy.registration_enabled = True
        policy.save(update_fields=["registration_enabled"])
        response = self.client.post(reverse("console:settings"), self.base_policy_fields())
        self.assertRedirects(response, reverse("console:settings"), fetch_redirect_response=False)
        self.assertFalse(SecurityPolicy.load().registration_enabled)
