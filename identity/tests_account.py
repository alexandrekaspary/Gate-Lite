"""Regression tests for account profile, verified e-mail and account recovery.

The protocol test module is intentionally large.  Keeping these scenarios in a
separate module makes the security boundary around e-mail ownership easier to
review and allows this suite to be run directly with ``manage.py test
identity.tests_account``.
"""

import hashlib
import re
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from django.conf import settings
from django.contrib.auth import SESSION_KEY
from django.contrib.auth.models import User
from django.contrib.sessions.models import Session
from django.core import mail
from django.test import Client, SimpleTestCase, TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from .models import OIDCClient, OIDCSession, RefreshToken, UserEmailState
from .oidc import user_claims


PASSWORD = "Strong-password-123!"
NEW_PASSWORD = "Different-strong-password-456!"


class BrandAndControlStyleTests(SimpleTestCase):
    def test_brand_assets_are_valid_grayscale_svg_files(self):
        for name in ("gatelite-mark.svg", "favicon.svg"):
            with self.subTest(name=name):
                source = Path(settings.BASE_DIR, "static", "img", name).read_text()
                self.assertIn("<svg", source)
                self.assertIn("viewBox=", source)
                self.assertNotRegex(source, r"(?i)purple|violet|indigo")
                for color in re.findall(r"#[0-9a-f]{6}", source, re.IGNORECASE):
                    red, green, blue = color[1:3], color[3:5], color[5:7]
                    self.assertEqual(
                        red.lower(), green.lower(), f"{name}: {color} não é cinza"
                    )
                    self.assertEqual(
                        green.lower(), blue.lower(), f"{name}: {color} não é cinza"
                    )

    def test_every_page_shell_publishes_the_svg_favicon_and_new_brand_mark(self):
        shells = (
            "templates/base.html",
            "templates/account/base.html",
            "templates/registration/login.html",
            "templates/registration/login_2fa.html",
            "templates/registration/auth_base.html",
        )
        for relative_path in shells:
            with self.subTest(template=relative_path):
                source = Path(settings.BASE_DIR, relative_path).read_text()
                self.assertIn("img/favicon.svg", source)
                self.assertRegex(source, r"rel=[\"']icon[\"']")
                self.assertIn("img/gatelite-mark.svg", source)
                self.assertNotIn('<span class="brand-mark">G</span>', source)

    def test_single_selects_and_text_inputs_share_the_same_height(self):
        source = Path(settings.BASE_DIR, "static", "css", "app.css").read_text()
        input_height = re.search(
            r"(?:\.input|input)[^{]*\{[^}]*(?:height|min-height):\s*(\d+)px",
            source,
            re.DOTALL,
        )
        select_rule = re.search(
            r"select:not\(\[multiple\]\)[^{]*\{([^}]*)\}", source, re.DOTALL
        )
        self.assertIsNotNone(input_height, "Inputs precisam declarar uma altura estável.")
        self.assertIsNotNone(select_rule, "Select simples precisa de regra própria.")
        select_height = re.search(
            r"(?:height|min-height):\s*(\d+)px", select_rule.group(1)
        )
        self.assertIsNotNone(select_height)
        self.assertEqual(select_height.group(1), input_height.group(1))
        self.assertRegex(select_rule.group(1), r"box-sizing:\s*border-box")


class EmailSecurityMixin:
    def mark_email_verified(self, user):
        state, _ = UserEmailState.objects.get_or_create(user=user)
        state.email_verified = True
        state.verified_email = user.email.strip().casefold()
        state.pending_email = ""
        state.confirmation_token_hash = ""
        state.confirmation_expires_at = None
        state.confirmation_sent_at = None
        state.verified_at = timezone.now()
        state.save()
        return state

    def confirmation_url_from_outbox(self, index=-1):
        body = mail.outbox[index].body
        match = re.search(
            r"(?:https?://[^/\s]+)?/account/email/confirm/\?token=[A-Za-z0-9_-]+",
            body,
        )
        self.assertIsNotNone(match, body)
        value = match.group(0).rstrip(".,)")
        parsed = urlparse(value)
        return f"{parsed.path}?{parsed.query}" if parsed.scheme else value

    def request_email_change(self, email="new.address@example.com"):
        response = self.client.post(
            reverse("account-profile-edit"),
            {
                "first_name": "Novo",
                "last_name": "Nome",
                "email": email,
                # An attacker adding the field manually still cannot rename the
                # stable login identifier.
                "username": "renamed-by-attacker",
            },
        )
        self.assertEqual(response.status_code, 302, response.content)
        self.assertEqual(len(mail.outbox), 1)
        return self.confirmation_url_from_outbox()

    def make_protocol_session(self, user):
        client = OIDCClient.objects.create(
            name="Account test app", client_id=f"account-test-{user.pk}"
        )
        oidc_session = OIDCSession.objects.create(
            user=user,
            client=client,
            audience=client,
            authentication_version=user.security_state.authentication_version,
            expires_at=timezone.now() + timezone.timedelta(hours=1),
        )
        refresh = RefreshToken.objects.create(
            token_hash=hashlib.sha256(f"refresh-{user.pk}".encode()).hexdigest(),
            client=client,
            audience=client,
            oidc_session=oidc_session,
            user=user,
            scope="openid email offline_access",
            expires_at=timezone.now() + timezone.timedelta(hours=1),
        )
        return oidc_session, refresh


class AccountProfileEmailTests(EmailSecurityMixin, TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            "stable-username",
            email="old.address@example.com",
            password=PASSWORD,
            first_name="Old",
            last_name="Name",
        )
        self.mark_email_verified(self.user)
        self.client.force_login(self.user)
        mail.outbox.clear()

    def test_profile_form_edits_names_and_email_but_never_the_username(self):
        page = self.client.get(reverse("account-profile-edit"))
        self.assertEqual(page.status_code, 200)
        self.assertTemplateUsed(page, "account/profile_edit.html")
        self.assertEqual(
            list(page.context["form"].fields),
            ["first_name", "last_name", "email", "language", "timezone"],
        )
        self.assertContains(page, 'id="account-username"')
        self.assertContains(page, 'id="account-username" type="text"', html=False)
        self.assertContains(page, "disabled", html=False)
        self.assertNotContains(page, 'name="username"')

        self.request_email_change("New.Address@Example.COM")
        self.user.refresh_from_db()
        state = self.user.email_state
        self.assertEqual(self.user.username, "stable-username")
        self.assertEqual(self.user.first_name, "Novo")
        self.assertEqual(self.user.last_name, "Nome")
        self.assertEqual(self.user.email, "old.address@example.com")
        self.assertEqual(state.pending_email, "new.address@example.com")
        self.assertTrue(state.is_current_email_verified())

    def test_new_email_is_not_activated_before_a_post_confirmation(self):
        confirm_url = self.request_email_change()
        state = UserEmailState.objects.get(user=self.user)
        raw_token = parse_qs(urlparse(confirm_url).query)["token"][0]
        self.assertNotEqual(state.confirmation_token_hash, raw_token)
        self.assertEqual(
            state.confirmation_token_hash,
            hashlib.sha256(raw_token.encode()).hexdigest(),
        )

        preview = self.client.get(confirm_url)
        self.assertEqual(preview.status_code, 200)
        self.assertTemplateUsed(preview, "account/email_confirm.html")
        self.assertTrue(preview.context["valid_token"])
        self.user.refresh_from_db()
        state.refresh_from_db()
        self.assertEqual(self.user.email, "old.address@example.com")
        self.assertTrue(state.confirmation_token_hash)

        confirmed = self.client.post(confirm_url)
        self.assertEqual(confirmed.status_code, 302)
        self.user.refresh_from_db()
        state.refresh_from_db()
        self.assertEqual(self.user.email, "new.address@example.com")
        self.assertTrue(state.email_verified)
        self.assertEqual(state.verified_email, "new.address@example.com")
        self.assertEqual(state.pending_email, "")
        self.assertEqual(state.confirmation_token_hash, "")

    def test_confirmation_token_expires_and_cannot_be_reused(self):
        confirm_url = self.request_email_change()
        state = UserEmailState.objects.get(user=self.user)
        state.confirmation_expires_at = timezone.now() - timezone.timedelta(seconds=1)
        state.save(update_fields=["confirmation_expires_at"])

        expired = self.client.get(confirm_url)
        self.assertEqual(expired.status_code, 200)
        self.assertFalse(expired.context["valid_token"])
        self.client.post(confirm_url)
        self.user.refresh_from_db()
        self.assertEqual(self.user.email, "old.address@example.com")

        # Issue a fresh token and consume it once.
        state.confirmation_sent_at = timezone.now() - timezone.timedelta(minutes=2)
        state.save(update_fields=["confirmation_sent_at"])
        mail.outbox.clear()
        resent = self.client.post(reverse("account-email-resend"))
        self.assertEqual(resent.status_code, 302)
        self.assertEqual(len(mail.outbox), 1)
        fresh_url = self.confirmation_url_from_outbox()
        self.assertEqual(self.client.post(fresh_url).status_code, 302)

        reused = Client().get(fresh_url)
        self.assertEqual(reused.status_code, 200)
        self.assertTemplateUsed(reused, "account/email_confirm.html")
        self.assertFalse(reused.context["valid_token"])

    def test_case_insensitive_email_uniqueness_is_enforced(self):
        owner = User.objects.create_user(
            "email-owner", email="taken@example.com", password=PASSWORD
        )
        self.mark_email_verified(owner)
        mail.outbox.clear()

        response = self.client.post(
            reverse("account-profile-edit"),
            {
                "first_name": "Still",
                "last_name": "Me",
                "email": "TAKEN@EXAMPLE.COM",
            },
        )
        self.assertEqual(response.status_code, 400)
        self.assertFormError(
            response.context["form"],
            "email",
            "Este endereço de e-mail já está em uso.",
        )
        self.user.refresh_from_db()
        self.assertEqual(self.user.email, "old.address@example.com")
        self.assertEqual(self.user.email_state.pending_email, "")
        self.assertEqual(mail.outbox, [])

    def test_confirming_email_revokes_every_existing_session_and_refresh_token(self):
        confirm_url = self.request_email_change()
        state = self.user.security_state
        old_version = state.authentication_version
        oidc_session, refresh = self.make_protocol_session(self.user)
        other_browser = Client()
        other_browser.force_login(self.user)
        other_session_key = other_browser.session.session_key

        response = self.client.post(confirm_url)
        self.assertEqual(response.status_code, 302)
        state.refresh_from_db()
        oidc_session.refresh_from_db()
        refresh.refresh_from_db()
        self.assertNotEqual(state.authentication_version, old_version)
        self.assertIsNotNone(oidc_session.revoked_at)
        self.assertIsNotNone(refresh.revoked_at)
        self.assertFalse(Session.objects.filter(pk=other_session_key).exists())
        self.assertNotIn(SESSION_KEY, self.client.session)

    def test_confirmation_email_uses_plain_text_and_html_templates(self):
        self.request_email_change()
        message = mail.outbox[0]
        self.assertIn("GateLite", message.subject)
        self.assertIn("new.address@example.com", message.body)
        self.assertIn("/account/email/confirm/?token=", message.body)
        self.assertTrue(message.alternatives)
        html_body, mime_type = message.alternatives[0]
        self.assertEqual(mime_type, "text/html")
        self.assertIn("GateLite", html_body)
        self.assertIn("Confirmar", html_body)

    def test_confirmation_throttle_cannot_be_bypassed_with_another_address(self):
        self.request_email_change("first.pending@example.com")
        state = UserEmailState.objects.get(user=self.user)
        first_hash = state.confirmation_token_hash

        response = self.client.post(
            reverse("account-profile-edit"),
            {
                "first_name": "Novo",
                "last_name": "Nome",
                "email": "second.pending@example.com",
            },
        )

        self.assertRedirects(
            response, reverse("account-profile-edit"), fetch_redirect_response=False
        )
        state.refresh_from_db()
        self.assertEqual(state.pending_email, "first.pending@example.com")
        self.assertEqual(state.confirmation_token_hash, first_hash)
        self.assertEqual(len(mail.outbox), 1)


class OIDCVerifiedEmailClaimTests(EmailSecurityMixin, TestCase):
    def test_email_verified_claim_comes_from_persisted_matching_state(self):
        user = User.objects.create_user(
            "claims-user", email="claims@example.com", password=PASSWORD
        )
        client = OIDCClient.objects.create(name="Claims app", client_id="claims-app")

        unverified = user_claims(user, client, "openid email")
        self.assertEqual(unverified["email"], "claims@example.com")
        self.assertIs(unverified["email_verified"], False)

        state = self.mark_email_verified(user)
        user.refresh_from_db()
        verified = user_claims(user, client, "openid email")
        self.assertIs(verified["email_verified"], True)

        # A direct/stale User.email change cannot accidentally carry the old
        # verification bit into a JWT.
        User.objects.filter(pk=user.pk).update(email="other@example.com")
        user.refresh_from_db()
        state.refresh_from_db()
        self.assertFalse(state.is_current_email_verified())
        stale = user_claims(user, client, "openid email")
        self.assertIs(stale["email_verified"], False)


class VerifiedEmailPasswordResetTests(EmailSecurityMixin, TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            "recovery-user",
            email="verified.recovery@example.com",
            password=PASSWORD,
            first_name="Recovery",
        )
        self.mark_email_verified(self.user)
        mail.outbox.clear()

    def reset_url_from_outbox(self):
        match = re.search(r"https?://[^\s]+", mail.outbox[-1].body)
        self.assertIsNotNone(match, mail.outbox[-1].body)
        parsed = urlparse(match.group(0).rstrip(".,)"))
        return f"{parsed.path}?{parsed.query}" if parsed.query else parsed.path

    def request_reset(self, email=None, *, follow=False):
        return self.client.post(
            reverse("password-reset"),
            {"email": email or self.user.email},
            follow=follow,
        )

    def test_reset_response_does_not_enumerate_unknown_or_unverified_accounts(self):
        unverified = User.objects.create_user(
            "unverified-reset",
            email="unverified@example.com",
            password=PASSWORD,
        )
        UserEmailState.objects.get_or_create(user=unverified)

        observable_responses = []
        for email in (
            "missing@example.com",
            "unverified@example.com",
            "verified.recovery@example.com",
        ):
            with self.subTest(email=email):
                mail.outbox.clear()
                response = self.request_reset(email, follow=True)
                self.assertEqual(response.status_code, 200)
                self.assertTemplateUsed(response, "registration/password_reset_done.html")
                self.assertContains(
                    response,
                    "Se existir uma conta com o e-mail informado",
                )
                observable_responses.append(
                    (response.redirect_chain, response.content, response.status_code)
                )
                self.assertEqual(
                    len(mail.outbox),
                    1 if email == "verified.recovery@example.com" else 0,
                )

        self.assertEqual(observable_responses[0], observable_responses[1])
        self.assertEqual(observable_responses[1], observable_responses[2])

    def test_state_must_verify_the_users_current_email(self):
        state = self.user.email_state
        state.verified_email = "former-address@example.com"
        state.save(update_fields=["verified_email"])

        response = self.request_reset(follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(mail.outbox, [])

    def test_reset_email_has_text_and_html_versions_and_link_renders(self):
        response = self.request_reset()
        self.assertRedirects(
            response,
            reverse("password-reset-done"),
            fetch_redirect_response=False,
        )
        self.assertEqual(len(mail.outbox), 1)
        message = mail.outbox[0]
        self.assertIn("Redefinição de senha", message.subject)
        self.assertIn("GateLite", message.body)
        self.assertTrue(message.alternatives)
        self.assertEqual(message.alternatives[0].mimetype, "text/html")
        self.assertIn("Redefinir minha senha", message.alternatives[0].content)

        reset_url = self.reset_url_from_outbox()
        landing = self.client.get(reset_url)
        self.assertEqual(landing.status_code, 302)
        form_page = self.client.get(landing.url)
        self.assertEqual(form_page.status_code, 200)
        self.assertTemplateUsed(form_page, "registration/password_reset_confirm.html")
        self.assertTrue(form_page.context["validlink"])

    def test_successful_reset_changes_password_and_revokes_all_access(self):
        oidc_session, refresh = self.make_protocol_session(self.user)
        old_version = self.user.security_state.authentication_version

        first_browser = Client()
        second_browser = Client()
        first_browser.force_login(self.user)
        second_browser.force_login(self.user)
        first_key = first_browser.session.session_key
        second_key = second_browser.session.session_key

        self.request_reset()
        reset_url = self.reset_url_from_outbox()
        recovery_browser = Client()
        landing = recovery_browser.get(reset_url)
        self.assertEqual(landing.status_code, 302)
        completed = recovery_browser.post(
            landing.url,
            {
                "new_password1": NEW_PASSWORD,
                "new_password2": NEW_PASSWORD,
            },
        )
        self.assertRedirects(
            completed,
            reverse("password-reset-complete"),
            fetch_redirect_response=False,
        )

        self.user.refresh_from_db()
        self.user.security_state.refresh_from_db()
        oidc_session.refresh_from_db()
        refresh.refresh_from_db()
        self.assertTrue(self.user.check_password(NEW_PASSWORD))
        self.assertNotEqual(
            self.user.security_state.authentication_version, old_version
        )
        self.assertIsNotNone(oidc_session.revoked_at)
        self.assertIsNotNone(refresh.revoked_at)
        self.assertFalse(Session.objects.filter(pk=first_key).exists())
        self.assertFalse(Session.objects.filter(pk=second_key).exists())

        # Django's password-reset token is also one-use because changing the
        # password invalidates its signature.
        reused = Client().get(reset_url)
        self.assertEqual(reused.status_code, 200)
        self.assertTemplateUsed(reused, "registration/password_reset_confirm.html")
        self.assertFalse(reused.context["validlink"])

    def test_password_reset_pages_render_the_professional_auth_shell(self):
        form = self.client.get(reverse("password-reset"))
        self.assertEqual(form.status_code, 200)
        self.assertTemplateUsed(form, "registration/password_reset_form.html")
        self.assertTemplateUsed(form, "registration/auth_base.html")
        self.assertContains(form, 'for="id_email"')
        self.assertContains(form, "img/gatelite-mark.svg")
        self.assertContains(form, "img/favicon.svg")


class ConsoleEmailVerificationTests(EmailSecurityMixin, TestCase):
    def setUp(self):
        self.admin = User.objects.create_superuser(
            "email-admin", "admin@example.com", PASSWORD
        )
        self.mark_email_verified(self.admin)
        self.client.force_login(self.admin)
        mail.outbox.clear()

    def test_console_created_user_receives_a_confirmation_email(self):
        response = self.client.post(
            reverse("console:create", args=["users"]),
            {
                "username": "created-by-console",
                "first_name": "Created",
                "last_name": "User",
                "email": "created@example.com",
                "password1": PASSWORD,
                "password2": PASSWORD,
                "is_active": "on",
            },
        )
        self.assertEqual(response.status_code, 302, response.content)
        created = User.objects.get(username="created-by-console")
        state = UserEmailState.objects.get(user=created)
        self.assertFalse(state.email_verified)
        self.assertEqual(state.pending_email, "created@example.com")
        self.assertTrue(state.confirmation_token_hash)
        self.assertEqual(len(mail.outbox), 1)
        self.assertEqual(mail.outbox[0].to, ["created@example.com"])

    @override_settings(EMAIL_ENABLED=False)
    def test_confirmation_is_skipped_when_email_is_disabled(self):
        from .email_verification import request_email_confirmation

        user = User.objects.create_user(
            "without-email-delivery",
            email="without.delivery@example.com",
            password=PASSWORD,
        )
        result = request_email_confirmation(user, user.email)

        state = UserEmailState.objects.get(user=user)
        self.assertFalse(result.sent)
        self.assertEqual(state.pending_email, "")
        self.assertEqual(state.confirmation_token_hash, "")
        self.assertEqual(mail.outbox, [])

    def test_admin_email_edit_is_pending_and_does_not_silently_claim_address(self):
        target = User.objects.create_user(
            "managed-user",
            email="managed.old@example.com",
            password=PASSWORD,
            first_name="Managed",
            last_name="User",
        )
        self.mark_email_verified(target)
        mail.outbox.clear()
        response = self.client.post(
            reverse("console:edit", args=["users", target.pk]),
            {
                "username": target.username,
                "first_name": target.first_name,
                "last_name": target.last_name,
                "email": "managed.new@example.com",
                "new_password": "",
                "is_active": "on",
            },
        )
        self.assertEqual(response.status_code, 302, response.content)
        target.refresh_from_db()
        state = target.email_state
        self.assertEqual(target.email, "managed.old@example.com")
        self.assertTrue(state.is_current_email_verified())
        self.assertEqual(state.pending_email, "managed.new@example.com")
        self.assertTrue(state.confirmation_token_hash)
        self.assertEqual(len(mail.outbox), 1)
        self.assertEqual(mail.outbox[0].to, ["managed.new@example.com"])


class PolicyDrivenRecoveryTimeoutTests(EmailSecurityMixin, TestCase):
    """As validades e janelas de reenvio vêm da SecurityPolicy persistida."""

    def setUp(self):
        self.user = User.objects.create_user(
            "policy-recovery",
            email="policy.recovery@example.com",
            password=PASSWORD,
        )
        self.mark_email_verified(self.user)
        mail.outbox.clear()

    def test_reset_link_validity_follows_the_persisted_policy(self):
        from datetime import datetime, timedelta

        from .models import SecurityPolicy
        from .views import PolicyPasswordResetTokenGenerator, SecurePasswordResetConfirmView

        self.assertIsInstance(
            SecurePasswordResetConfirmView.token_generator,
            PolicyPasswordResetTokenGenerator,
        )
        policy = SecurityPolicy.load()
        policy.password_reset_timeout = 600
        policy.save()

        class AgedGenerator(PolicyPasswordResetTokenGenerator):
            def __init__(self, age_seconds):
                super().__init__()
                self.age_seconds = age_seconds

            def _now(self):
                return datetime.now() - timedelta(seconds=self.age_seconds)

        generator = PolicyPasswordResetTokenGenerator()
        within = AgedGenerator(300).make_token(self.user)
        beyond = AgedGenerator(900).make_token(self.user)
        self.assertTrue(generator.check_token(self.user, within))
        self.assertFalse(generator.check_token(self.user, beyond))

        # A validade é conferida ao abrir o link: ampliar a política revalida
        # um token já emitido, sem reemissão.
        policy.password_reset_timeout = 1200
        policy.save()
        self.assertTrue(generator.check_token(self.user, beyond))

    def test_second_reset_request_is_throttled_without_changing_the_response(self):
        from .models import SecurityPolicy

        policy = SecurityPolicy.load()
        policy.password_reset_resend_seconds = 120
        policy.save()

        first = self.client.post(
            reverse("password-reset"), {"email": self.user.email}, follow=True
        )
        second = self.client.post(
            reverse("password-reset"), {"email": self.user.email}, follow=True
        )
        self.assertEqual(first.status_code, 200)
        self.assertEqual(second.status_code, 200)
        self.assertEqual(first.content, second.content)
        self.assertEqual(len(mail.outbox), 1)

        UserEmailState.objects.filter(user=self.user).update(
            password_reset_sent_at=timezone.now() - timezone.timedelta(seconds=121)
        )
        self.client.post(reverse("password-reset"), {"email": self.user.email})
        self.assertEqual(len(mail.outbox), 2)

    def test_confirmation_expiry_and_resend_window_come_from_the_policy(self):
        from .email_verification import EmailConfirmationThrottled, request_email_confirmation
        from .models import SecurityPolicy

        policy = SecurityPolicy.load()
        policy.email_confirmation_timeout = 600
        policy.email_confirmation_resend_seconds = 45
        policy.save()

        user = User.objects.create_user("policy-mail", password=PASSWORD)
        request_email_confirmation(user, "policy-mail@example.com")
        state = UserEmailState.objects.get(user=user)
        remaining = (state.confirmation_expires_at - timezone.now()).total_seconds()
        self.assertAlmostEqual(remaining, 600, delta=30)

        with self.assertRaises(EmailConfirmationThrottled) as ctx:
            request_email_confirmation(user, "policy-mail@example.com")
        self.assertLessEqual(ctx.exception.retry_after, 45)
