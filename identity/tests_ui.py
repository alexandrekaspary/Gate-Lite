"""Stable UI and route contracts not covered by the protocol-heavy test suite.

These tests intentionally assert semantic structure, form contracts and observable
navigation.  They avoid snapshots and styling details that may change without
affecting usability.
"""

import base64
import re
from pathlib import Path

from django import forms
from django.conf import settings
from django.contrib.auth.models import Group, Permission, User
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from .forms import (
    ClientForm,
    ClientRoleForm,
    GroupForm,
    MFAChallengeForm,
    MFASetupConfirmForm,
    PasswordAndMFAForm,
    PermissionForm,
    SecurityPolicyForm,
    UserCreateForm,
    UserEditForm,
)
from .models import (
    AuditEvent,
    ClientRole,
    OIDCClient,
    OIDCSession,
    RefreshToken,
    SecurityPolicy,
    SigningKey,
    UserMFA,
)


PASSWORD = "Strong-password-123!"
TOTP_SECRET = base64.b32encode(b"12345678901234567890").decode().rstrip("=")


def permission(codename):
    return Permission.objects.get(
        content_type__app_label="identity", codename=codename
    )


def enable_mfa(user, recovery_codes=()):
    device = UserMFA(
        user=user,
        encrypted_secret=b"",
        enabled=True,
        verified_at=timezone.now(),
        recovery_code_hashes=list(recovery_codes),
    )
    device.set_secret(TOTP_SECRET)
    device.save()
    return device


class FormWidgetContractTests(TestCase):
    def test_management_and_mfa_forms_expose_labels_and_input_classes(self):
        user = User.objects.create_user("form-user", password=PASSWORD)
        policy = SecurityPolicy.load()
        managed_forms = (
            UserCreateForm(),
            UserEditForm(instance=user),
            GroupForm(),
            ClientForm(),
            ClientRoleForm(),
            PermissionForm(),
            SecurityPolicyForm(instance=policy),
            MFASetupConfirmForm(),
            MFAChallengeForm(),
            PasswordAndMFAForm(user),
        )

        for form in managed_forms:
            with self.subTest(form=form.__class__.__name__):
                for name, field in form.fields.items():
                    bound = form[name]
                    self.assertTrue(bound.label, f"{form.__class__.__name__}.{name}")
                    if not isinstance(
                        field.widget,
                        (
                            forms.CheckboxInput,
                            forms.CheckboxSelectMultiple,
                            forms.RadioSelect,
                            forms.HiddenInput,
                        ),
                    ):
                        self.assertIn(
                            "input",
                            field.widget.attrs.get("class", "").split(),
                            f"{form.__class__.__name__}.{name}",
                        )

        self.assertTrue(UserCreateForm().fields["basic_access"].disabled)
        self.assertIsInstance(ClientForm().fields["require_mfa"].widget, forms.CheckboxInput)
        self.assertIsInstance(UserEditForm(instance=user).fields["reset_mfa"].widget, forms.CheckboxInput)

    def test_one_time_code_widgets_publish_mobile_and_autocomplete_hints(self):
        user = User.objects.create_user("mfa-form-user", password=PASSWORD)
        setup = MFASetupConfirmForm().fields["code"]
        challenge = MFAChallengeForm().fields["code"]
        protected_action = PasswordAndMFAForm(user).fields["code"]

        self.assertEqual(setup.widget.attrs["inputmode"], "numeric")
        self.assertEqual(setup.widget.attrs["autocomplete"], "one-time-code")
        self.assertEqual(setup.widget.attrs["maxlength"], "6")
        self.assertEqual(challenge.widget.attrs["autocomplete"], "one-time-code")
        self.assertGreaterEqual(challenge.max_length, 24)
        self.assertEqual(
            protected_action.widget.attrs["autocomplete"], "one-time-code"
        )
        self.assertGreaterEqual(protected_action.max_length, 24)

    def test_checkbox_alignment_slot_has_a_responsive_css_contract(self):
        app_css = Path(settings.BASE_DIR, "static/css/app.css").read_text()
        console_css = Path(settings.BASE_DIR, "static/css/console.css").read_text()

        self.assertRegex(
            app_css,
            re.compile(
                r"\.control-label-spacer\s*\{[^}]*min-height:\s*20px",
                re.DOTALL,
            ),
        )
        self.assertRegex(
            console_css,
            re.compile(
                r"@media\s*\(max-width:\s*720px\).*?"
                r"\.checkbox-field\s*>\s*\.control-label-spacer\s*,\s*"
                r"\.setting-toggle\s*>\s*\.control-label-spacer\s*"
                r"\{\s*display:\s*none;\s*\}",
                re.DOTALL,
            ),
        )


class LoginTemplateContractTests(TestCase):
    def test_login_renders_labeled_credentials_and_preserves_safe_next(self):
        response = self.client.get(
            reverse("login"), {"next": reverse("console:list", args=["clients"])}
        )

        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "registration/login.html")
        self.assertContains(response, 'for="id_username"')
        self.assertContains(response, 'for="id_password"')
        self.assertContains(response, 'class="input-icon-wrap"', count=2)
        self.assertContains(response, 'class="btn primary login-submit"')
        self.assertContains(
            response,
            'name="next" value="/console/clients/"',
            html=False,
        )

    def test_invalid_login_renders_the_forms_real_non_field_error(self):
        response = self.client.post(
            reverse("login"), {"username": "missing", "password": "wrong"}
        )

        self.assertEqual(response.status_code, 200)
        errors = list(response.context["form"].non_field_errors())
        self.assertTrue(errors)
        for error in errors:
            self.assertContains(response, error)
        self.assertContains(response, 'class="alert error"')

    def test_two_factor_challenge_template_and_expired_message_are_rendered(self):
        user = User.objects.create_user("login-mfa", password=PASSWORD)
        enable_mfa(user)
        password_step = self.client.post(
            reverse("login"), {"username": user.username, "password": PASSWORD}
        )
        self.assertRedirects(
            password_step, reverse("login-2fa"), fetch_redirect_response=False
        )

        challenge = self.client.get(reverse("login-2fa"))
        self.assertEqual(challenge.status_code, 200)
        self.assertTemplateUsed(challenge, "registration/login_2fa.html")
        self.assertContains(challenge, 'for="id_code"')
        self.assertContains(challenge, 'autocomplete="one-time-code"')
        self.assertContains(challenge, 'id="two-factor-form"')
        self.assertEqual(challenge["Cache-Control"], "no-store")
        self.assertEqual(challenge["Referrer-Policy"], "no-referrer")

        session = self.client.session
        session.pop("mfa_challenge_id", None)
        session.save()
        expired = self.client.get(reverse("login-2fa"), follow=True)
        self.assertRedirects(expired, reverse("login"))
        self.assertContains(expired, "A verificação expirou. Entre novamente.")
        self.assertContains(expired, 'class="message-stack"')


class ConsoleTemplateContractTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.admin = User.objects.create_superuser(
            "ui-admin", "ui-admin@example.com", PASSWORD
        )

    def setUp(self):
        self.client.force_login(self.admin)

    def test_all_console_lists_render_common_navigation_filters_and_tables(self):
        for kind in ("users", "groups", "clients", "roles", "permissions"):
            with self.subTest(kind=kind):
                response = self.client.get(reverse("console:list", args=[kind]))
                self.assertEqual(response.status_code, 200)
                self.assertTemplateUsed(response, "console/list.html")
                self.assertEqual(response.context["kind"], kind)
                self.assertContains(response, 'class="filterbar"')
                self.assertContains(response, 'class="table-card"')
                self.assertContains(response, 'class="data-table"')
                self.assertContains(response, reverse("console:create", args=[kind]))

        dashboard = self.client.get(reverse("console:dashboard"))
        self.assertTemplateUsed(dashboard, "console/dashboard.html")
        self.assertContains(dashboard, 'id="console-sidebar"')
        self.assertContains(dashboard, "Usuários")
        self.assertContains(dashboard, "Grupos")
        self.assertContains(dashboard, "Clients")

    def test_console_create_forms_render_a_label_for_every_visible_field(self):
        expected_fields = {
            "users": ("username", "groups", "client_roles"),
            "groups": ("name", "users", "client_roles", "permissions"),
            "clients": ("client_id", "client_type", "require_mfa", "redirect_uris"),
            "roles": ("client", "name", "groups", "users", "composites"),
            "permissions": ("name", "codename", "content_type"),
        }
        for kind, required_names in expected_fields.items():
            with self.subTest(kind=kind):
                response = self.client.get(reverse("console:create", args=[kind]))
                self.assertEqual(response.status_code, 200)
                self.assertTemplateUsed(response, "console/form.html")
                self.assertContains(response, 'class="form-grid wizard-form"')
                form = response.context["form"]
                self.assertTrue(set(required_names).issubset(form.fields))
                for field in form.visible_fields():
                    if isinstance(field.field.widget, forms.CheckboxSelectMultiple):
                        self.assertContains(response, f'id="{field.auto_id}-label"')
                    else:
                        self.assertTrue(field.id_for_label)
                        self.assertContains(response, f'for="{field.id_for_label}"')
                    self.assertContains(response, f'data-field="{field.name}"')

        client_form = self.client.get(reverse("console:create", args=["clients"]))
        self.assertContains(client_form, 'data-field="require_mfa"')
        self.assertContains(client_form, 'class="checkbox-control"')
        self.assertContains(
            client_form,
            '<span class="control-label-spacer" aria-hidden="true"></span>',
            html=True,
        )

    def test_bound_client_errors_are_visible_in_the_wizard(self):
        response = self.client.post(
            reverse("console:create", args=["clients"]),
            {
                "name": "Broken web client",
                "client_id": "broken-web",
                "application_type": OIDCClient.ApplicationType.WEB,
                "client_type": OIDCClient.ClientType.CONFIDENTIAL,
                "token_endpoint_auth_method": OIDCClient.AuthMethod.BASIC,
                "authorization_code_enabled": "on",
                "refresh_token_enabled": "on",
                "access_policy": OIDCClient.AccessPolicy.OPEN,
                "is_active": "on",
                "redirect_uris": "",
                "post_logout_redirect_uris": "",
                "allowed_origins": "",
                "scopes": "openid profile",
            },
        )

        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "console/form.html")
        error = "Informe ao menos uma Redirect URI para Authorization Code."
        self.assertFormError(response.context["form"], "redirect_uris", error)
        self.assertContains(response, error)
        self.assertContains(response, 'class="field-error"')

    def test_search_status_client_filter_and_pagination_shape_results(self):
        User.objects.create_user("needle-active", password=PASSWORD, is_active=True)
        User.objects.create_user("needle-inactive", password=PASSWORD, is_active=False)
        users = self.client.get(
            reverse("console:list", args=["users"]),
            {"q": "needle", "status": "active"},
        )
        self.assertEqual(
            [obj.username for obj in users.context["objects"]], ["needle-active"]
        )

        first_client = OIDCClient.objects.create(name="API A", client_id="api-a")
        second_client = OIDCClient.objects.create(name="API B", client_id="api-b")
        expected_role = ClientRole.objects.create(client=first_client, name="reader")
        ClientRole.objects.create(client=second_client, name="reader")
        roles = self.client.get(
            reverse("console:list", args=["roles"]),
            {"q": "reader", "client": first_client.pk},
        )
        self.assertEqual(list(roles.context["objects"]), [expected_role])
        self.assertContains(roles, f'value="{first_client.pk}" selected')

        Group.objects.bulk_create([Group(name=f"page-group-{index:02}") for index in range(26)])
        second_page = self.client.get(
            reverse("console:list", args=["groups"]), {"page": 2}
        )
        self.assertEqual(second_page.context["page_obj"].number, 2)
        self.assertContains(second_page, 'class="pagination"')


class AccountTemplateAndRouteTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user("account-user", password=PASSWORD)
        self.other = User.objects.create_user("other-user", password=PASSWORD)
        self.client.force_login(self.user)

    def test_profile_password_and_mfa_status_render_self_service_controls(self):
        group = Group.objects.create(name="Operations")
        self.user.groups.add(group)

        profile = self.client.get(reverse("account"))
        self.assertEqual(profile.status_code, 200)
        self.assertTemplateUsed(profile, "account/profile.html")
        self.assertContains(profile, 'class="account-topbar"')
        self.assertContains(profile, "Operations")
        self.assertContains(profile, reverse("change-own-password"))
        self.assertContains(profile, reverse("account-mfa"))

        password = self.client.get(reverse("change-own-password"))
        self.assertTemplateUsed(password, "account/password.html")
        for field in password.context["form"].visible_fields():
            self.assertIn("input", field.field.widget.attrs.get("class", "").split())
            self.assertContains(password, f'for="{field.id_for_label}"')

        mfa_status = self.client.get(reverse("account-mfa"))
        self.assertTemplateUsed(mfa_status, "account/mfa_status.html")
        self.assertContains(mfa_status, "Autenticação em duas etapas desativada")
        self.assertContains(mfa_status, reverse("account-mfa-setup"))

    def test_mfa_setup_and_enabled_status_render_qr_fields_and_protected_actions(self):
        setup = self.client.get(reverse("account-mfa-setup"))
        self.assertEqual(setup.status_code, 200)
        self.assertTemplateUsed(setup, "account/mfa_setup.html")
        self.assertContains(setup, 'class="mfa-setup-grid"')
        self.assertContains(setup, "data:image/svg+xml;base64,")
        self.assertContains(setup, 'for="id_code"')
        self.assertContains(setup, 'autocomplete="one-time-code"')
        self.assertEqual(setup["Cache-Control"], "no-store")

        enable_mfa(self.user, recovery_codes=["hash-one", "hash-two"])
        status = self.client.get(reverse("account-mfa"))
        self.assertContains(status, "Autenticação em duas etapas ativa")
        self.assertContains(status, reverse("account-mfa-disable"))
        self.assertContains(status, reverse("account-mfa-recovery"))
        self.assertContains(status, 'id="disable-password"')
        self.assertContains(status, 'id="recovery-code"')
        self.assertContains(status, "2 restantes")

        invalid_disable = self.client.post(
            reverse("account-mfa-disable"),
            {"password": "wrong-password", "code": "000000"},
        )
        self.assertEqual(invalid_disable.status_code, 400)
        self.assertTemplateUsed(invalid_disable, "account/mfa_status.html")
        self.assertContains(invalid_disable, "Senha incorreta.", status_code=400)
        self.assertContains(
            invalid_disable, 'class="field-error"', status_code=400
        )
        self.assertTrue(UserMFA.objects.filter(user=self.user, enabled=True).exists())

    def test_session_revocation_is_post_only_and_scoped_to_the_owner(self):
        client = OIDCClient.objects.create(name="Portal", client_id="portal")
        expires_at = timezone.now() + timezone.timedelta(hours=1)
        own_session = OIDCSession.objects.create(
            user=self.user,
            client=client,
            audience=client,
            expires_at=expires_at,
        )
        other_session = OIDCSession.objects.create(
            user=self.other,
            client=client,
            audience=client,
            expires_at=expires_at,
        )
        refresh = RefreshToken.objects.create(
            token_hash="a" * 64,
            client=client,
            audience=client,
            oidc_session=own_session,
            user=self.user,
            scope="openid",
            expires_at=expires_at,
        )

        profile = self.client.get(reverse("account"))
        self.assertContains(profile, "Portal")
        self.assertContains(profile, reverse("revoke-own-session", args=[own_session.pk]))
        self.assertEqual(
            self.client.get(
                reverse("revoke-own-session", args=[own_session.pk])
            ).status_code,
            405,
        )
        self.assertEqual(
            self.client.post(
                reverse("revoke-own-session", args=[other_session.pk])
            ).status_code,
            404,
        )
        own_session.refresh_from_db()
        self.assertIsNone(own_session.revoked_at)

        revoked = self.client.post(
            reverse("revoke-own-session", args=[own_session.pk])
        )
        self.assertRedirects(revoked, reverse("account"), fetch_redirect_response=False)
        own_session.refresh_from_db()
        refresh.refresh_from_db()
        self.assertIsNotNone(own_session.revoked_at)
        self.assertIsNotNone(refresh.revoked_at)
        other_session.refresh_from_db()
        self.assertIsNone(other_session.revoked_at)

    def test_password_page_rejects_users_without_self_service_permission(self):
        self.user.user_permissions.remove(permission("change_own_password"))
        denied = self.client.get(reverse("change-own-password"))
        self.assertEqual(denied.status_code, 403)
        self.assertEqual(denied.json(), {"error": "access_denied"})


class PolicyAndRouteContractTests(TestCase):
    def test_manage_security_can_render_and_persist_the_complete_policy(self):
        operator = User.objects.create_user("security-operator", password=PASSWORD)
        operator.user_permissions.add(permission("manage_security"))
        self.client.force_login(operator)

        page = self.client.get(reverse("console:settings"))
        self.assertEqual(page.status_code, 200)
        self.assertTemplateUsed(page, "console/settings.html")
        self.assertContains(page, 'id="mfa"')
        self.assertContains(page, 'name="mfa_mode"')
        self.assertContains(page, 'class="settings-savebar"')
        self.assertContains(
            page,
            '<span class="control-label-spacer" aria-hidden="true"></span>',
            html=True,
        )

        response = self.client.post(
            reverse("console:settings"),
            {
                "password_min_length": 14,
                "password_require_uppercase": "on",
                "password_require_lowercase": "on",
                "password_require_number": "on",
                "password_require_special": "on",
                "mfa_mode": SecurityPolicy.MFAMode.ALL,
                "access_token_ttl": 420,
                "id_token_ttl": 430,
                "refresh_token_ttl": 3600,
                "sso_session_ttl": 7200,
                "client_secret_grace_period": 120,
                "email_confirmation_timeout": 43200,
                "email_confirmation_resend_seconds": 90,
                "password_reset_timeout": 1800,
                "password_reset_resend_seconds": 120,
                "login_max_attempts": 8,
                "login_lockout_seconds": 600,
            },
        )
        self.assertRedirects(
            response, reverse("console:settings"), fetch_redirect_response=False
        )
        policy = SecurityPolicy.load()
        self.assertEqual(policy.password_min_length, 14)
        self.assertTrue(policy.password_require_special)
        self.assertEqual(policy.mfa_mode, SecurityPolicy.MFAMode.ALL)
        self.assertEqual(policy.access_token_ttl, 420)
        self.assertEqual(policy.client_secret_grace_period, 120)
        self.assertEqual(policy.email_confirmation_timeout, 43200)
        self.assertEqual(policy.email_confirmation_resend_seconds, 90)
        self.assertEqual(policy.password_reset_timeout, 1800)
        self.assertEqual(policy.password_reset_resend_seconds, 120)
        self.assertEqual(policy.login_max_attempts, 8)
        self.assertEqual(policy.login_lockout_seconds, 600)
        self.assertTrue(
            AuditEvent.objects.filter(
                actor=operator, action="security_policy.updated"
            ).exists()
        )

    def test_settings_is_readable_by_key_managers_but_only_security_managers_can_post(self):
        key_manager = User.objects.create_user("key-manager", password=PASSWORD)
        key_manager.user_permissions.add(permission("manage_keys"))
        self.client.force_login(key_manager)

        self.assertEqual(self.client.get(reverse("console:settings")).status_code, 200)
        denied = self.client.post(reverse("console:settings"), {})
        self.assertEqual(denied.status_code, 403)

    def test_password_policy_is_applied_by_the_user_creation_form(self):
        policy = SecurityPolicy.load()
        policy.password_min_length = 16
        policy.password_require_special = True
        policy.save()

        invalid = UserCreateForm(
            data={
                "username": "policy-user",
                "password1": "NoSpecial123",
                "password2": "NoSpecial123",
                "is_active": "on",
            }
        )
        self.assertFalse(invalid.is_valid())
        password_errors = " ".join(invalid.errors.get("password2", ()))
        self.assertIn("ao menos 16 caracteres", password_errors)
        self.assertIn("caractere especial", password_errors)

        valid_password = "Valid-Password-123!"
        valid = UserCreateForm(
            data={
                "username": "policy-user",
                "password1": valid_password,
                "password2": valid_password,
                "is_active": "on",
            }
        )
        self.assertTrue(valid.is_valid(), valid.errors)
        user = valid.save()
        self.assertTrue(user.check_password(valid_password))

    def test_mutating_routes_reject_get_and_key_rotation_is_audited(self):
        admin = User.objects.create_superuser(
            "route-admin", "route-admin@example.com", PASSWORD
        )
        group = Group.objects.create(name="protected-group")
        self.client.force_login(admin)

        guarded_gets = (
            reverse("console:delete", args=["groups", group.pk]),
            reverse("console:rotate_key"),
            reverse("account-mfa-disable"),
            reverse("account-mfa-recovery"),
        )
        for url in guarded_gets:
            with self.subTest(url=url):
                self.assertEqual(self.client.get(url).status_code, 405)
        self.assertTrue(Group.objects.filter(pk=group.pk).exists())

        first = self.client.post(reverse("console:rotate_key"))
        self.assertRedirects(
            first, reverse("console:keys"), fetch_redirect_response=False
        )
        self.assertEqual(SigningKey.objects.filter(active=True).count(), 1)
        key_page = self.client.get(reverse("console:keys"))
        self.assertTemplateUsed(key_page, "console/keys.html")
        self.assertContains(key_page, "RS256")
        self.assertContains(key_page, 'class="table-card keys-table"')
        self.assertTrue(
            AuditEvent.objects.filter(actor=admin, action="signing_key.rotated").exists()
        )

    def test_anonymous_account_and_console_routes_preserve_the_local_destination(self):
        for url in (reverse("account"), reverse("console:list", args=["users"])):
            with self.subTest(url=url):
                response = self.client.get(url)
                self.assertRedirects(
                    response,
                    f"{reverse('login')}?next={url}",
                    fetch_redirect_response=False,
                )
