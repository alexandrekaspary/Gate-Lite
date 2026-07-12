import ast
import gettext
import re
from pathlib import Path
from urllib.parse import urlparse

from django.conf import settings
from django.contrib.auth.models import User
from django.core import mail
from django.test import SimpleTestCase, TestCase, override_settings
from django.urls import reverse
from django.utils import timezone, translation
from django.utils.translation.template import templatize

from .email_verification import request_email_confirmation
from .models import SecurityPolicy, UserEmailState, UserPreferences


PASSWORD = "Strong-password-123!"


class CatalogCoverageTests(SimpleTestCase):
    template_roots = ("templates/account", "templates/registration", "templates/emails")

    @staticmethod
    def template_message_ids():
        pattern = re.compile(
            r"(?:n?gettext|pgettext|_)\(u?('(?:\\.|[^'\\])*'|\"(?:\\.|[^\"\\])*\")"
        )
        message_ids = set()
        for root in CatalogCoverageTests.template_roots:
            for path in Path(settings.BASE_DIR, root).rglob("*"):
                if path.is_file():
                    source = templatize(path.read_text(encoding="utf-8"))
                    message_ids.update(
                        ast.literal_eval(match.group(1)) for match in pattern.finditer(source)
                    )
        return message_ids

    def test_compiled_catalogs_cover_every_account_and_email_template_message(self):
        expected = self.template_message_ids()
        self.assertTrue(expected)
        for language in ("en", "es"):
            path = Path(settings.BASE_DIR, "locale", language, "LC_MESSAGES", "django.mo")
            with path.open("rb") as catalog_file:
                catalog = gettext.GNUTranslations(catalog_file)._catalog
            missing = sorted(
                message_id
                for message_id in expected
                if message_id not in catalog and (message_id, 0) not in catalog
            )
            self.assertEqual(missing, [], f"{language} sem traduções: {missing}")

    def test_account_and_email_templates_do_not_leave_portuguese_copy_unmarked(self):
        markers = re.compile(
            r"\b(senha|conta|código|confirmação|recuperação|entrar|voltar|segurança|"
            r"usuário|endereço|obrigatório|alteração|aplicativo|mensagem)\b",
            re.IGNORECASE,
        )
        leftovers = []
        for root in self.template_roots:
            for path in Path(settings.BASE_DIR, root).rglob("*"):
                if not path.is_file():
                    continue
                source = path.read_text(encoding="utf-8")
                source = re.sub(
                    r"{%\s*blocktrans\b.*?%}.*?{%\s*endblocktrans\s*%}",
                    "",
                    source,
                    flags=re.DOTALL,
                )
                source = re.sub(r"{%\s*trans\b.*?%}", "", source, flags=re.DOTALL)
                source = re.sub(r"{#.*?#}|{%.*?%}|{{.*?}}", "", source, flags=re.DOTALL)
                if markers.search(source):
                    leftovers.append(str(path.relative_to(settings.BASE_DIR)))
        self.assertEqual(leftovers, [], f"Textos sem marcação i18n: {leftovers}")

    def test_javascript_catalogs_cover_account_generated_messages(self):
        source = "\n".join(
            Path(settings.BASE_DIR, "static", "js", name).read_text(encoding="utf-8")
            for name in ("app.js", "password-policy.js")
        )
        expected = set(re.findall(r"\bt\('([^']+)'\)", source))
        self.assertTrue(expected)
        for language in ("en", "es"):
            path = Path(settings.BASE_DIR, "locale", language, "LC_MESSAGES", "djangojs.mo")
            with path.open("rb") as catalog_file:
                catalog = gettext.GNUTranslations(catalog_file)._catalog
            self.assertEqual(sorted(expected - set(catalog)), [])


class AccountLanguageTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            "localized-user", email="localized@example.com", password=PASSWORD
        )
        self.client.force_login(self.user)

    def set_language(self, language):
        preferences = UserPreferences.for_user(self.user)
        preferences.language = language
        preferences.save(update_fields=["language", "updated_at"])

    def mark_email_verified(self):
        state, _ = UserEmailState.objects.get_or_create(user=self.user)
        state.email_verified = True
        state.verified_email = self.user.email
        state.verified_at = timezone.now()
        state.confirmation_sent_at = None
        state.confirmation_token_hash = ""
        state.confirmation_expires_at = None
        state.save()

    def test_english_account_password_and_mfa_pages_are_fully_localized(self):
        self.set_language("en")
        cases = (
            (reverse("account"), "Account protection"),
            (reverse("account-profile-edit"), "Edit personal details"),
            (reverse("change-own-password"), "Change my password"),
            (reverse("account-mfa"), "Two-factor authentication disabled"),
            (reverse("account-mfa-setup"), "Scan the QR code"),
        )
        for url, text in cases:
            with self.subTest(url=url):
                response = self.client.get(url)
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.headers["Content-Language"], "en")
                self.assertContains(response, '<html lang="en">', html=False)
                self.assertContains(response, text)

    def test_spanish_profile_and_password_pages_are_localized(self):
        self.set_language("es")
        for url, text in (
            (reverse("account-profile-edit"), "Editar datos personales"),
            (reverse("change-own-password"), "Cambiar mi contraseña"),
            (reverse("account-mfa"), "Autenticación en dos pasos desactivada"),
        ):
            with self.subTest(url=url):
                response = self.client.get(url)
                self.assertEqual(response.headers["Content-Language"], "es")
                self.assertContains(response, text)

    def test_language_change_uses_the_new_language_for_the_redirect_notice(self):
        self.mark_email_verified()
        self.set_language("pt-BR")
        response = self.client.post(
            reverse("account-profile-edit"),
            {
                "first_name": "Localized",
                "last_name": "User",
                "email": self.user.email,
                "language": "en",
                "timezone": "America/Sao_Paulo",
            },
            follow=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Profile details updated.")
        self.assertEqual(response.headers["Content-Language"], "en")


@override_settings(
    EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend",
    EMAIL_ENABLED=True,
)
class LocalizedEmailTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            "mail-user",
            first_name="Mail",
            email="mail@example.com",
            password=PASSWORD,
        )
        state, _ = UserEmailState.objects.get_or_create(user=self.user)
        state.email_verified = True
        state.verified_email = self.user.email
        state.verified_at = timezone.now()
        state.confirmation_sent_at = None
        state.confirmation_token_hash = ""
        state.confirmation_expires_at = None
        state.save()
        mail.outbox.clear()

    def set_language(self, language):
        preferences = UserPreferences.for_user(self.user)
        preferences.language = language
        preferences.save(update_fields=["language", "updated_at"])

    def test_confirmation_email_and_preview_use_recipient_language(self):
        self.set_language("en")
        with translation.override("pt-br"):
            request_email_confirmation(self.user, self.user.email)
        message = mail.outbox[0]
        self.assertIn("Confirm the email", message.subject)
        self.assertIn("You requested to use", message.body)
        self.assertIn('<html lang="en">', message.alternatives[0].content)

        match = re.search(r"https?://[^\s]+", message.body)
        self.assertIsNotNone(match)
        parsed = urlparse(match.group(0).rstrip(".,)"))
        response = self.client.get(f"{parsed.path}?{parsed.query}")
        self.assertEqual(response.headers["Content-Language"], "en")
        self.assertContains(response, "Confirm your address")

    def test_password_reset_email_uses_recipient_language(self):
        self.set_language("es")
        policy = SecurityPolicy.load()
        policy.default_language = "pt-BR"
        policy.save(update_fields=["default_language"])
        response = self.client.post(reverse("password-reset"), {"email": self.user.email})
        self.assertEqual(response.status_code, 302)
        message = mail.outbox[0]
        self.assertIn("Restablecimiento de contraseña", message.subject)
        self.assertIn("Recibimos una solicitud", message.body)
        self.assertIn('<html lang="es">', message.alternatives[0].content)

    def test_javascript_catalog_uses_the_active_anonymous_language(self):
        policy = SecurityPolicy.load()
        policy.default_language = "en"
        policy.save(update_fields=["default_language"])
        response = self.client.get(reverse("javascript-catalog"))
        self.assertEqual(response.headers["Content-Language"], "en")
        self.assertContains(response, "Show password")
