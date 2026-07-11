from unittest.mock import patch

from django.core.mail import EmailMessage
from django.test import TestCase, override_settings

from .email_backend import DATABASE_EMAIL_BACKEND, DatabaseEmailBackend
from .forms import EmailConfigurationForm
from .models import EmailConfiguration


class EmailConfigurationTests(TestCase):
    def configuration_data(self, **overrides):
        return {
            "enabled": "on",
            "host": "smtp.example.com",
            "port": "587",
            "username": "mailer",
            "password": "smtp-secret",
            "from_email": "GateLite <no-reply@example.com>",
            "use_tls": "on",
            **overrides,
        }

    def test_form_encrypts_the_smtp_password_and_never_exposes_it(self):
        configuration = EmailConfiguration.load()
        form = EmailConfigurationForm(self.configuration_data(), instance=configuration)
        self.assertTrue(form.is_valid(), form.errors)
        saved = form.save()
        saved.refresh_from_db()

        self.assertTrue(saved.has_password)
        self.assertNotIn(b"smtp-secret", bytes(saved.encrypted_password))
        self.assertEqual(saved.get_password(), "smtp-secret")

        unchanged = EmailConfigurationForm(
            self.configuration_data(password="", host="smtp.changed.example"),
            instance=saved,
        )
        self.assertTrue(unchanged.is_valid(), unchanged.errors)
        unchanged.save()
        saved.refresh_from_db()
        self.assertEqual(saved.host, "smtp.changed.example")
        self.assertEqual(saved.get_password(), "smtp-secret")

    @override_settings(EMAIL_BACKEND=DATABASE_EMAIL_BACKEND, EMAIL_ENABLED=True)
    def test_database_backend_uses_decrypted_password_only_for_smtp_connection(self):
        configuration = EmailConfiguration.load()
        configuration.enabled = True
        configuration.host = "smtp.example.com"
        configuration.port = 587
        configuration.username = "mailer"
        configuration.from_email = "GateLite <no-reply@example.com>"
        configuration.set_password("smtp-secret")
        configuration.save()

        with patch("identity.email_backend.SMTPEmailBackend") as backend_class:
            backend_class.return_value.send_messages.return_value = 1
            sent = DatabaseEmailBackend().send_messages([
                EmailMessage("Subject", "Body", to=["person@example.com"]),
            ])

        self.assertEqual(sent, 1)
        self.assertEqual(backend_class.call_args.kwargs["password"], "smtp-secret")
        self.assertEqual(backend_class.call_args.kwargs["host"], "smtp.example.com")

    def test_tls_and_ssl_cannot_be_enabled_together(self):
        form = EmailConfigurationForm(
            self.configuration_data(use_ssl="on"), instance=EmailConfiguration.load()
        )
        self.assertFalse(form.is_valid())
        self.assertIn("use_ssl", form.errors)
