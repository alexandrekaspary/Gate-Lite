from django.conf import settings
from django.core.mail.backends.smtp import EmailBackend as SMTPEmailBackend


DATABASE_EMAIL_BACKEND = "identity.email_backend.DatabaseEmailBackend"


def email_delivery_enabled():
    """Indica se há um backend de teste/alternativo ou SMTP configurado no banco."""
    if not settings.EMAIL_ENABLED:
        return False
    if settings.EMAIL_BACKEND != DATABASE_EMAIL_BACKEND:
        return True
    from .models import EmailConfiguration
    return EmailConfiguration.load().is_configured


class DatabaseEmailBackend:
    """Backend SMTP configurado no banco, com senha decifrada apenas ao enviar."""

    def __init__(self, fail_silently=False, **kwargs):
        self.fail_silently = fail_silently

    def send_messages(self, email_messages):
        if not email_messages or not email_delivery_enabled():
            return 0

        from .models import EmailConfiguration
        config = EmailConfiguration.load()
        backend = SMTPEmailBackend(
            host=config.host,
            port=config.port,
            username=config.username,
            password=config.get_password(),
            use_tls=config.use_tls,
            use_ssl=config.use_ssl,
            timeout=settings.EMAIL_TIMEOUT,
            fail_silently=self.fail_silently,
        )
        return backend.send_messages(email_messages)
