from django.utils import timezone
from .models import AuditEvent, AuthorizationCode, MFAChallenge, OIDCSession, RefreshToken, RevokedAccessToken, SecurityPolicy, UserEmailState


def run_cleanup():
    """Remove artefatos OIDC expirados e eventos de auditoria além da retenção configurada."""
    now = timezone.now()
    grace = now - timezone.timedelta(days=7)
    retention = SecurityPolicy.load().audit_log_retention_days
    return {
        "codes": AuthorizationCode.objects.filter(expires_at__lt=grace).delete()[0],
        "refresh_tokens": RefreshToken.objects.filter(expires_at__lt=grace).delete()[0],
        "revoked_jtis": RevokedAccessToken.objects.filter(expires_at__lt=now).delete()[0],
        "sessions": OIDCSession.objects.filter(expires_at__lt=grace).delete()[0],
        "mfa_challenges": MFAChallenge.objects.filter(expires_at__lt=grace).delete()[0],
        "email_confirmations": UserEmailState.objects.filter(
            confirmation_expires_at__lt=now
        ).exclude(confirmation_token_hash="").update(
            confirmation_token_hash="", confirmation_expires_at=None,
            confirmation_sent_at=None, updated_at=now,
        ),
        "audit_events": AuditEvent.objects.filter(
            created_at__lt=now - timezone.timedelta(days=retention)
        ).delete()[0],
    }
