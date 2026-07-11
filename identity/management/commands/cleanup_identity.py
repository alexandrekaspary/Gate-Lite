from django.core.management.base import BaseCommand
from django.utils import timezone
from identity.models import AuthorizationCode, MFAChallenge, OIDCSession, RefreshToken, RevokedAccessToken, UserEmailState

class Command(BaseCommand):
    help="Remove artefatos OIDC expirados. Execute periodicamente no scheduler."
    def handle(self,*args,**options):
        now=timezone.now(); grace=now-timezone.timedelta(days=7)
        counts={
            "codes":AuthorizationCode.objects.filter(expires_at__lt=grace).delete()[0],
            "refresh_tokens":RefreshToken.objects.filter(expires_at__lt=grace).delete()[0],
            "revoked_jtis":RevokedAccessToken.objects.filter(expires_at__lt=now).delete()[0],
            "sessions":OIDCSession.objects.filter(expires_at__lt=grace).delete()[0],
            "mfa_challenges":MFAChallenge.objects.filter(expires_at__lt=grace).delete()[0],
            "email_confirmations":UserEmailState.objects.filter(
                confirmation_expires_at__lt=now
            ).exclude(confirmation_token_hash="").update(
                confirmation_token_hash="",confirmation_expires_at=None,
                confirmation_sent_at=None,updated_at=now,
            ),
        }
        self.stdout.write(self.style.SUCCESS("Limpeza concluída: "+", ".join(f"{k}={v}" for k,v in counts.items())))
