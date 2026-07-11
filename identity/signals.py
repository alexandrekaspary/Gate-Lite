import logging

from django.contrib.auth.models import Permission, User
from django.contrib.auth.signals import user_logged_in, user_login_failed
from django.db.models.signals import post_migrate, post_save, pre_save
from django.dispatch import receiver
from django.utils import timezone

BASIC_PERMISSION_CODES = ("view_own_profile", "change_own_password")
logger = logging.getLogger(__name__)


@receiver(pre_save, sender=User)
def remember_previous_email(sender,instance,**kwargs):
    if instance.pk:
        instance._gatelite_previous_email=sender.objects.filter(pk=instance.pk).values_list("email",flat=True).first() or ""
    else:
        instance._gatelite_previous_email=""

@receiver(post_save, sender=User)
def grant_basic_self_service_permissions(sender, instance, **kwargs):
    permissions = Permission.objects.filter(
        content_type__app_label="identity", codename__in=BASIC_PERMISSION_CODES
    )
    if permissions.count() == len(BASIC_PERMISSION_CODES):
        instance.user_permissions.add(*permissions)
    from .models import UserEmailState, UserSecurityState
    UserSecurityState.objects.get_or_create(user=instance)
    email_state,_=UserEmailState.objects.get_or_create(user=instance)
    current_email=(instance.email or "").strip().casefold()
    previous_email=getattr(instance,"_gatelite_previous_email","").strip().casefold()
    email_changed=not kwargs.get("created") and previous_email!=current_email
    verification_invalid=email_state.email_verified and email_state.verified_email!=current_email
    if verification_invalid:
        email_state.email_verified=False
        email_state.verified_email=None
        email_state.verified_at=None
    if email_changed or verification_invalid:
        email_state.pending_email=""
        email_state.confirmation_token_hash=""
        email_state.confirmation_expires_at=None
        email_state.confirmation_sent_at=None
        email_state.save(update_fields=[
            "email_verified","verified_email","verified_at","pending_email",
            "confirmation_token_hash","confirmation_expires_at",
            "confirmation_sent_at","updated_at",
        ])
    if current_email and (kwargs.get("created") or email_changed):
        from .email_verification import EmailConfirmationError, request_email_confirmation
        try:
            request_email_confirmation(instance,current_email)
        except EmailConfirmationError:
            # An existing pending request or a duplicate address must not make
            # unrelated user updates fail.
            pass
        except Exception:
            # Account creation must survive a transient SMTP failure; the user
            # can request a new message from the account page.
            logger.exception("Não foi possível enviar a confirmação de e-mail do usuário %s",instance.pk)
    if email_changed:
        from .mfa import invalidate_web_sessions, rotate_security_version
        from .models import AuditEvent
        rotate_security_version(instance)
        invalidate_web_sessions(instance)
        AuditEvent.objects.create(
            action="email.changed_directly",target_type="User",target_id=str(instance.pk),
            metadata={"email_removed":not bool(current_email)},
        )
    if not instance.is_active:
        from .models import OIDCSession, RefreshToken
        OIDCSession.objects.filter(user=instance,revoked_at__isnull=True).update(revoked_at=timezone.now())
        RefreshToken.objects.filter(user=instance,revoked_at__isnull=True).update(revoked_at=timezone.now())

@receiver(post_migrate)
def backfill_basic_self_service_permissions(sender, **kwargs):
    if sender.name != "identity": return
    permissions = Permission.objects.filter(
        content_type__app_label="identity", codename__in=BASIC_PERMISSION_CODES
    )
    if permissions.count() == len(BASIC_PERMISSION_CODES):
        for user in User.objects.iterator(): user.user_permissions.add(*permissions)

@receiver(user_logged_in)
def audit_login(sender,request,user,**kwargs):
    from .models import AuditEvent
    AuditEvent.objects.create(actor=user,action="authentication.login",target_type="User",target_id=str(user.pk),ip_address=request.META.get("REMOTE_ADDR"))

@receiver(user_login_failed)
def audit_login_failure(sender,credentials,request,**kwargs):
    from .models import AuditEvent
    AuditEvent.objects.create(action="authentication.failed",target_type="User",metadata={"username":str(credentials.get("username", ""))[:150]},ip_address=request.META.get("REMOTE_ADDR") if request else None)
