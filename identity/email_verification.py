import hashlib
import secrets
from dataclasses import dataclass
from urllib.parse import urlencode

from django.conf import settings
from django.contrib.auth.models import User
from django.core.mail import EmailMultiAlternatives
from django.core.validators import validate_email
from django.db import IntegrityError, transaction
from django.template.loader import render_to_string
from django.urls import reverse
from django.utils import timezone

from .models import AuditEvent, SecurityPolicy, UserEmailState


class EmailConfirmationError(Exception):
    pass


class EmailAlreadyInUse(EmailConfirmationError):
    pass


class EmailConfirmationThrottled(EmailConfirmationError):
    def __init__(self, retry_after):
        self.retry_after = max(1, int(retry_after))
        super().__init__(f"Tente novamente em {self.retry_after} segundos.")


class InvalidEmailConfirmation(EmailConfirmationError):
    pass


@dataclass(frozen=True)
class EmailConfirmationRequest:
    sent: bool
    pending_email: str
    retry_after: int = 0


def normalize_email(value):
    """Use one canonical representation for uniqueness and token binding."""
    value = (value or "").strip()
    validate_email(value)
    return value.casefold()


def email_available_for_user(email, user):
    normalized = normalize_email(email)
    if User.objects.exclude(pk=user.pk).filter(email__iexact=normalized).exists():
        return False
    return not UserEmailState.objects.exclude(user=user).filter(
        verified_email=normalized,
        email_verified=True,
    ).exists()


def get_email_state(user):
    state, _ = UserEmailState.objects.get_or_create(user=user)
    return state


def _confirmation_url(raw_token, request=None):
    path = reverse("account-email-confirm")
    query = urlencode({"token": raw_token})
    if request is not None:
        return request.build_absolute_uri(f"{path}?{query}")
    return f"{settings.OIDC_ISSUER}{path}?{query}"


def _send_confirmation_message(user, target_email, raw_token, request=None):
    timeout = SecurityPolicy.load().email_confirmation_timeout
    context = {
        "user": user,
        "target_email": target_email,
        "confirmation_url": _confirmation_url(raw_token, request),
        "expires_hours": max(1, (timeout + 3599) // 3600),
        "site_name": "GateLite",
    }
    subject = "".join(render_to_string(
        "emails/email_confirmation_subject.txt", context
    ).splitlines()).strip()
    text_body = render_to_string("emails/email_confirmation.txt", context)
    html_body = render_to_string("emails/email_confirmation.html", context)
    message = EmailMultiAlternatives(
        subject=subject,
        body=text_body,
        from_email=settings.DEFAULT_FROM_EMAIL,
        to=[target_email],
    )
    message.attach_alternative(html_body, "text/html")
    message.send(fail_silently=False)


def request_email_confirmation(user, email, request=None, actor=None, ip_address=None):
    """Create one expiring request; the raw token exists only in the email."""
    target = normalize_email(email)
    if not email_available_for_user(target, user):
        raise EmailAlreadyInUse("Este endereço de e-mail já está em uso.")

    now = timezone.now()
    policy = SecurityPolicy.load()
    throttle = policy.email_confirmation_resend_seconds
    with transaction.atomic():
        state, _ = UserEmailState.objects.select_for_update().get_or_create(user=user)
        if state.confirmation_sent_at and (now - state.confirmation_sent_at).total_seconds() < throttle:
            remaining = throttle - (now - state.confirmation_sent_at).total_seconds()
            raise EmailConfirmationThrottled(remaining)

        raw_token = secrets.token_urlsafe(48)
        state.pending_email = target
        state.confirmation_token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
        state.confirmation_expires_at = now + timezone.timedelta(
            seconds=policy.email_confirmation_timeout
        )
        state.confirmation_sent_at = now
        state.save(update_fields=[
            "pending_email", "confirmation_token_hash",
            "confirmation_expires_at", "confirmation_sent_at", "updated_at",
        ])

    try:
        _send_confirmation_message(user, target, raw_token, request)
    except Exception:
        # Do not throttle a resend for a message that never left the server.
        UserEmailState.objects.filter(
            user=user,confirmation_token_hash=hashlib.sha256(raw_token.encode()).hexdigest(),
        ).update(
            confirmation_token_hash="",confirmation_expires_at=None,
            confirmation_sent_at=None,
        )
        raise
    AuditEvent.objects.create(
        actor=actor,
        action="email.confirmation_requested",
        target_type="User",
        target_id=str(user.pk),
        metadata={"changes_address": target != (user.email or "").strip().casefold()},
        ip_address=ip_address,
    )
    return EmailConfirmationRequest(sent=True, pending_email=target)


def inspect_confirmation_token(raw_token):
    if not raw_token:
        return None
    digest = hashlib.sha256(raw_token.encode()).hexdigest()
    state = UserEmailState.objects.filter(
        confirmation_token_hash=digest,
        confirmation_expires_at__gt=timezone.now(),
    ).first()
    return state if state and state.pending_email else None


def consume_confirmation_token(raw_token, actor=None, ip_address=None):
    if not raw_token:
        raise InvalidEmailConfirmation("Link de confirmação inválido ou expirado.")
    digest = hashlib.sha256(raw_token.encode()).hexdigest()
    now = timezone.now()
    try:
        with transaction.atomic():
            state = UserEmailState.objects.select_for_update().select_related("user").filter(
                confirmation_token_hash=digest,
            ).first()
            if (
                not state
                or not state.pending_email
                or not state.confirmation_expires_at
                or state.confirmation_expires_at <= now
            ):
                raise InvalidEmailConfirmation("Link de confirmação inválido ou expirado.")

            user = state.user
            target = normalize_email(state.pending_email)
            if not email_available_for_user(target, user):
                raise EmailAlreadyInUse("Este endereço de e-mail já está em uso.")

            previous = (user.email or "").strip().casefold()
            # QuerySet.update intentionally avoids a signal observing a half-updated
            # state inside this transaction.
            User.objects.filter(pk=user.pk).update(email=target)
            user.email = target
            state.email_verified = True
            state.verified_email = target
            state.verified_at = now
            state.pending_email = ""
            state.confirmation_token_hash = ""
            state.confirmation_expires_at = None
            state.confirmation_sent_at = None
            state.save(update_fields=[
                "email_verified", "verified_email", "verified_at", "pending_email",
                "confirmation_token_hash", "confirmation_expires_at",
                "confirmation_sent_at", "updated_at",
            ])
    except IntegrityError as exc:
        raise EmailAlreadyInUse("Este endereço de e-mail já está em uso.") from exc

    from .mfa import invalidate_web_sessions, rotate_security_version
    rotate_security_version(user)
    invalidate_web_sessions(user)
    AuditEvent.objects.create(
        actor=actor if actor and actor.is_authenticated and actor.pk==user.pk else None,
        action="email.confirmed",
        target_type="User",
        target_id=str(user.pk),
        metadata={"address_changed": previous != target},
        ip_address=ip_address,
    )
    return user


def mask_email(email):
    try:
        local, domain = email.rsplit("@", 1)
    except ValueError:
        return "••••••"
    visible = local[:1]
    return f"{visible}{'•' * max(3, min(8, len(local) - 1))}@{domain}"
