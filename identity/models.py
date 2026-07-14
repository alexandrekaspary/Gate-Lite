import hashlib
import secrets
import uuid
import zoneinfo
from urllib.parse import urlsplit
from django.conf import settings
from django.contrib.auth.hashers import check_password, make_password
from django.contrib.auth.models import User
from django.core.exceptions import ValidationError
from django.core.validators import MaxValueValidator, MinValueValidator, RegexValidator
from django.db import models
from django.utils import timezone

def generate_client_id():
    return secrets.token_urlsafe(24)

LANGUAGE_CHOICES = [("pt-BR", "Português (Brasil)"), ("en", "English"), ("es", "Español")]

def timezone_choices():
    return [(name, name) for name in sorted(zoneinfo.available_timezones())]


class OIDCClient(models.Model):
    class ClientType(models.TextChoices):
        PUBLIC = "public", "Público (SPA/mobile)"
        CONFIDENTIAL = "confidential", "Confidencial (backend)"
    class AuthMethod(models.TextChoices):
        NONE = "none", "Nenhum (client público)"
        BASIC = "client_secret_basic", "Client Secret Basic"
        POST = "client_secret_post", "Client Secret Post"
        LEGACY = "client_secret_basic_or_post", "Basic ou Post (compatibilidade)"
    class AccessPolicy(models.TextChoices):
        OPEN = "open", "Qualquer usuário ativo"
        RESTRICTED = "restricted", "Somente usuários/grupos com atribuição"
    class ApplicationType(models.TextChoices):
        SPA = "spa", "Single-page application"
        NATIVE = "native", "Aplicativo nativo"
        WEB = "web", "Aplicação web backend"
        SERVICE = "service", "Service account"
        RESOURCE = "resource", "Resource server / API"

    name = models.CharField(max_length=120)
    client_id = models.CharField(max_length=100, unique=True, default=generate_client_id,validators=[RegexValidator(r"^[A-Za-z0-9._~-]+$","Use apenas letras, números, ponto, hífen, underscore ou til.")])
    application_type = models.CharField(max_length=16, choices=ApplicationType.choices, default=ApplicationType.WEB)
    client_type = models.CharField(max_length=16, choices=ClientType.choices, default=ClientType.CONFIDENTIAL)
    token_endpoint_auth_method = models.CharField(max_length=32, choices=AuthMethod.choices, default=AuthMethod.BASIC)
    require_pkce = models.BooleanField(default=True)
    require_mfa = models.BooleanField(default=False, help_text="Exige uma sessão autenticada com segundo fator")
    authorization_code_enabled = models.BooleanField(default=True)
    refresh_token_enabled = models.BooleanField(default=True)
    client_credentials_enabled = models.BooleanField(default=False)
    access_policy = models.CharField(max_length=16, choices=AccessPolicy.choices, default=AccessPolicy.OPEN)
    is_active = models.BooleanField(default=True)
    allowed_groups = models.ManyToManyField(
        "auth.Group", blank=True, related_name="allowed_oidc_clients",
        help_text="Exceções autorizadas quando a política do client é restrita.",
    )
    allowed_users = models.ManyToManyField("auth.User", blank=True, related_name="allowed_oidc_clients")
    allowed_audiences = models.ManyToManyField("self", symmetrical=False, blank=True, related_name="authorized_callers", help_text="Resource servers que este client pode solicitar no claim aud.")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta: ordering = ["name"]
    def __str__(self): return self.name
    def uri_list(self, field="redirect_uris"):
        kind=ClientURI.Kind.REDIRECT if field=="redirect_uris" else ClientURI.Kind.POST_LOGOUT
        return list(self.uris.filter(kind=kind).values_list("uri",flat=True))
    @property
    def is_confidential(self): return self.client_type == self.ClientType.CONFIDENTIAL
    def set_secret(self, raw):
        grace=SecurityPolicy.load().client_secret_grace_period
        self.secrets.filter(revoked_at__isnull=True,expires_at__isnull=True).update(expires_at=timezone.now()+timezone.timedelta(seconds=grace))
        return ClientSecret.objects.create(client=self,prefix=raw[:8],secret_hash=make_password(raw))
    def check_secret(self, raw):
        if not raw: return False
        for credential in self.secrets.filter(revoked_at__isnull=True).filter(models.Q(expires_at__isnull=True)|models.Q(expires_at__gt=timezone.now())):
            valid=secrets.compare_digest(credential.secret_hash,hashlib.sha256(raw.encode()).hexdigest()) if len(credential.secret_hash)==64 and "$" not in credential.secret_hash else check_password(raw,credential.secret_hash)
            if valid:
                credential.last_used_at=timezone.now(); credential.save(update_fields=["last_used_at"]); return True
        return False
    def origin_list(self): return list(self.web_origins.values_list("origin",flat=True))
    def scope_names(self): return [assignment.scope.name for assignment in self.scope_assignments.all()]
    def clean(self):
        if self.client_type == self.ClientType.PUBLIC:
            self.token_endpoint_auth_method = self.AuthMethod.NONE
            self.require_pkce = True
            self.client_credentials_enabled = False
        elif self.token_endpoint_auth_method == self.AuthMethod.NONE:
            raise ValidationError("Clients confidenciais precisam de um método de autenticação.")

    def user_has_access(self, user):
        if not user.is_authenticated or not user.is_active:
            return False
        if user.is_superuser or self.access_policy == self.AccessPolicy.OPEN:
            return True
        now=timezone.now()
        has_assignment=self.roles.filter(
            models.Q(user_assignments__user=user,user_assignments__expires_at__isnull=True)
            | models.Q(user_assignments__user=user,user_assignments__expires_at__gt=now)
            | models.Q(group_assignments__group__user=user,group_assignments__expires_at__isnull=True)
            | models.Q(group_assignments__group__user=user,group_assignments__expires_at__gt=now)
        ).exists()
        return has_assignment or (
            self.allowed_users.filter(pk=user.pk).exists()
            or self.allowed_groups.filter(user=user).exists()
        )

    def effective_role_names(self, user):
        now=timezone.now()
        base=self.roles.filter(
            models.Q(is_default=True)
            | models.Q(user_assignments__user=user,user_assignments__expires_at__isnull=True)
            | models.Q(user_assignments__user=user,user_assignments__expires_at__gt=now)
            | models.Q(group_assignments__group__user=user,group_assignments__expires_at__isnull=True)
            | models.Q(group_assignments__group__user=user,group_assignments__expires_at__gt=now)
        ).distinct()
        return self.expand_role_names(base)

    def expand_role_names(self,roles):
        role_ids=set(roles.values_list("pk",flat=True)); frontier=set(role_ids)
        while frontier:
            children=set(ClientRole.objects.filter(client=self,pk__in=frontier).values_list("composites__pk",flat=True)); children.discard(None); frontier=children-role_ids; role_ids.update(frontier)
        return list(self.roles.filter(pk__in=role_ids).values_list("name",flat=True).order_by("name"))

    def relevant_group_names(self,user):
        now=timezone.now()
        return list(user.groups.filter(models.Q(allowed_oidc_clients=self) | models.Q(client_role_assignments__role__client=self,client_role_assignments__expires_at__isnull=True) | models.Q(client_role_assignments__role__client=self,client_role_assignments__expires_at__gt=now)).values_list("name",flat=True).distinct().order_by("name"))


class ClientURI(models.Model):
    class Kind(models.TextChoices):
        REDIRECT="redirect","Redirect URI"
        POST_LOGOUT="post_logout","Post logout redirect URI"
    client=models.ForeignKey(OIDCClient,on_delete=models.CASCADE,related_name="uris")
    kind=models.CharField(max_length=16,choices=Kind.choices)
    uri=models.TextField()
    class Meta: constraints=[models.UniqueConstraint(fields=["client","kind","uri"],name="unique_client_uri")]
    def clean(self):
        parsed=urlsplit(self.uri)
        if not parsed.scheme or parsed.fragment or parsed.username or parsed.password: raise ValidationError("URI absoluta inválida.")
        if parsed.scheme in ("http","https"):
            if not parsed.hostname or (parsed.scheme=="http" and parsed.hostname not in ("localhost","127.0.0.1","::1")): raise ValidationError("HTTP somente em loopback exato.")
        elif self.client.application_type != OIDCClient.ApplicationType.NATIVE: raise ValidationError("Scheme customizado somente para aplicativo nativo.")

class ClientWebOrigin(models.Model):
    client=models.ForeignKey(OIDCClient,on_delete=models.CASCADE,related_name="web_origins")
    origin=models.CharField(max_length=255)
    class Meta: constraints=[models.UniqueConstraint(fields=["client","origin"],name="unique_client_web_origin")]
    def clean(self):
        parsed=urlsplit(self.origin)
        if parsed.scheme not in ("http","https") or not parsed.hostname or parsed.path not in ("","/") or parsed.query or parsed.fragment or parsed.username: raise ValidationError("Origem CORS inválida.")
        if parsed.scheme=="http" and parsed.hostname not in ("localhost","127.0.0.1","::1"): raise ValidationError("HTTP somente em loopback exato.")

class OIDCScope(models.Model):
    name=models.CharField(max_length=80,unique=True,validators=[RegexValidator(r"^[A-Za-z0-9_.:-]+$","Nome de scope inválido.")])
    description=models.CharField(max_length=255,blank=True)
    is_standard=models.BooleanField(default=False)
    def __str__(self): return self.name

class ClientScopeAssignment(models.Model):
    client=models.ForeignKey(OIDCClient,on_delete=models.CASCADE,related_name="scope_assignments")
    scope=models.ForeignKey(OIDCScope,on_delete=models.CASCADE,related_name="client_assignments")
    is_default=models.BooleanField(default=False)
    class Meta: constraints=[models.UniqueConstraint(fields=["client","scope"],name="unique_client_scope")]


class ClientRole(models.Model):
    client = models.ForeignKey(OIDCClient, on_delete=models.CASCADE, related_name="roles")
    name = models.SlugField(max_length=80, help_text="Nome enviado no claim roles do JWT.")
    description = models.CharField(max_length=255, blank=True)
    is_default = models.BooleanField(default=False, help_text="Concedida por padrão a usuários com acesso ao client.")
    composites = models.ManyToManyField("self", symmetrical=False, blank=True, related_name="included_by")
    groups = models.ManyToManyField("auth.Group", through="GroupClientRoleAssignment", blank=True, related_name="oidc_client_roles")
    users = models.ManyToManyField("auth.User", through="UserClientRoleAssignment", through_fields=("role","user"), blank=True, related_name="direct_oidc_client_roles")
    service_clients = models.ManyToManyField(OIDCClient, through="ServiceAccountRoleAssignment", blank=True, related_name="service_account_roles")

    class Meta:
        ordering = ["client__name", "name"]
        constraints = [models.UniqueConstraint(fields=["client", "name"], name="unique_role_per_client")]

    def __str__(self): return f"{self.client.name} · {self.name}"


class RoleAssignmentBase(models.Model):
    assigned_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(null=True, blank=True)
    assigned_by = models.ForeignKey("auth.User", null=True, blank=True, on_delete=models.SET_NULL, related_name="+")
    class Meta: abstract = True

class UserClientRoleAssignment(RoleAssignmentBase):
    role = models.ForeignKey(ClientRole, on_delete=models.CASCADE, related_name="user_assignments")
    user = models.ForeignKey("auth.User", on_delete=models.CASCADE, related_name="client_role_assignments")
    class Meta:
        constraints=[models.UniqueConstraint(fields=["role","user"],name="unique_user_client_role")]

class GroupClientRoleAssignment(RoleAssignmentBase):
    role = models.ForeignKey(ClientRole, on_delete=models.CASCADE, related_name="group_assignments")
    group = models.ForeignKey("auth.Group", on_delete=models.CASCADE, related_name="client_role_assignments")
    class Meta:
        constraints=[models.UniqueConstraint(fields=["role","group"],name="unique_group_client_role")]

class ServiceAccountRoleAssignment(RoleAssignmentBase):
    role = models.ForeignKey(ClientRole, on_delete=models.CASCADE, related_name="service_assignments")
    service_client = models.ForeignKey(OIDCClient, on_delete=models.CASCADE, related_name="role_assignments")
    class Meta:
        constraints=[models.UniqueConstraint(fields=["role","service_client"],name="unique_service_client_role")]


class AccountCapability(models.Model):
    """Âncora das permissões básicas de autosserviço; não armazena dados sensíveis."""
    label = models.CharField(max_length=1, blank=True)

    class Meta:
        default_permissions = ()
        permissions = [
            ("view_own_profile", "Pode visualizar o próprio perfil"),
            ("change_own_password", "Pode alterar a própria senha"),
            ("view_identity_console", "Pode acessar o console de identidade"),
            ("manage_users", "Pode gerenciar usuários"),
            ("manage_groups", "Pode gerenciar grupos"),
            ("manage_clients", "Pode gerenciar clients e roles"),
            ("manage_security", "Pode gerenciar políticas de segurança"),
            ("manage_keys", "Pode gerenciar chaves de assinatura"),
            ("manage_permissions", "Pode gerenciar permissões administrativas"),
        ]


class SecurityPolicy(models.Model):
    class MFAMode(models.TextChoices):
        OPTIONAL="optional","Opcional"
        ADMINS="admins","Obrigatório para administradores"
        ALL="all","Obrigatório para todos"
    password_min_length = models.PositiveSmallIntegerField(default=10,validators=[MinValueValidator(8),MaxValueValidator(128)])
    password_require_uppercase = models.BooleanField(default=True)
    password_require_lowercase = models.BooleanField(default=True)
    password_require_number = models.BooleanField(default=True)
    password_require_special = models.BooleanField(default=False)
    access_token_ttl = models.PositiveIntegerField(default=300, help_text="Segundos",validators=[MinValueValidator(30),MaxValueValidator(86400)])
    id_token_ttl = models.PositiveIntegerField(default=300, help_text="Segundos",validators=[MinValueValidator(30),MaxValueValidator(86400)])
    refresh_token_ttl = models.PositiveIntegerField(default=2592000, help_text="Segundos",validators=[MinValueValidator(300),MaxValueValidator(31536000)])
    sso_session_ttl = models.PositiveIntegerField(default=28800, help_text="Segundos",validators=[MinValueValidator(300),MaxValueValidator(2592000)])
    client_secret_grace_period = models.PositiveIntegerField(default=300, help_text="Segundos de sobreposição durante rotação",validators=[MaxValueValidator(86400)])
    mfa_mode = models.CharField(max_length=16,choices=MFAMode.choices,default=MFAMode.OPTIONAL)
    email_confirmation_timeout = models.PositiveIntegerField(default=86400, help_text="Segundos",validators=[MinValueValidator(300),MaxValueValidator(604800)])
    email_confirmation_resend_seconds = models.PositiveIntegerField(default=60, help_text="Segundos",validators=[MinValueValidator(10),MaxValueValidator(3600)])
    password_reset_timeout = models.PositiveIntegerField(default=3600, help_text="Segundos",validators=[MinValueValidator(300),MaxValueValidator(604800)])
    password_reset_resend_seconds = models.PositiveIntegerField(default=60, help_text="Segundos",validators=[MinValueValidator(10),MaxValueValidator(3600)])
    login_max_attempts = models.PositiveSmallIntegerField(default=5, help_text="Erros de senha consecutivos antes do bloqueio temporário",validators=[MinValueValidator(1),MaxValueValidator(50)])
    login_lockout_seconds = models.PositiveIntegerField(default=300, help_text="Segundos",validators=[MinValueValidator(30),MaxValueValidator(86400)])
    default_language = models.CharField(max_length=16, choices=LANGUAGE_CHOICES, default="pt-BR")
    default_timezone = models.CharField(max_length=64, choices=timezone_choices, default="America/Sao_Paulo")
    registration_enabled = models.BooleanField(default=False, help_text="Permite que qualquer visitante crie a própria conta na tela de cadastro.")
    registration_default_groups = models.ManyToManyField("auth.Group", blank=True, related_name="registration_defaults", help_text="Concedidos automaticamente a quem se cadastrar.")

    class Meta: verbose_name = "Política de segurança"
    @classmethod
    def load(cls):
        obj, _ = cls.objects.get_or_create(pk=1)
        return obj
    def save(self, *args, **kwargs):
        self.pk = 1
        return super().save(*args, **kwargs)


class EmailConfiguration(models.Model):
    """Configuração SMTP única, com senha cifrada no banco."""

    enabled = models.BooleanField(default=False)
    host = models.CharField(max_length=255, blank=True)
    port = models.PositiveIntegerField(default=587, validators=[MinValueValidator(1), MaxValueValidator(65535)])
    username = models.CharField(max_length=255, blank=True)
    encrypted_password = models.BinaryField(blank=True, editable=False)
    from_email = models.CharField(max_length=320, blank=True)
    use_tls = models.BooleanField(default=True)
    use_ssl = models.BooleanField(default=False)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Configuração de e-mail"

    @classmethod
    def load(cls):
        obj, _ = cls.objects.get_or_create(pk=1)
        return obj

    @property
    def has_password(self):
        return bool(self.encrypted_password)

    @property
    def is_configured(self):
        return self.enabled and bool(self.host.strip())

    def set_password(self, password):
        from .crypto import encrypt_value
        self.encrypted_password = encrypt_value(password.encode(), "smtp-password") if password else b""

    def get_password(self):
        if not self.encrypted_password:
            return ""
        from .crypto import decrypt_value
        return decrypt_value(self.encrypted_password, "smtp-password").decode()

    def save(self, *args, **kwargs):
        self.pk = 1
        self.host = self.host.strip()
        self.username = self.username.strip()
        self.from_email = self.from_email.strip()
        return super().save(*args, **kwargs)


class ClientSecret(models.Model):
    client=models.ForeignKey(OIDCClient,on_delete=models.CASCADE,related_name="secrets")
    prefix=models.CharField(max_length=12)
    secret_hash=models.CharField(max_length=255)
    created_at=models.DateTimeField(auto_now_add=True)
    expires_at=models.DateTimeField(null=True,blank=True)
    revoked_at=models.DateTimeField(null=True,blank=True)
    last_used_at=models.DateTimeField(null=True,blank=True)


class UserMFA(models.Model):
    user=models.OneToOneField(User,on_delete=models.CASCADE,related_name="mfa")
    encrypted_secret=models.BinaryField()
    enabled=models.BooleanField(default=False)
    verified_at=models.DateTimeField(null=True,blank=True)
    last_used_counter=models.BigIntegerField(default=-1)
    recovery_code_hashes=models.JSONField(default=list,blank=True)
    failed_attempts=models.PositiveSmallIntegerField(default=0)
    locked_until=models.DateTimeField(null=True,blank=True)
    created_at=models.DateTimeField(auto_now_add=True)
    updated_at=models.DateTimeField(auto_now=True)
    def set_secret(self,secret):
        from .crypto import encrypt_value
        self.encrypted_secret=encrypt_value(secret.encode(),"totp-secret")
    def get_secret(self):
        from .crypto import decrypt_value
        return decrypt_value(self.encrypted_secret,"totp-secret").decode()


class UserSecurityState(models.Model):
    user=models.OneToOneField(User,on_delete=models.CASCADE,related_name="security_state")
    authentication_version=models.UUIDField(default=uuid.uuid4)
    must_change_password=models.BooleanField(default=False)
    failed_login_attempts=models.PositiveSmallIntegerField(default=0)
    login_locked_until=models.DateTimeField(null=True,blank=True)
    updated_at=models.DateTimeField(auto_now=True)


class UserPreferences(models.Model):
    """Preferências de localização por usuário; os valores iniciais vêm do SecurityPolicy."""

    user=models.OneToOneField(User,on_delete=models.CASCADE,related_name="preferences")
    language=models.CharField(max_length=16,choices=LANGUAGE_CHOICES,default="pt-BR")
    timezone=models.CharField(max_length=64,choices=timezone_choices,default="America/Sao_Paulo")
    updated_at=models.DateTimeField(auto_now=True)

    class Meta: verbose_name="Preferências do usuário"

    @classmethod
    def for_user(cls,user):
        policy=SecurityPolicy.load()
        obj,_=cls.objects.get_or_create(user=user,defaults={"language":policy.default_language,"timezone":policy.default_timezone})
        return obj


class UserEmailState(models.Model):
    """Verification state kept separately from Django's mutable User.email."""

    user=models.OneToOneField(User,on_delete=models.CASCADE,related_name="email_state")
    email_verified=models.BooleanField(default=False)
    verified_email=models.EmailField(null=True,blank=True,unique=True)
    pending_email=models.EmailField(blank=True)
    confirmation_token_hash=models.CharField(max_length=64,blank=True,db_index=True)
    confirmation_expires_at=models.DateTimeField(null=True,blank=True)
    confirmation_sent_at=models.DateTimeField(null=True,blank=True)
    password_reset_sent_at=models.DateTimeField(null=True,blank=True)
    verified_at=models.DateTimeField(null=True,blank=True)
    created_at=models.DateTimeField(auto_now_add=True)
    updated_at=models.DateTimeField(auto_now=True)

    def is_current_email_verified(self):
        if not self.email_verified or not self.verified_email or not self.user.email:
            return False
        return self.verified_email.casefold() == self.user.email.strip().casefold()

    def save(self,*args,**kwargs):
        if self.verified_email:
            self.verified_email=self.verified_email.strip().casefold()
        if self.pending_email:
            self.pending_email=self.pending_email.strip().casefold()
        return super().save(*args,**kwargs)


class MFAChallenge(models.Model):
    id=models.UUIDField(primary_key=True,default=uuid.uuid4,editable=False)
    user=models.ForeignKey(User,on_delete=models.CASCADE,related_name="mfa_challenges")
    session_binding=models.CharField(max_length=64)
    password_session_hash=models.CharField(max_length=128)
    next_url=models.TextField()
    auth_time=models.DateTimeField(default=timezone.now)
    created_at=models.DateTimeField(auto_now_add=True)
    expires_at=models.DateTimeField()
    attempts=models.PositiveSmallIntegerField(default=0)
    consumed_at=models.DateTimeField(null=True,blank=True)
    ip_address=models.GenericIPAddressField(null=True,blank=True)


class AuditEvent(models.Model):
    actor=models.ForeignKey(User,null=True,on_delete=models.SET_NULL,related_name="identity_audit_events")
    action=models.CharField(max_length=80,db_index=True)
    target_type=models.CharField(max_length=80)
    target_id=models.CharField(max_length=120,blank=True)
    metadata=models.JSONField(default=dict,blank=True)
    ip_address=models.GenericIPAddressField(null=True,blank=True)
    created_at=models.DateTimeField(auto_now_add=True,db_index=True)
    class Meta: ordering=["-created_at"]


class SigningKey(models.Model):
    kid = models.CharField(max_length=64, unique=True)
    encrypted_private_key = models.BinaryField()
    public_jwk = models.JSONField()
    algorithm = models.CharField(max_length=10, default="RS256", editable=False)
    active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    retired_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at"]
        constraints=[models.UniqueConstraint(fields=["active"],condition=models.Q(active=True),name="single_active_signing_key")]
    def __str__(self): return self.kid


class AuthorizationCode(models.Model):
    code_hash = models.CharField(max_length=64, unique=True)
    client = models.ForeignKey(OIDCClient, on_delete=models.CASCADE)
    audience = models.ForeignKey(OIDCClient, on_delete=models.CASCADE, related_name="audience_authorization_codes")
    oidc_session = models.ForeignKey("OIDCSession", null=True, blank=True, on_delete=models.CASCADE, related_name="authorization_codes")
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    redirect_uri = models.TextField()
    scope = models.TextField()
    nonce = models.CharField(max_length=255, blank=True)
    code_challenge = models.CharField(max_length=128, blank=True)
    code_challenge_method = models.CharField(max_length=10, blank=True)
    expires_at = models.DateTimeField()
    used_at = models.DateTimeField(null=True, blank=True)

    @classmethod
    def issue(cls, **kwargs):
        raw = secrets.token_urlsafe(48)
        cls.objects.create(code_hash=hashlib.sha256(raw.encode()).hexdigest(), expires_at=timezone.now()+timezone.timedelta(minutes=2), **kwargs)
        return raw


class RefreshToken(models.Model):
    token_hash = models.CharField(max_length=64, unique=True)
    client = models.ForeignKey(OIDCClient, on_delete=models.CASCADE)
    audience = models.ForeignKey(OIDCClient, on_delete=models.CASCADE, related_name="audience_refresh_tokens")
    oidc_session = models.ForeignKey("OIDCSession", null=True, blank=True, on_delete=models.CASCADE, related_name="refresh_tokens")
    family_id = models.UUIDField(default=uuid.uuid4, db_index=True)
    parent = models.ForeignKey("self", null=True, blank=True, on_delete=models.SET_NULL, related_name="children")
    reuse_detected_at = models.DateTimeField(null=True, blank=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    scope = models.TextField()
    expires_at = models.DateTimeField()
    revoked_at = models.DateTimeField(null=True, blank=True)

    @classmethod
    def issue(cls, **kwargs):
        raw = secrets.token_urlsafe(64)
        cls.objects.create(token_hash=hashlib.sha256(raw.encode()).hexdigest(), **kwargs)
        return raw


class OIDCSession(models.Model):
    id=models.UUIDField(primary_key=True,default=uuid.uuid4,editable=False)
    user=models.ForeignKey(User,on_delete=models.CASCADE,related_name="oidc_sessions")
    client=models.ForeignKey(OIDCClient,on_delete=models.CASCADE,related_name="user_sessions")
    audience=models.ForeignKey(OIDCClient,on_delete=models.CASCADE,related_name="audience_sessions")
    auth_time=models.DateTimeField(default=timezone.now)
    authentication_methods=models.JSONField(default=list)
    acr=models.CharField(max_length=80,default="urn:gatelite:acr:1")
    authentication_version=models.UUIDField(null=True)
    expires_at=models.DateTimeField()
    last_seen_at=models.DateTimeField(auto_now=True)
    revoked_at=models.DateTimeField(null=True,blank=True)
    def is_active(self):
        if self.revoked_at or self.expires_at<=timezone.now() or not self.user.is_active or not self.client.is_active or not self.audience.is_active: return False
        state=UserSecurityState.objects.filter(user=self.user).first()
        if self.authentication_version and state and self.authentication_version!=state.authentication_version: return False
        policy=SecurityPolicy.load(); is_admin=self.user.is_superuser or self.user.is_staff or any(self.user.has_perm(f"identity.{code}") for code in ("view_identity_console","manage_users","manage_groups","manage_clients","manage_security","manage_keys","manage_permissions"))
        required=policy.mfa_mode==SecurityPolicy.MFAMode.ALL or (policy.mfa_mode==SecurityPolicy.MFAMode.ADMINS and is_admin) or self.client.require_mfa or self.audience.require_mfa
        return not required or "otp" in self.authentication_methods or "recovery" in self.authentication_methods


class RevokedAccessToken(models.Model):
    jti = models.CharField(max_length=64, primary_key=True)
    expires_at = models.DateTimeField(db_index=True)
    revoked_at = models.DateTimeField(auto_now_add=True)

    class Meta: ordering = ["-revoked_at"]
