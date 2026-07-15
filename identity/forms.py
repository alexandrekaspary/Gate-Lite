import secrets
import re
from urllib.parse import urlsplit
from django import forms
from django.contrib.auth.forms import PasswordResetForm, SetPasswordForm, UserCreationForm
from django.contrib.auth.models import Group, Permission, User
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.utils import timezone, translation
from django.utils.translation import gettext_lazy as _
from .email_verification import EmailConfirmationError, EmailConfirmationThrottled, email_available_for_user, normalize_email, request_email_confirmation
from .models import LANGUAGE_CHOICES, ClientRole, ClientScopeAssignment, ClientURI, ClientWebOrigin, EmailConfiguration, OIDCClient, OIDCScope, SecurityPolicy, UserEmailState, UserPreferences, UserSecurityState, generate_client_id, timezone_choices

def grant_basic_permissions(user):
    user.user_permissions.add(*Permission.objects.filter(
        content_type__app_label="identity",
        codename__in=("view_own_profile", "change_own_password"),
    ))

def user_preference_defaults(user):
    """(language, timezone) do usuário, caindo nos padrões do sistema."""
    preferences=UserPreferences.objects.filter(user=user).first() if user and user.pk else None
    if preferences: return preferences.language, preferences.timezone
    policy=SecurityPolicy.load()
    return policy.default_language, policy.default_timezone

class StyledFormMixin:
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field in self.fields.values():
            # Listas de seleção múltipla viram checkboxes: desmarcar um único
            # item selecionado num <select multiple> exige Ctrl+clique, o que
            # torna a remoção da última opção quase impossível de descobrir.
            if isinstance(field.widget, forms.SelectMultiple) and not isinstance(field.widget, forms.CheckboxSelectMultiple):
                field.widget = forms.CheckboxSelectMultiple(attrs=field.widget.attrs)
                field.widget.choices = field.choices
            if not isinstance(field.widget, (forms.CheckboxInput, forms.RadioSelect, forms.CheckboxSelectMultiple)):
                field.widget.attrs.setdefault("class", "input")

class UserCreateForm(StyledFormMixin, UserCreationForm):
    # password1/password2 adjacentes ocupam a mesma linha do grid de 2 colunas
    # no passo Segurança do wizard.
    field_order = ("username","first_name","last_name","email","language","timezone","password1","password2","must_change_password","basic_access","groups","client_roles","is_active","is_staff","user_permissions")
    basic_access = forms.CharField(required=False, disabled=True, initial="Perfil próprio e alteração da própria senha", label="Acesso básico")
    email = forms.EmailField(required=False)
    language = forms.ChoiceField(choices=LANGUAGE_CHOICES, required=False, label="Idioma", help_text="Padrão definido nas configurações.")
    timezone = forms.ChoiceField(choices=timezone_choices, required=False, label="Fuso horário", help_text="Padrão definido nas configurações.")
    must_change_password = forms.BooleanField(required=False, initial=True, label="Exigir troca de senha no próximo login", help_text="Acesso restrito até definir uma nova senha.")
    groups = forms.ModelMultipleChoiceField(Group.objects.all(), required=False)
    client_roles = forms.ModelMultipleChoiceField(ClientRole.objects.select_related("client").order_by("client__name","name"), required=False, label="Roles diretas de clients", help_text="Atribua somente exceções; prefira roles herdadas por grupos.")
    user_permissions = forms.ModelMultipleChoiceField(Permission.objects.select_related("content_type").exclude(content_type__app_label="identity", codename__in=("view_own_profile","change_own_password")), required=False, label="Permissões administrativas")
    class Meta(UserCreationForm.Meta):
        fields = ("username", "first_name", "last_name", "email", "language", "timezone", "must_change_password", "basic_access", "groups", "client_roles", "is_active", "is_staff", "user_permissions")
        # Ajuda curta, em uma linha, no lugar dos textos longos padrão do Django.
        help_texts = {"is_active": "Desmarque para suspender a conta sem excluí-la.", "is_staff": "Permite acessar o Console admin."}
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        policy = SecurityPolicy.load()
        self.fields["language"].initial = policy.default_language
        self.fields["timezone"].initial = policy.default_timezone
    def clean_language(self):
        return self.cleaned_data.get("language") or SecurityPolicy.load().default_language
    def clean_timezone(self):
        return self.cleaned_data.get("timezone") or SecurityPolicy.load().default_timezone
    def clean_email(self):
        email=self.cleaned_data.get("email","").strip()
        if email and User.objects.filter(email__iexact=email).exists():
            raise forms.ValidationError("Este endereço de e-mail já está em uso.")
        return normalize_email(email) if email else ""
    def save(self, commit=True):
        user = super().save(commit)
        if commit:
            grant_basic_permissions(user)
            user.direct_oidc_client_roles.set(self.cleaned_data["client_roles"])
            state, _ = UserSecurityState.objects.get_or_create(user=user)
            state.must_change_password = self.cleaned_data["must_change_password"]
            state.save(update_fields=["must_change_password", "updated_at"])
            UserPreferences.objects.update_or_create(user=user, defaults={"language": self.cleaned_data["language"], "timezone": self.cleaned_data["timezone"]})
        return user

class UserEditForm(StyledFormMixin, forms.ModelForm):
    basic_access = forms.CharField(required=False, disabled=True, initial="Perfil próprio e alteração da própria senha", label="Acesso básico")
    new_password = forms.CharField(required=False, widget=forms.PasswordInput(attrs={"autocomplete": "new-password"}), label="Nova senha", help_text="Deixe em branco para manter a senha atual.")
    new_password_confirmation = forms.CharField(required=False, widget=forms.PasswordInput(attrs={"autocomplete": "new-password"}), label="Confirme a nova senha")
    language = forms.ChoiceField(choices=LANGUAGE_CHOICES, required=False, label="Idioma")
    timezone = forms.ChoiceField(choices=timezone_choices, required=False, label="Fuso horário")
    must_change_password = forms.BooleanField(required=False, label="Exigir troca de senha no próximo login", help_text="Acesso restrito até definir uma nova senha.")
    user_permissions = forms.ModelMultipleChoiceField(Permission.objects.select_related("content_type").exclude(content_type__app_label="identity", codename__in=("view_own_profile","change_own_password")), required=False, label="Permissões administrativas")
    client_roles = forms.ModelMultipleChoiceField(ClientRole.objects.select_related("client").order_by("client__name","name"), required=False, label="Roles diretas de clients", help_text="Somadas às roles herdadas pelos grupos.")
    reset_mfa = forms.BooleanField(required=False,label="Redefinir 2FA",help_text="Remove o autenticador e códigos de recuperação.")
    class Meta:
        model = User
        fields = ("username", "first_name", "last_name", "email", "language", "timezone", "new_password", "new_password_confirmation", "must_change_password", "basic_access", "groups", "client_roles", "is_active", "is_staff", "is_superuser", "user_permissions", "reset_mfa")
        widgets = {"groups": forms.SelectMultiple(), "user_permissions": forms.SelectMultiple()}
        # Ajuda curta, em uma linha, no lugar dos textos longos padrão do Django.
        help_texts = {"is_active": "Desmarque para suspender a conta sem excluí-la.", "is_staff": "Permite acessar o Console admin.", "is_superuser": "Concede todas as permissões automaticamente."}
    def __init__(self, *args, **kwargs):
        instance=kwargs.get("instance")
        self._original_email=(instance.email if instance else "") or ""
        super().__init__(*args, **kwargs)
        if self.instance.pk:
            self.fields["client_roles"].initial = self.instance.direct_oidc_client_roles.all()
            state, _ = UserSecurityState.objects.get_or_create(user=self.instance)
            self.fields["must_change_password"].initial = state.must_change_password
            self.fields["language"].initial, self.fields["timezone"].initial = user_preference_defaults(self.instance)
    def clean_language(self):
        return self.cleaned_data.get("language") or user_preference_defaults(self.instance)[0]
    def clean_timezone(self):
        return self.cleaned_data.get("timezone") or user_preference_defaults(self.instance)[1]
    def clean_email(self):
        email=self.cleaned_data.get("email","").strip()
        if email and not email_available_for_user(email,self.instance):
            raise forms.ValidationError("Este endereço de e-mail já está em uso.")
        return normalize_email(email) if email else ""
    def clean(self):
        cleaned_data = super().clean()
        new_password = cleaned_data.get("new_password")
        confirmation = cleaned_data.get("new_password_confirmation")
        if new_password or confirmation:
            if not new_password:
                self.add_error("new_password", "Informe a nova senha.")
            elif not confirmation:
                self.add_error("new_password_confirmation", "Confirme a nova senha.")
            elif new_password != confirmation:
                self.add_error("new_password_confirmation", "As senhas não coincidem.")
            else:
                candidate = User(
                    username=cleaned_data.get("username", self.instance.username),
                    first_name=cleaned_data.get("first_name", self.instance.first_name),
                    last_name=cleaned_data.get("last_name", self.instance.last_name),
                    email=cleaned_data.get("email", self._original_email),
                )
                try:
                    validate_password(new_password, candidate)
                except ValidationError as exc:
                    self.add_error("new_password", exc)
        return cleaned_data
    def save(self, commit=True):
        user = super().save(commit=False)
        requested_email=self.cleaned_data.get("email","")
        user.email=self._original_email if requested_email else ""
        password_changed = bool(self.cleaned_data.get("new_password"))
        if password_changed:
            user.set_password(self.cleaned_data["new_password"])
        if commit:
            user.save(); self.save_m2m(); grant_basic_permissions(user); user.direct_oidc_client_roles.set(self.cleaned_data["client_roles"])
            UserPreferences.objects.update_or_create(user=user, defaults={"language": self.cleaned_data["language"], "timezone": self.cleaned_data["timezone"]})
            state, _ = UserSecurityState.objects.get_or_create(user=user)
            was_required = state.must_change_password
            state.must_change_password = self.cleaned_data["must_change_password"]
            state.save(update_fields=["must_change_password", "updated_at"])
            if requested_email and requested_email.casefold()!=self._original_email.strip().casefold():
                request=getattr(self,"request",None)
                try:
                    request_email_confirmation(
                        user,requested_email,request=request,
                        actor=request.user if request else None,
                        ip_address=request.META.get("REMOTE_ADDR") if request else None,
                    )
                except EmailConfirmationThrottled as exc:
                    self.email_confirmation_error=f"A confirmação anterior ainda está no intervalo de reenvio. Tente em {exc.retry_after} segundos."
                except EmailConfirmationError as exc:
                    self.email_confirmation_error=str(exc)
                except Exception:
                    self.email_confirmation_error="Não foi possível enviar a confirmação de e-mail agora."
            if password_changed or self.cleaned_data.get("reset_mfa") or (state.must_change_password and not was_required):
                from .mfa import invalidate_web_sessions, rotate_security_version
                rotate_security_version(user)
                invalidate_web_sessions(user)
            if self.cleaned_data.get("reset_mfa"):
                from .models import UserMFA
                UserMFA.objects.filter(user=user).delete()
        return user


class UserRegistrationForm(StyledFormMixin, UserCreationForm):
    field_order = ("username", "first_name", "last_name", "email", "password1", "password2")
    email = forms.EmailField(required=True, label=_("E-mail"))
    class Meta(UserCreationForm.Meta):
        fields = ("username", "first_name", "last_name", "email")
        labels = {"first_name": _("Nome"), "last_name": _("Sobrenome")}
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["username"].help_text = _("Não pode ser alterado depois de criada a conta.")
    def clean_email(self):
        email = normalize_email(self.cleaned_data.get("email", ""))
        if User.objects.filter(email__iexact=email).exists():
            raise forms.ValidationError(_("Este endereço de e-mail já está em uso."))
        return email
    def save(self, commit=True):
        user = super().save(commit=False)
        user.email = self.cleaned_data["email"]
        if commit:
            user.save()
            grant_basic_permissions(user)
            policy = SecurityPolicy.load()
            user.groups.set(policy.registration_default_groups.all())
            UserPreferences.objects.update_or_create(user=user, defaults={"language": policy.default_language, "timezone": policy.default_timezone})
        return user


class AccountProfileForm(StyledFormMixin, forms.ModelForm):
    email=forms.EmailField(required=True,label=_("E-mail"))
    language=forms.ChoiceField(choices=LANGUAGE_CHOICES,required=False,label=_("Idioma"))
    timezone=forms.ChoiceField(choices=timezone_choices,required=False,label=_("Fuso horário"))

    class Meta:
        model=User
        fields=("first_name","last_name","email")
        labels={"first_name":_("Nome"),"last_name":_("Sobrenome")}

    def __init__(self,*args,**kwargs):
        instance=kwargs.get("instance")
        self._original_email=(instance.email if instance else "") or ""
        super().__init__(*args,**kwargs)
        self.fields["language"].initial,self.fields["timezone"].initial=user_preference_defaults(self.instance)

    def clean_language(self):
        return self.cleaned_data.get("language") or user_preference_defaults(self.instance)[0]

    def clean_timezone(self):
        return self.cleaned_data.get("timezone") or user_preference_defaults(self.instance)[1]

    def clean_email(self):
        email=normalize_email(self.cleaned_data["email"])
        if not email_available_for_user(email,self.instance):
            raise forms.ValidationError(_("Este endereço de e-mail já está em uso."))
        return email

    def save(self, commit=True, request=None):
        current_email=self._original_email.strip().casefold()
        requested_email=self.cleaned_data["email"]
        user=super().save(commit=False)
        user.email=self._original_email
        if commit:
            user.save(update_fields=["first_name","last_name"])
            UserPreferences.objects.update_or_create(user=user,defaults={"language":self.cleaned_data["language"],"timezone":self.cleaned_data["timezone"]})
            state,_=UserEmailState.objects.get_or_create(user=user)
            current_verified=state.is_current_email_verified()
            if requested_email!=current_email or not current_verified:
                self.confirmation=request_email_confirmation(
                    user,requested_email,request=request,actor=user,
                    ip_address=request.META.get("REMOTE_ADDR") if request else None,
                )
            else:
                self.confirmation=None
        return user


class VerifiedEmailPasswordResetForm(PasswordResetForm):
    """Keep Django's non-enumerating response while selecting verified mail only."""

    def get_users(self, email):
        normalized=normalize_email(email)
        throttle=SecurityPolicy.load().password_reset_resend_seconds
        now=timezone.now()
        users=User._default_manager.filter(email__iexact=normalized,is_active=True).select_related("email_state")
        for user in users.iterator():
            state=getattr(user,"email_state",None)
            if user.has_usable_password() and state and state.is_current_email_verified():
                # The throttled branch keeps the public response identical, so a
                # rapid second request neither enumerates accounts nor sends mail.
                if state.password_reset_sent_at and (now-state.password_reset_sent_at).total_seconds()<throttle:
                    continue
                UserEmailState.objects.filter(pk=state.pk).update(password_reset_sent_at=now,updated_at=now)
                yield user

    def send_mail(self,subject_template_name,email_template_name,context,from_email,to_email,html_email_template_name=None):
        language=user_preference_defaults(context.get("user"))[0]
        with translation.override(language.lower()):
            return super().send_mail(subject_template_name,email_template_name,context,from_email,to_email,html_email_template_name)


class SecureSetPasswordForm(SetPasswordForm):
    def __init__(self, *args, keep_session_key=None, **kwargs):
        self.keep_session_key = keep_session_key
        super().__init__(*args, **kwargs)

    def save(self, commit=True):
        user=super().save(commit=commit)
        if commit:
            from .mfa import invalidate_web_sessions, rotate_security_version
            UserSecurityState.objects.filter(user=user,must_change_password=True).update(must_change_password=False)
            rotate_security_version(user)
            invalidate_web_sessions(user,self.keep_session_key)
        return user

class GroupForm(StyledFormMixin, forms.ModelForm):
    users = forms.ModelMultipleChoiceField(User.objects.order_by("username"), required=False, label="Usuários do grupo", help_text="Membros herdam o acesso e as roles vinculadas a este grupo.")
    client_roles = forms.ModelMultipleChoiceField(ClientRole.objects.select_related("client").order_by("client__name", "name"), required=False, label="Roles de clients", help_text="Cada opção é exibida como Client · Role.")
    class Meta:
        model = Group
        fields = ("name", "users", "client_roles", "permissions")
        labels = {"permissions":"Permissões administrativas do grupo"}
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.instance.pk:
            self.fields["users"].initial = self.instance.user_set.all()
            self.fields["client_roles"].initial = self.instance.oidc_client_roles.all()
    def save(self, commit=True):
        group = super().save(commit)
        if commit:
            group.user_set.set(self.cleaned_data["users"])
            group.oidc_client_roles.set(self.cleaned_data["client_roles"])
        return group

class PermissionForm(StyledFormMixin, forms.ModelForm):
    class Meta: model = Permission; fields = ("name", "codename", "content_type")

class ClientForm(StyledFormMixin, forms.ModelForm):
    redirect_uris=forms.CharField(widget=forms.Textarea,required=False,label="Redirect URIs",help_text="Uma URI exata por linha.")
    post_logout_redirect_uris=forms.CharField(widget=forms.Textarea,required=False,label="Post logout redirect URIs",help_text="Uma URI exata por linha.")
    allowed_origins=forms.CharField(widget=forms.Textarea,required=False,label="Web origins (CORS)",help_text="Uma origem exata por linha, sem caminho.")
    scopes=forms.CharField(widget=forms.Textarea,initial="openid profile email groups offline_access",label="Scopes permitidos",help_text="Separe por espaço, vírgula ou linha.")
    generate_secret = forms.BooleanField(required=False, initial=True, help_text="Um novo secret será mostrado uma única vez.")
    class Meta:
        model = OIDCClient
        fields = ("name","client_id","application_type","client_type","token_endpoint_auth_method","authorization_code_enabled","refresh_token_enabled","client_credentials_enabled","require_pkce","require_mfa","allowed_audiences","access_policy","allowed_groups","allowed_users","is_active")
        labels = {"authorization_code_enabled":"Authorization Code","refresh_token_enabled":"Refresh Token","client_credentials_enabled":"Client Credentials","require_pkce":"Exigir PKCE"}
        help_texts = {"authorization_code_enabled":"Login interativo de usuários pelo navegador.","refresh_token_enabled":"Permite renovar tokens sem novo login.","client_credentials_enabled":"Emite tokens de service account, sem usuário.","require_pkce":"Sempre ativo em clients públicos."}
    def __init__(self,*args,**kwargs):
        super().__init__(*args,**kwargs)
        self.fields["generate_secret"].initial=not bool(self.instance.pk)
        if not self.instance.pk:
            self.initial["client_id"]=""
            self.fields["client_id"].required=False
            self.fields["client_id"].help_text="Deixe em branco para gerar um identificador aleatório."
        if self.instance.pk:
            self.fields["redirect_uris"].initial="\n".join(self.instance.uri_list())
            self.fields["post_logout_redirect_uris"].initial="\n".join(self.instance.uri_list("post_logout_redirect_uris"))
            self.fields["allowed_origins"].initial="\n".join(self.instance.origin_list())
            self.fields["scopes"].initial=" ".join(self.instance.scope_names())
    @staticmethod
    def _lines(value): return list(dict.fromkeys(line.strip() for line in value.splitlines() if line.strip()))
    def clean_client_id(self):
        return self.cleaned_data.get("client_id","").strip() or generate_client_id()
    def _validate_uri(self,value,origin=False):
        parsed=urlsplit(value)
        if not parsed.scheme or parsed.fragment or parsed.username or parsed.password: raise forms.ValidationError("URI absoluta inválida; fragmentos e credenciais não são permitidos.")
        if origin and (parsed.scheme not in ("http","https") or parsed.query or parsed.path not in ("","/")): raise forms.ValidationError("Origem CORS deve conter somente scheme, host e porta.")
        if parsed.scheme in ("http","https"):
            if not parsed.hostname: raise forms.ValidationError("Host obrigatório.")
            if parsed.scheme=="http" and parsed.hostname not in ("localhost","127.0.0.1","::1"): raise forms.ValidationError("HTTP é permitido somente para loopback exato.")
        elif origin or self.cleaned_data.get("application_type")!=OIDCClient.ApplicationType.NATIVE:
            raise forms.ValidationError("Scheme customizado é permitido somente para aplicativos nativos.")
        return value.rstrip("/") if origin else value
    def clean(self):
        data=super().clean()
        if data.get("client_type")==OIDCClient.ClientType.PUBLIC:
            data["token_endpoint_auth_method"]=OIDCClient.AuthMethod.NONE
            data["require_pkce"]=True
            data["client_credentials_enabled"]=False
            self.instance.token_endpoint_auth_method=OIDCClient.AuthMethod.NONE
            self.instance.require_pkce=True; self.instance.client_credentials_enabled=False
        app_type=data.get("application_type")
        if not getattr(self, "derive_application_defaults", False):
            if app_type in (OIDCClient.ApplicationType.SPA,OIDCClient.ApplicationType.NATIVE) and data.get("client_type")!=OIDCClient.ClientType.PUBLIC: self.add_error("client_type","SPA e aplicativos nativos devem ser clients públicos.")
            if app_type in (OIDCClient.ApplicationType.SERVICE,OIDCClient.ApplicationType.RESOURCE) and data.get("client_type")!=OIDCClient.ClientType.CONFIDENTIAL: self.add_error("client_type","Services e resource servers devem ser confidenciais.")
        redirects=self._lines(data.get("redirect_uris", "")); origins=self._lines(data.get("allowed_origins", "")); logouts=self._lines(data.get("post_logout_redirect_uris", ""))
        if not getattr(self, "derive_application_defaults", False) and data.get("authorization_code_enabled") and not redirects: self.add_error("redirect_uris","Informe ao menos uma Redirect URI para Authorization Code.")
        for field,values,is_origin in (("redirect_uris",redirects,False),("post_logout_redirect_uris",logouts,False),("allowed_origins",origins,True)):
            try: data[field]="\n".join(dict.fromkeys(self._validate_uri(v,is_origin) for v in values))
            except forms.ValidationError as exc: self.add_error(field,exc)
        scope_names=list(dict.fromkeys(re.findall(r"[A-Za-z0-9_.:-]+",data.get("scopes", ""))))
        if not getattr(self, "derive_application_defaults", False) and data.get("authorization_code_enabled") and "openid" not in scope_names: self.add_error("scopes","Authorization Code OIDC exige o scope openid.")
        data["scope_names"]=scope_names
        return data
    def save(self,commit=True):
        client=super().save(commit)
        if commit:
            ClientURI.objects.filter(client=client).delete()
            ClientURI.objects.bulk_create([ClientURI(client=client,kind=kind,uri=uri) for kind,field in ((ClientURI.Kind.REDIRECT,"redirect_uris"),(ClientURI.Kind.POST_LOGOUT,"post_logout_redirect_uris")) for uri in self._lines(self.cleaned_data.get(field,""))])
            ClientWebOrigin.objects.filter(client=client).delete(); ClientWebOrigin.objects.bulk_create([ClientWebOrigin(client=client,origin=v) for v in self._lines(self.cleaned_data.get("allowed_origins",""))])
            scopes=[OIDCScope.objects.get_or_create(name=name,defaults={"description":"Scope customizado"})[0] for name in self.cleaned_data["scope_names"]]
            ClientScopeAssignment.objects.filter(client=client).exclude(scope__in=scopes).delete()
            for scope in scopes: ClientScopeAssignment.objects.get_or_create(client=client,scope=scope,defaults={"is_default":scope.name in ("openid","profile","email")})
        return client

class ClientCreateForm(ClientForm):
    """Cadastro orientado pelo tipo da aplicação, com protocolo seguro derivado."""

    derive_application_defaults = True
    role_definitions = forms.CharField(
        label="Roles do client",
        widget=forms.Textarea(attrs={"rows": 6, "placeholder": "reader | Consulta dados\neditor | Altera dados"}),
        help_text="Informe uma role por linha no formato nome | descrição.",
    )
    url_status = forms.CharField(
        label="URLs deste tipo",
        required=False,
        disabled=True,
        initial="Este tipo não usa redirecionamento. Configure CORS somente se houver chamadas pelo navegador.",
    )

    APPLICATION_PRESETS = {
        OIDCClient.ApplicationType.SPA: {
            "client_type": OIDCClient.ClientType.PUBLIC,
            "token_endpoint_auth_method": OIDCClient.AuthMethod.NONE,
            "authorization_code_enabled": True,
            "refresh_token_enabled": True,
            "client_credentials_enabled": False,
            "require_pkce": True,
        },
        OIDCClient.ApplicationType.NATIVE: {
            "client_type": OIDCClient.ClientType.PUBLIC,
            "token_endpoint_auth_method": OIDCClient.AuthMethod.NONE,
            "authorization_code_enabled": True,
            "refresh_token_enabled": True,
            "client_credentials_enabled": False,
            "require_pkce": True,
        },
        OIDCClient.ApplicationType.WEB: {
            "client_type": OIDCClient.ClientType.CONFIDENTIAL,
            "token_endpoint_auth_method": OIDCClient.AuthMethod.BASIC,
            "authorization_code_enabled": True,
            "refresh_token_enabled": True,
            "client_credentials_enabled": False,
            "require_pkce": True,
        },
        OIDCClient.ApplicationType.SERVICE: {
            "client_type": OIDCClient.ClientType.CONFIDENTIAL,
            "token_endpoint_auth_method": OIDCClient.AuthMethod.BASIC,
            "authorization_code_enabled": False,
            "refresh_token_enabled": False,
            "client_credentials_enabled": True,
            "require_pkce": False,
        },
        OIDCClient.ApplicationType.RESOURCE: {
            "client_type": OIDCClient.ClientType.CONFIDENTIAL,
            "token_endpoint_auth_method": OIDCClient.AuthMethod.BASIC,
            "authorization_code_enabled": False,
            "refresh_token_enabled": False,
            "client_credentials_enabled": False,
            "require_pkce": False,
        },
    }
    DERIVED_FIELDS = tuple(next(iter(APPLICATION_PRESETS.values())))
    SCOPE_PRESETS = {
        OIDCClient.ApplicationType.SPA: "openid profile email groups offline_access",
        OIDCClient.ApplicationType.NATIVE: "openid profile email groups offline_access",
        OIDCClient.ApplicationType.WEB: "openid profile email groups offline_access",
        OIDCClient.ApplicationType.SERVICE: "api.read",
        OIDCClient.ApplicationType.RESOURCE: "api.read api.write",
    }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        application_type = (
            self.data.get("application_type") if self.is_bound
            else self.initial.get("application_type", OIDCClient.ApplicationType.WEB)
        )
        preset = self.APPLICATION_PRESETS.get(application_type, self.APPLICATION_PRESETS[OIDCClient.ApplicationType.WEB])
        for name in self.DERIVED_FIELDS:
            self.fields[name].required = False
            self.fields[name].disabled = True
            self.fields[name].initial = preset[name]
        for name in ("generate_secret", "allowed_groups", "allowed_users", "allowed_audiences"):
            self.fields.pop(name, None)
        self.fields["access_policy"].required = False
        self.fields["access_policy"].disabled = True
        self.fields["access_policy"].widget = forms.HiddenInput()
        self.fields["access_policy"].initial = self.instance.access_policy if self.instance.pk else OIDCClient.AccessPolicy.OPEN
        self.fields["application_type"].choices = (
            (OIDCClient.ApplicationType.SPA, "SPA — aplicação no navegador"),
            (OIDCClient.ApplicationType.NATIVE, "Aplicativo mobile ou desktop"),
            (OIDCClient.ApplicationType.WEB, "Backend web com login de usuário"),
            (OIDCClient.ApplicationType.SERVICE, "Serviço sem usuário — máquina a máquina"),
            (OIDCClient.ApplicationType.RESOURCE, "API que recebe e valida tokens"),
        )
        self.fields["application_type"].help_text = "A escolha define automaticamente os fluxos, a autenticação e os campos necessários."
        self.fields["client_type"].label = "Tipo do client"
        self.fields["token_endpoint_auth_method"].label = "Autenticação no endpoint de token"
        self.fields["authorization_code_enabled"].help_text = "Login de usuário pelo navegador. Usado em SPA, mobile e backend web com login."
        self.fields["refresh_token_enabled"].help_text = "Renova a sessão da aplicação sem pedir novo login."
        self.fields["client_credentials_enabled"].help_text = "Token sem usuário, exclusivo para comunicação máquina a máquina."
        self.fields["require_pkce"].help_text = "Protege o Authorization Code contra interceptação."
        if not self.instance.pk:
            self.fields["scopes"].initial = self.SCOPE_PRESETS[application_type]
        self.fields["scopes"].help_text = "Permissões que este client poderá solicitar. Ajuste os nomes conforme sua API."
        self.fields["require_mfa"].label = "Exigir autenticação em dois fatores"

    def clean(self):
        data = super().clean()
        preset = self.APPLICATION_PRESETS.get(data.get("application_type"))
        if not preset:
            return data
        data.update(preset)
        for name, value in preset.items():
            setattr(self.instance, name, value)
        app_type = data.get("application_type")
        if app_type in (OIDCClient.ApplicationType.SERVICE, OIDCClient.ApplicationType.RESOURCE):
            for field_name in ("redirect_uris", "post_logout_redirect_uris"):
                self._errors.pop(field_name, None)
            data["redirect_uris"] = ""
            data["post_logout_redirect_uris"] = ""
            data["require_mfa"] = False
            self.instance.require_mfa = False
        if preset["authorization_code_enabled"]:
            if not self._lines(data.get("redirect_uris", "")) and "redirect_uris" not in self.errors:
                self.add_error("redirect_uris", "Informe ao menos uma Redirect URI para Authorization Code.")
            if "openid" not in data.get("scope_names", []) and "scopes" not in self.errors:
                self.add_error("scopes", "Aplicações com login de usuário exigem o scope openid.")
        roles = []
        seen = set()
        for line_number, line in enumerate(data.get("role_definitions", "").splitlines(), 1):
            if not line.strip():
                continue
            parts = [part.strip() for part in line.split("|", 1)]
            if len(parts) != 2 or not all(parts):
                self.add_error("role_definitions", f"Linha {line_number}: use o formato nome | descrição.")
                continue
            name, description = parts
            try:
                ClientRole._meta.get_field("name").clean(name, None)
            except forms.ValidationError as exc:
                self.add_error("role_definitions", f"Linha {line_number}: {exc.messages[0]}")
                continue
            if name in seen:
                self.add_error("role_definitions", f"Linha {line_number}: a role {name} está repetida.")
                continue
            seen.add(name)
            roles.append((name, description))
        data["parsed_roles"] = roles
        return data

    def save(self, commit=True):
        client = super().save(commit)
        if commit:
            ClientRole.objects.bulk_create(
                ClientRole(client=client, name=name, description=description)
                for name, description in self.cleaned_data["parsed_roles"]
            )
        return client

class ClientEditForm(ClientCreateForm):
    """Edição com o mesmo fluxo simplificado da criação e sincronização das roles."""

    rotate_secret = forms.BooleanField(
        required=False,
        label="Gerar novo client secret",
        help_text="O novo valor será exibido uma única vez após salvar. O secret anterior respeitará a janela de sobreposição configurada.",
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.instance.pk and not self.is_bound:
            self.fields["role_definitions"].initial = "\n".join(
                f"{role.name} | {role.description}" for role in self.instance.roles.all()
            )

    def save(self, commit=True):
        client = ClientForm.save(self, commit)
        if commit:
            names = []
            for name, description in self.cleaned_data["parsed_roles"]:
                ClientRole.objects.update_or_create(
                    client=client,
                    name=name,
                    defaults={"description": description},
                )
                names.append(name)
            client.roles.exclude(name__in=names).delete()
        return client

class ClientRoleForm(StyledFormMixin, forms.ModelForm):
    class Meta:
        model = ClientRole
        fields = ("client", "name", "description")

class SecurityPolicyForm(StyledFormMixin, forms.ModelForm):
    class Meta:
        model = SecurityPolicy
        fields = ("password_min_length","password_require_uppercase","password_require_lowercase","password_require_number","password_require_special","mfa_mode","access_token_ttl","id_token_ttl","refresh_token_ttl","sso_session_ttl","client_secret_grace_period","email_confirmation_timeout","email_confirmation_resend_seconds","password_reset_timeout","password_reset_resend_seconds","login_max_attempts","login_lockout_seconds","default_language","default_timezone","registration_enabled","registration_default_groups","audit_log_retention_days")
        labels = {"password_min_length":"Tamanho mínimo","password_require_uppercase":"Exigir letra maiúscula","password_require_lowercase":"Exigir letra minúscula","password_require_number":"Exigir número","password_require_special":"Exigir caractere especial","mfa_mode":"Política de autenticação em dois fatores","access_token_ttl":"Validade do access token","id_token_ttl":"Validade do ID token","refresh_token_ttl":"Validade máxima do refresh token","sso_session_ttl":"Validade da sessão SSO","client_secret_grace_period":"Sobreposição de secrets na rotação","email_confirmation_timeout":"Validade da confirmação de e-mail","email_confirmation_resend_seconds":"Intervalo mínimo de reenvio","password_reset_timeout":"Validade da recuperação de senha","password_reset_resend_seconds":"Intervalo mínimo entre recuperações","login_max_attempts":"Tentativas de senha antes do bloqueio","login_lockout_seconds":"Duração do bloqueio de login","default_language":"Idioma padrão","default_timezone":"Fuso horário padrão","registration_enabled":"Habilitar cadastro de novos usuários","registration_default_groups":"Grupos padrão do cadastro","audit_log_retention_days":"Retenção do log de auditoria"}
        help_texts = {"default_language":"Pré-selecionado ao cadastrar novos usuários.","default_timezone":"Pré-selecionado ao cadastrar novos usuários.","registration_enabled":"Exibe a tela pública de cadastro e permite que qualquer visitante crie a própria conta.","registration_default_groups":"Concedidos automaticamente a quem se cadastrar pela tela pública.","audit_log_retention_days":"Eventos mais antigos são apagados automaticamente na limpeza periódica."}


class EmailConfigurationForm(StyledFormMixin, forms.ModelForm):
    field_order = ("enabled", "host", "port", "username", "password", "use_tls", "use_ssl", "from_email", "clear_password")
    password = forms.CharField(required=False, label="Senha SMTP", widget=forms.PasswordInput(attrs={"autocomplete": "new-password"}), help_text="Deixe em branco para manter a senha cifrada já armazenada.")
    clear_password = forms.BooleanField(required=False, label="Remover senha SMTP armazenada")
    port = forms.IntegerField(required=False, min_value=1, max_value=65535, label="Porta SMTP")

    class Meta:
        model = EmailConfiguration
        fields = ("enabled", "host", "port", "username", "from_email", "use_tls", "use_ssl")
        labels = {
            "enabled": "Habilitar envio de e-mails",
            "host": "Servidor SMTP",
            "username": "Usuário SMTP",
            "from_email": "Remetente padrão",
            "use_tls": "Usar STARTTLS",
            "use_ssl": "Usar SSL/TLS direto",
        }
        help_texts = {
            "host": "Ex.: smtp.exemplo.com. Deixe vazio para não enviar mensagens.",
            "username": "Deixe vazio se o servidor não exigir autenticação.",
            "from_email": "Aceita o formato GateLite <no-reply@exemplo.com>.",
            "use_tls": "Criptografia negociada; padrão na porta 587.",
            "use_ssl": "Conexão cifrada direta; comum na porta 465.",
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["port"].initial = self.instance.port or 587

    def clean(self):
        data = super().clean()
        data["port"] = data.get("port") or self.instance.port or 587
        if data.get("use_tls") and data.get("use_ssl"):
            self.add_error("use_ssl", "STARTTLS e SSL/TLS direto não podem ser usados juntos.")
        if data.get("enabled") and not (data.get("host") or "").strip():
            self.add_error("host", "Informe o servidor SMTP para habilitar os envios.")
        if data.get("password") and data.get("clear_password"):
            self.add_error("clear_password", "Informe uma nova senha ou remova a senha armazenada, não ambos.")
        return data

    def save(self, commit=True):
        config = super().save(commit=False)
        password = self.cleaned_data.get("password")
        if password:
            config.set_password(password)
        elif self.cleaned_data.get("clear_password"):
            config.set_password("")
        if commit:
            config.save()
        return config

class MFASetupConfirmForm(StyledFormMixin, forms.Form):
    code=forms.RegexField(r"^\d{6}$",label="Código do aplicativo",widget=forms.TextInput(attrs={"inputmode":"numeric","autocomplete":"one-time-code","maxlength":"6"}))

class MFAChallengeForm(StyledFormMixin, forms.Form):
    code=forms.CharField(label="Código de autenticação",max_length=32,widget=forms.TextInput(attrs={"autocomplete":"one-time-code","autofocus":True}),help_text="Use o código de 6 dígitos ou um código de recuperação.")

class PasswordAndMFAForm(StyledFormMixin, forms.Form):
    password=forms.CharField(label="Senha atual",widget=forms.PasswordInput(attrs={"autocomplete":"current-password"}))
    code=forms.CharField(label="Código 2FA",max_length=32,widget=forms.TextInput(attrs={"autocomplete":"one-time-code"}))
    def __init__(self,user,*args,**kwargs): self.user=user; super().__init__(*args,**kwargs)
    def clean(self):
        data=super().clean()
        if data.get("password") and not self.user.check_password(data["password"]): self.add_error("password","Senha incorreta.")
        if not self.errors and data.get("code"):
            from .mfa import verify_mfa
            if not verify_mfa(self.user,data["code"]): self.add_error("code","Código inválido, expirado ou já utilizado.")
        return data
