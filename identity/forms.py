import secrets
import re
from urllib.parse import urlsplit
from django import forms
from django.contrib.auth.forms import PasswordResetForm, SetPasswordForm, UserCreationForm
from django.contrib.auth.models import Group, Permission, User
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.utils import timezone
from .email_verification import EmailConfirmationError, EmailConfirmationThrottled, email_available_for_user, normalize_email, request_email_confirmation
from .models import ClientRole, ClientScopeAssignment, ClientURI, ClientWebOrigin, OIDCClient, OIDCScope, SecurityPolicy, UserEmailState, UserSecurityState

def grant_basic_permissions(user):
    user.user_permissions.add(*Permission.objects.filter(
        content_type__app_label="identity",
        codename__in=("view_own_profile", "change_own_password"),
    ))

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
    field_order = ("username","first_name","last_name","email","password1","password2","must_change_password","basic_access","groups","client_roles","is_active","is_staff","user_permissions")
    basic_access = forms.CharField(required=False, disabled=True, initial="Perfil próprio e alteração da própria senha", label="Acesso básico")
    email = forms.EmailField(required=False)
    must_change_password = forms.BooleanField(required=False, initial=True, label="Exigir troca de senha no próximo login", help_text="Restringe o acesso do usuário até que ele defina uma nova senha.")
    groups = forms.ModelMultipleChoiceField(Group.objects.all(), required=False)
    client_roles = forms.ModelMultipleChoiceField(ClientRole.objects.select_related("client").order_by("client__name","name"), required=False, label="Roles diretas de clients", help_text="Atribua somente exceções; prefira roles herdadas por grupos.")
    user_permissions = forms.ModelMultipleChoiceField(Permission.objects.select_related("content_type").exclude(content_type__app_label="identity", codename__in=("view_own_profile","change_own_password")), required=False, label="Permissões administrativas")
    class Meta(UserCreationForm.Meta): fields = ("username", "first_name", "last_name", "email", "must_change_password", "basic_access", "groups", "client_roles", "is_active", "is_staff", "user_permissions")
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
        return user

class UserEditForm(StyledFormMixin, forms.ModelForm):
    basic_access = forms.CharField(required=False, disabled=True, initial="Perfil próprio e alteração da própria senha", label="Acesso básico")
    new_password = forms.CharField(required=False, widget=forms.PasswordInput(attrs={"autocomplete": "new-password"}), label="Nova senha", help_text="Deixe em branco para manter a senha atual.")
    new_password_confirmation = forms.CharField(required=False, widget=forms.PasswordInput(attrs={"autocomplete": "new-password"}), label="Confirme a nova senha")
    must_change_password = forms.BooleanField(required=False, label="Exigir troca de senha no próximo login", help_text="Restringe o acesso do usuário até que ele defina uma nova senha.")
    user_permissions = forms.ModelMultipleChoiceField(Permission.objects.select_related("content_type").exclude(content_type__app_label="identity", codename__in=("view_own_profile","change_own_password")), required=False, label="Permissões administrativas")
    client_roles = forms.ModelMultipleChoiceField(ClientRole.objects.select_related("client").order_by("client__name","name"), required=False, label="Roles diretas de clients", help_text="Somadas às roles herdadas pelos grupos.")
    reset_mfa = forms.BooleanField(required=False,label="Redefinir 2FA",help_text="Remove o autenticador e códigos de recuperação cadastrados.")
    class Meta:
        model = User
        fields = ("username", "first_name", "last_name", "email", "new_password", "new_password_confirmation", "must_change_password", "basic_access", "groups", "client_roles", "is_active", "is_staff", "is_superuser", "user_permissions", "reset_mfa")
        widgets = {"groups": forms.SelectMultiple(), "user_permissions": forms.SelectMultiple()}
    def __init__(self, *args, **kwargs):
        instance=kwargs.get("instance")
        self._original_email=(instance.email if instance else "") or ""
        super().__init__(*args, **kwargs)
        if self.instance.pk:
            self.fields["client_roles"].initial = self.instance.direct_oidc_client_roles.all()
            state, _ = UserSecurityState.objects.get_or_create(user=self.instance)
            self.fields["must_change_password"].initial = state.must_change_password
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


class AccountProfileForm(StyledFormMixin, forms.ModelForm):
    email=forms.EmailField(required=True,label="E-mail")

    class Meta:
        model=User
        fields=("first_name","last_name","email")
        labels={"first_name":"Nome","last_name":"Sobrenome"}

    def __init__(self,*args,**kwargs):
        instance=kwargs.get("instance")
        self._original_email=(instance.email if instance else "") or ""
        super().__init__(*args,**kwargs)

    def clean_email(self):
        email=normalize_email(self.cleaned_data["email"])
        if not email_available_for_user(email,self.instance):
            raise forms.ValidationError("Este endereço de e-mail já está em uso.")
        return email

    def save(self, commit=True, request=None):
        current_email=self._original_email.strip().casefold()
        requested_email=self.cleaned_data["email"]
        user=super().save(commit=False)
        user.email=self._original_email
        if commit:
            user.save(update_fields=["first_name","last_name"])
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
    def __init__(self,*args,**kwargs):
        super().__init__(*args,**kwargs)
        self.fields["generate_secret"].initial=not bool(self.instance.pk)
        if self.instance.pk:
            self.fields["redirect_uris"].initial="\n".join(self.instance.uri_list())
            self.fields["post_logout_redirect_uris"].initial="\n".join(self.instance.uri_list("post_logout_redirect_uris"))
            self.fields["allowed_origins"].initial="\n".join(self.instance.origin_list())
            self.fields["scopes"].initial=" ".join(self.instance.scope_names())
    @staticmethod
    def _lines(value): return list(dict.fromkeys(line.strip() for line in value.splitlines() if line.strip()))
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
        if app_type in (OIDCClient.ApplicationType.SPA,OIDCClient.ApplicationType.NATIVE) and data.get("client_type")!=OIDCClient.ClientType.PUBLIC: self.add_error("client_type","SPA e aplicativos nativos devem ser clients públicos.")
        if app_type in (OIDCClient.ApplicationType.SERVICE,OIDCClient.ApplicationType.RESOURCE) and data.get("client_type")!=OIDCClient.ClientType.CONFIDENTIAL: self.add_error("client_type","Services e resource servers devem ser confidenciais.")
        redirects=self._lines(data.get("redirect_uris", "")); origins=self._lines(data.get("allowed_origins", "")); logouts=self._lines(data.get("post_logout_redirect_uris", ""))
        if data.get("authorization_code_enabled") and not redirects: self.add_error("redirect_uris","Informe ao menos uma Redirect URI para Authorization Code.")
        for field,values,is_origin in (("redirect_uris",redirects,False),("post_logout_redirect_uris",logouts,False),("allowed_origins",origins,True)):
            try: data[field]="\n".join(dict.fromkeys(self._validate_uri(v,is_origin) for v in values))
            except forms.ValidationError as exc: self.add_error(field,exc)
        scope_names=list(dict.fromkeys(re.findall(r"[A-Za-z0-9_.:-]+",data.get("scopes", ""))))
        if data.get("authorization_code_enabled") and "openid" not in scope_names: self.add_error("scopes","Authorization Code OIDC exige o scope openid.")
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

class ClientRoleForm(StyledFormMixin, forms.ModelForm):
    groups=forms.ModelMultipleChoiceField(Group.objects.order_by("name"),required=False,label="Grupos")
    users=forms.ModelMultipleChoiceField(User.objects.order_by("username"),required=False,label="Usuários diretos")
    service_clients=forms.ModelMultipleChoiceField(OIDCClient.objects.order_by("name"),required=False,label="Service accounts",help_text="Clients que recebem esta role via Client Credentials.")
    composites=forms.ModelMultipleChoiceField(ClientRole.objects.select_related("client").order_by("client__name","name"),required=False,label="Roles compostas",help_text="Inclui automaticamente as roles selecionadas.")
    class Meta: model = ClientRole; fields = ("client", "name", "description", "is_default")
    def __init__(self,*args,**kwargs):
        super().__init__(*args,**kwargs)
        if self.instance.pk:
            self.fields["groups"].initial=self.instance.groups.all()
            self.fields["users"].initial=self.instance.users.all()
            self.fields["service_clients"].initial=self.instance.service_clients.all()
            self.fields["composites"].initial=self.instance.composites.all()
    def clean(self):
        data=super().clean(); client=data.get("client"); composites=data.get("composites")
        if client and composites and composites.exclude(client=client).exists(): self.add_error("composites","Roles compostas devem pertencer ao mesmo client.")
        if self.instance.pk and composites and composites.filter(pk=self.instance.pk).exists(): self.add_error("composites","Uma role não pode incluir a si mesma.")
        if self.instance.pk and composites:
            frontier=set(composites.values_list("pk",flat=True)); visited=set()
            while frontier:
                if self.instance.pk in frontier: self.add_error("composites","A composição criaria um ciclo entre roles."); break
                visited.update(frontier); frontier=set(ClientRole.objects.filter(pk__in=frontier).values_list("composites__pk",flat=True))-visited; frontier.discard(None)
        return data
    def save(self,commit=True):
        role=super().save(commit)
        if commit:
            role.groups.set(self.cleaned_data["groups"]); role.users.set(self.cleaned_data["users"]); role.service_clients.set(self.cleaned_data["service_clients"]); role.composites.set(self.cleaned_data["composites"])
        return role

class SecurityPolicyForm(StyledFormMixin, forms.ModelForm):
    class Meta:
        model = SecurityPolicy
        fields = ("password_min_length","password_require_uppercase","password_require_lowercase","password_require_number","password_require_special","mfa_mode","access_token_ttl","id_token_ttl","refresh_token_ttl","sso_session_ttl","client_secret_grace_period","email_confirmation_timeout","email_confirmation_resend_seconds","password_reset_timeout","password_reset_resend_seconds","login_max_attempts","login_lockout_seconds")
        labels = {"password_min_length":"Tamanho mínimo","password_require_uppercase":"Exigir letra maiúscula","password_require_lowercase":"Exigir letra minúscula","password_require_number":"Exigir número","password_require_special":"Exigir caractere especial","mfa_mode":"Política de autenticação em dois fatores","access_token_ttl":"Validade do access token","id_token_ttl":"Validade do ID token","refresh_token_ttl":"Validade máxima do refresh token","sso_session_ttl":"Validade da sessão SSO","client_secret_grace_period":"Sobreposição de secrets na rotação","email_confirmation_timeout":"Validade da confirmação de e-mail","email_confirmation_resend_seconds":"Intervalo mínimo de reenvio","password_reset_timeout":"Validade da recuperação de senha","password_reset_resend_seconds":"Intervalo mínimo entre recuperações","login_max_attempts":"Tentativas de senha antes do bloqueio","login_lockout_seconds":"Duração do bloqueio de login"}

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
