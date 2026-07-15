import hashlib
import secrets
import base64
from urllib.parse import urlencode
import jwt
from django.conf import settings
from django.contrib import messages
from django.contrib.admin.views.decorators import staff_member_required
from django.contrib.auth import views as auth_views
from django.contrib.auth.decorators import login_required
from django.contrib.auth import update_session_auth_hash
from django.contrib.auth import login as auth_login
from django.contrib.auth.forms import AuthenticationForm, PasswordChangeForm
from django.contrib.auth.models import Group, Permission, User
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.crypto import constant_time_compare
from django.utils.http import base36_to_int
from django.utils.translation import gettext as _, ngettext
from django.core.exceptions import PermissionDenied
from django.core.paginator import Paginator
from django.db import transaction
from django.db.models import Q
from django.http import Http404, JsonResponse, HttpResponseBadRequest
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.urls import reverse_lazy
from django.utils import timezone, translation
from django.utils.dateparse import parse_date
from django.utils.http import url_has_allowed_host_and_scheme
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.cache import never_cache
from django.views.decorators.debug import sensitive_post_parameters
from django.views.decorators.http import require_http_methods, require_POST
from .crypto import generate_key
from .crypto import decrypt_value, encrypt_value
from .forms import AccountProfileForm, ClientForm, ClientRoleForm, EmailConfigurationForm, GroupForm, MFAChallengeForm, MFASetupConfirmForm, PasswordAndMFAForm, PermissionForm, SecurityPolicyForm, SecureSetPasswordForm, UserCreateForm, UserEditForm, UserRegistrationForm, VerifiedEmailPasswordResetForm
from .models import AuditEvent, AuthorizationCode, ClientRole, EmailConfiguration, GroupClientRoleAssignment, MFAChallenge, OIDCClient, OIDCScope, OIDCSession, RefreshToken, RevokedAccessToken, SecurityPolicy, ServiceAccountRoleAssignment, SigningKey, UserClientRoleAssignment, UserMFA, UserPreferences, UserSecurityState
from .email_verification import EmailAlreadyInUse, EmailConfirmationThrottled, InvalidEmailConfirmation, consume_confirmation_token, get_email_state, inspect_confirmation_token, mask_email, request_email_confirmation
from .email_backend import email_delivery_enabled
from .mfa import enable_mfa, generate_totp_secret, hash_recovery_codes, invalidate_web_sessions, matching_counter, provisioning_uri, qr_data_uri, generate_recovery_codes, record_mfa_failure, rotate_security_version, session_binding, verify_mfa
from .oidc import active_key, issue_client_credentials_token, issue_tokens, user_claims, verify_pkce

def oidc_error(error, description, status=400):
    response=JsonResponse({"error":error,"error_description":description},status=status)
    if error=="invalid_client": response["WWW-Authenticate"]='Basic realm="GateLite OIDC"'
    return response
def audit(request,action,target=None,metadata=None):
    AuditEvent.objects.create(actor=request.user if request.user.is_authenticated else None,action=action,target_type=target.__class__.__name__ if target else "system",target_id=str(getattr(target,"pk","")),metadata=metadata or {},ip_address=request.META.get("REMOTE_ADDR"))
def safe_next(request,value,default="account"):
    return value if value and url_has_allowed_host_and_scheme(value,{request.get_host()},require_https=request.is_secure()) else reverse(default)
def is_admin_user(user):
    return user.is_superuser or user.is_staff or any(user.has_perm(f"identity.{code}") for code in ("view_identity_console","manage_users","manage_groups","manage_clients","manage_security","manage_keys","manage_permissions","view_audit_log"))
def preferred_language(user):
    preferences=UserPreferences.objects.filter(user=user).first() if user and user.pk else None
    return (preferences.language if preferences else SecurityPolicy.load().default_language).lower()
def activate_user_language(request,user):
    language=preferred_language(user)
    translation.activate(language); request.LANGUAGE_CODE=translation.get_language()
    return request.LANGUAGE_CODE
def set_auth_assurance(request,auth_time,methods):
    state,_=UserSecurityState.objects.get_or_create(user=request.user)
    request.session["authentication_time"]=int(auth_time.timestamp()); request.session["authentication_methods"]=methods; request.session["authentication_acr"]="urn:gatelite:acr:2" if any(v in methods for v in ("otp","recovery")) else "urn:gatelite:acr:1"; request.session["authentication_version"]=str(state.authentication_version)
def create_mfa_challenge(request,user,next_url,auth_time=None):
    request.session.cycle_key()
    if not request.session.session_key: request.session.save()
    challenge=MFAChallenge.objects.create(user=user,session_binding=session_binding(request.session.session_key),password_session_hash=user.get_session_auth_hash(),next_url=next_url,auth_time=auth_time or timezone.now(),expires_at=timezone.now()+timezone.timedelta(minutes=5),ip_address=request.META.get("REMOTE_ADDR"))
    request.session["mfa_challenge_id"]=str(challenge.pk); return challenge

def login_view(request):
    if request.user.is_authenticated: return redirect("account")
    form=AuthenticationForm(request,data=request.POST or None)
    # A checagem de lockout precede a verificação de senha: uma conta bloqueada
    # não gasta hash nem permite continuar adivinhando durante a janela.
    registration_enabled=SecurityPolicy.load().registration_enabled
    if request.method=="POST" and UserSecurityState.objects.filter(user__username=request.POST.get("username",""),login_locked_until__gt=timezone.now()).exists():
        messages.error(request,_("Conta temporariamente bloqueada por excesso de tentativas. Tente novamente mais tarde."))
        return render(request,"registration/login.html",{"form":AuthenticationForm(request),"next":request.POST.get("next",""),"registration_enabled":registration_enabled},status=429)
    if request.method=="POST" and form.is_valid():
        user=form.get_user()
        requested_next=request.POST.get("next")
        # "next" só é respeitado para retomar um fluxo OIDC interrompido pelo login
        # (ex.: /oidc/authorize/), já que aplicações terceiras dependem desse retorno
        # para completar o SSO. Qualquer outro destino (páginas do console, sessão
        # expirada etc.) sempre cai em Minha conta.
        next_url=safe_next(request,requested_next) if requested_next and requested_next.startswith("/oidc/") else reverse("account")
        must_change_password=UserSecurityState.objects.filter(user=user,must_change_password=True).exists()
        mfa=UserMFA.objects.filter(user=user,enabled=True).first()
        if mfa:
            if mfa.locked_until and mfa.locked_until>timezone.now():
                activate_user_language(request,user); form.add_error(None,_("Segundo fator temporariamente bloqueado. Tente novamente mais tarde.")); return render(request,"registration/login.html",{"form":form,"next":request.POST.get("next","")},status=429)
            if must_change_password: request.session["password_change_next"]=next_url; next_url=reverse("change-own-password")
            create_mfa_challenge(request,user,next_url)
            return redirect("login-2fa")
        auth_login(request,user); set_auth_assurance(request,timezone.now(),["pwd"])
        if must_change_password:
            request.session["password_change_next"]=next_url
            activate_user_language(request,user); messages.info(request,_("Defina uma nova senha para continuar."))
            return redirect("change-own-password")
        policy=SecurityPolicy.load(); required=policy.mfa_mode==SecurityPolicy.MFAMode.ALL or (policy.mfa_mode==SecurityPolicy.MFAMode.ADMINS and is_admin_user(user))
        return redirect(reverse("account-mfa-setup")+"?"+urlencode({"next":next_url})) if required else redirect(next_url)
    return render(request,"registration/login.html",{"form":form,"next":request.POST.get("next") or request.GET.get("next",""),"registration_enabled":registration_enabled})

def admin_login_redirect(request):
    """Keep the Django Admin from becoming an alternate password-only login."""
    requested_next=request.GET.get("next") or request.POST.get("next")
    next_url=safe_next(request,requested_next) if requested_next else "/admin/"
    if request.user.is_authenticated: return redirect(next_url)
    return redirect(reverse("login")+"?"+urlencode({"next":next_url}))

def register_view(request):
    if request.user.is_authenticated: return redirect("account")
    policy=SecurityPolicy.load()
    if not policy.registration_enabled:
        messages.error(request,_("O cadastro de novos usuários está desativado no momento."))
        return redirect("login")
    form=UserRegistrationForm(request.POST or None)
    if request.method=="POST" and form.is_valid():
        user=form.save()
        audit(request,"user.self_registered",user)
        messages.success(request,_("Conta criada com sucesso. Entre com seu usuário e senha para continuar."))
        return redirect("login")
    return render(request,"registration/register.html",{"form":form,"password_policy":policy})

def login_2fa(request):
    challenge_id=request.session.get("mfa_challenge_id"); challenge=MFAChallenge.objects.select_related("user").filter(pk=challenge_id).first() if challenge_id else None
    valid_challenge=challenge and not challenge.consumed_at and challenge.expires_at>timezone.now() and challenge.user.is_active and secrets.compare_digest(challenge.password_session_hash,challenge.user.get_session_auth_hash()) and request.session.session_key and secrets.compare_digest(challenge.session_binding,session_binding(request.session.session_key))
    if not valid_challenge:
        request.session.pop("mfa_challenge_id",None)
        messages.error(request,_("A verificação expirou. Entre novamente.")); return redirect("login")
    user=challenge.user; form=MFAChallengeForm(request.POST or None)
    if request.method=="POST" and form.is_valid():
        method=verify_mfa(user,form.cleaned_data["code"])
        if method:
            challenge.consumed_at=timezone.now(); challenge.save(update_fields=["consumed_at"]); request.session.pop("mfa_challenge_id",None)
            auth_login(request,user); request.session["mfa_verified_user_id"]=user.pk; set_auth_assurance(request,challenge.auth_time,["pwd",method]); audit(request,"mfa.challenge_succeeded",user,{"method":method})
            if UserSecurityState.objects.filter(user=user,must_change_password=True).exists(): activate_user_language(request,user); messages.info(request,_("Defina uma nova senha para continuar."))
            return redirect(challenge.next_url)
        challenge.attempts+=1; challenge.save(update_fields=["attempts"]); record_mfa_failure(user)
        audit(request,"mfa.challenge_failed",user,{"attempt":challenge.attempts})
        if challenge.attempts>=5:
            challenge.consumed_at=timezone.now(); challenge.save(update_fields=["consumed_at"]); request.session.pop("mfa_challenge_id",None)
            activate_user_language(request,user); messages.error(request,_("Muitas tentativas inválidas. Entre novamente.")); return redirect("login")
        remaining=5-challenge.attempts
        activate_user_language(request,user)
        form.add_error("code",ngettext("Código inválido, expirado ou já utilizado. Resta %(count)s tentativa.","Código inválido, expirado ou já utilizado. Restam %(count)s tentativas.",remaining)%{"count":remaining})
    if challenge: activate_user_language(request,challenge.user)
    return render(request,"registration/login_2fa.html",{"form":form})
def decode_signed_token(raw, verify_audience=False, audience=None):
    # Aceita somente a chave ativa ou aposentadas dentro da janela de retenção,
    # espelhando o JWKS; uma chave rotacionada há muito tempo não verifica mais.
    header=jwt.get_unverified_header(raw); key=SigningKey.objects.filter(models_q_active_or_recent()).get(kid=header["kid"])
    return jwt.decode(raw,jwt.PyJWK(key.public_jwk).key,algorithms=["RS256"],issuer=settings.OIDC_ISSUER,audience=audience,options={"verify_aud":verify_audience})
def resolve_audience(client, audience_id):
    if not audience_id or audience_id == client.client_id: return client
    return client.allowed_audiences.filter(client_id=audience_id,is_active=True).first()
def client_auth(request):
    client_id = request.POST.get("client_id", ""); secret = request.POST.get("client_secret", "")
    auth = request.headers.get("Authorization", ""); used_method=OIDCClient.AuthMethod.NONE
    if auth.startswith("Basic "):
        import base64
        try: client_id, secret = base64.b64decode(auth[6:],validate=True).decode().split(":", 1); used_method=OIDCClient.AuthMethod.BASIC
        except Exception: return None
    elif secret: used_method=OIDCClient.AuthMethod.POST
    client = OIDCClient.objects.filter(client_id=client_id, is_active=True).first()
    if not client: return None
    if client.client_type == OIDCClient.ClientType.PUBLIC:
        if used_method != OIDCClient.AuthMethod.NONE: return None
    elif (client.token_endpoint_auth_method != OIDCClient.AuthMethod.LEGACY and used_method != client.token_endpoint_auth_method) or not client.check_secret(secret): return None
    return client

def discovery(request):
    i=settings.OIDC_ISSUER
    return JsonResponse({
        "issuer":i,"authorization_endpoint":f"{i}/oidc/authorize/","token_endpoint":f"{i}/oidc/token/",
        "userinfo_endpoint":f"{i}/oidc/userinfo/","jwks_uri":f"{i}/oidc/jwks/","revocation_endpoint":f"{i}/oidc/revoke/",
        "introspection_endpoint":f"{i}/oidc/introspect/","end_session_endpoint":f"{i}/oidc/logout/",
        "response_types_supported":["code"],"response_modes_supported":["query"],
        "grant_types_supported":["authorization_code","refresh_token","client_credentials"],"subject_types_supported":["public"],
        "id_token_signing_alg_values_supported":["RS256"],"scopes_supported":list(OIDCScope.objects.values_list("name",flat=True).order_by("name")),
        "claims_supported":["sub","name","given_name","family_name","preferred_username","email","email_verified","groups","permissions","roles","resource_access","azp","sid","auth_time","amr","acr"],
        "acr_values_supported":["urn:gatelite:acr:1","urn:gatelite:acr:2"],
        "token_endpoint_auth_methods_supported":["client_secret_basic","client_secret_post","none"],"revocation_endpoint_auth_methods_supported":["client_secret_basic","client_secret_post","none"],
        "introspection_endpoint_auth_methods_supported":["client_secret_basic","client_secret_post"],"code_challenge_methods_supported":["S256"],
    })

def jwks(request):
    active_key()
    return JsonResponse({"keys":[k.public_jwk for k in SigningKey.objects.filter(models_q_active_or_recent())]})
def models_q_active_or_recent():
    policy=SecurityPolicy.load(); retention=max(policy.access_token_ttl,policy.id_token_ttl)+300
    return Q(active=True) | Q(retired_at__gte=timezone.now()-timezone.timedelta(seconds=retention))

@login_required
def authorize(request):
    p=request.GET; client=OIDCClient.objects.filter(client_id=p.get("client_id"), is_active=True).first()
    redirect_uri=p.get("redirect_uri", "")
    if not client or redirect_uri not in client.uri_list(): return HttpResponseBadRequest("client_id ou redirect_uri inválido")
    audience=resolve_audience(client,p.get("audience"))
    if not audience:
        sep="&" if "?" in redirect_uri else "?"; return redirect(redirect_uri+sep+urlencode({"error":"invalid_target","state":p.get("state","")}))
    if not client.authorization_code_enabled:
        sep="&" if "?" in redirect_uri else "?"; return redirect(redirect_uri+sep+urlencode({"error":"unauthorized_client","state":p.get("state","")}))
    if not client.user_has_access(request.user):
        sep="&" if "?" in redirect_uri else "?"
        return redirect(redirect_uri+sep+urlencode({"error":"access_denied","error_description":"Usuário não autorizado para este client","state":p.get("state","")}))
    if audience != client and not audience.user_has_access(request.user):
        sep="&" if "?" in redirect_uri else "?"; return redirect(redirect_uri+sep+urlencode({"error":"access_denied","error_description":"Usuário não autorizado para o resource server","state":p.get("state","")}))
    if p.get("response_type") != "code":
        sep="&" if "?" in redirect_uri else "?"; return redirect(redirect_uri+sep+urlencode({"error":"unsupported_response_type","state":p.get("state","")}))
    scope=p.get("scope", "openid")
    if "openid" not in scope.split() or not set(scope.split()).issubset(set(client.scope_names())):
        sep="&" if "?" in redirect_uri else "?"; return redirect(redirect_uri+sep+urlencode({"error":"invalid_scope","state":p.get("state","")}))
    pkce_required=client.client_type==OIDCClient.ClientType.PUBLIC or client.require_pkce
    if (pkce_required and not p.get("code_challenge")) or (p.get("code_challenge") and p.get("code_challenge_method") != "S256"):
        sep="&" if "?" in redirect_uri else "?"
        return redirect(redirect_uri+sep+urlencode({"error":"invalid_request","error_description":"PKCE S256 é obrigatório para clients públicos","state":p.get("state","")}))
    policy=SecurityPolicy.load(); requested_acr=set(p.get("acr_values","").split()); configured_mfa=UserMFA.objects.filter(user=request.user,enabled=True).exists(); mfa_required=configured_mfa or client.require_mfa or audience.require_mfa or "urn:gatelite:acr:2" in requested_acr or policy.mfa_mode==SecurityPolicy.MFAMode.ALL or (policy.mfa_mode==SecurityPolicy.MFAMode.ADMINS and is_admin_user(request.user))
    if mfa_required and not configured_mfa:
        return redirect(reverse("account-mfa-setup")+"?"+urlencode({"next":request.get_full_path()}))
    if mfa_required and request.session.get("mfa_verified_user_id")!=request.user.pk:
        auth_timestamp=request.session.get("authentication_time"); auth_time=timezone.datetime.fromtimestamp(auth_timestamp,tz=timezone.get_current_timezone()) if auth_timestamp else timezone.now(); create_mfa_challenge(request,request.user,request.get_full_path(),auth_time); return redirect("login-2fa")
    auth_timestamp=request.session.get("authentication_time"); auth_time=timezone.datetime.fromtimestamp(auth_timestamp,tz=timezone.get_current_timezone()) if auth_timestamp else timezone.now(); methods=request.session.get("authentication_methods",["pwd"]); acr=request.session.get("authentication_acr","urn:gatelite:acr:1"); state,_=UserSecurityState.objects.get_or_create(user=request.user)
    oidc_session=OIDCSession.objects.create(user=request.user,client=client,audience=audience,auth_time=auth_time,authentication_methods=methods,acr=acr,authentication_version=state.authentication_version,expires_at=timezone.now()+timezone.timedelta(seconds=policy.sso_session_ttl))
    code=AuthorizationCode.issue(client=client,audience=audience,user=request.user,oidc_session=oidc_session,redirect_uri=redirect_uri,scope=scope,nonce=p.get("nonce", ""),code_challenge=p.get("code_challenge", ""),code_challenge_method=p.get("code_challenge_method", ""))
    sep="&" if "?" in redirect_uri else "?"
    return redirect(redirect_uri+sep+urlencode({"code":code,"state":p.get("state","")}))

@csrf_exempt
@require_POST
def token(request):
    client=client_auth(request)
    if not client: return oidc_error("invalid_client", "Credenciais do client inválidas", 401)
    grant=request.POST.get("grant_type")
    if grant == "authorization_code":
        if not client.authorization_code_enabled: return oidc_error("unauthorized_client", "Authorization Code desabilitado")
        digest=hashlib.sha256(request.POST.get("code", "").encode()).hexdigest()
        with transaction.atomic():
            code=AuthorizationCode.objects.select_for_update().filter(code_hash=digest, client=client).first()
            if not code or code.used_at or code.expires_at <= timezone.now(): return oidc_error("invalid_grant", "Código inválido ou expirado")
            if request.POST.get("redirect_uri") != code.redirect_uri or not verify_pkce(code.code_challenge, request.POST.get("code_verifier", ""), code.code_challenge_method): return oidc_error("invalid_grant", "redirect_uri ou PKCE inválido")
            if not client.user_has_access(code.user) or not code.audience.user_has_access(code.user): return oidc_error("access_denied", "Usuário não autorizado para este client ou audience", 403)
            if code.oidc_session and not code.oidc_session.is_active(): return oidc_error("invalid_grant","Sessão OIDC inválida")
            code.used_at=timezone.now(); code.save(update_fields=["used_at"])
        return JsonResponse(issue_tokens(code.user, client, code.scope, code.nonce, audience=code.audience,oidc_session=code.oidc_session))
    if grant == "refresh_token":
        if not client.refresh_token_enabled: return oidc_error("unauthorized_client", "Refresh Token desabilitado")
        digest=hashlib.sha256(request.POST.get("refresh_token", "").encode()).hexdigest()
        with transaction.atomic():
            old=RefreshToken.objects.select_for_update().filter(token_hash=digest, client=client).first()
            if not old or old.expires_at<=timezone.now(): return oidc_error("invalid_grant", "Refresh token inválido")
            if old.revoked_at:
                old.reuse_detected_at=timezone.now(); old.save(update_fields=["reuse_detected_at"])
                RefreshToken.objects.filter(family_id=old.family_id,revoked_at__isnull=True).update(revoked_at=timezone.now())
                if old.oidc_session: OIDCSession.objects.filter(pk=old.oidc_session_id).update(revoked_at=timezone.now())
                return oidc_error("invalid_grant","Reutilização de refresh token detectada; família revogada")
            if old.oidc_session and not old.oidc_session.is_active(): return oidc_error("invalid_grant","Sessão OIDC inválida")
            if not client.user_has_access(old.user) or not old.audience.user_has_access(old.user): return oidc_error("access_denied", "Usuário não autorizado para este client", 403)
            new_scope=request.POST.get("scope",old.scope)
            if not set(new_scope.split()).issubset(set(old.scope.split())): return oidc_error("invalid_scope","Refresh token não pode ampliar scopes")
            old.revoked_at=timezone.now(); old.save(update_fields=["revoked_at"])
        return JsonResponse(issue_tokens(old.user, client, new_scope, audience=old.audience,oidc_session=old.oidc_session,refresh_family=old.family_id,refresh_parent=old,refresh_expires_at=old.expires_at))
    if grant == "client_credentials":
        if client.client_type != OIDCClient.ClientType.CONFIDENTIAL or not client.client_credentials_enabled: return oidc_error("unauthorized_client", "Client Credentials desabilitado")
        scope=request.POST.get("scope", ""); allowed=set(client.scope_names())
        if not set(scope.split()).issubset(allowed): return oidc_error("invalid_scope", "Scope não permitido")
        audience=resolve_audience(client,request.POST.get("audience"))
        if not audience: return oidc_error("invalid_target","Audience não autorizada")
        return JsonResponse(issue_client_credentials_token(client,scope,audience))
    return oidc_error("unsupported_grant_type", "Grant type não suportado")

def userinfo(request):
    raw=request.headers.get("Authorization", "").removeprefix("Bearer ")
    try:
        payload=decode_signed_token(raw)
        if payload.get("token_use") != "access": raise ValueError()
        if RevokedAccessToken.objects.filter(jti=payload.get("jti","")).exists(): raise ValueError()
        if payload.get("sid") and not OIDCSession.objects.get(pk=payload["sid"]).is_active(): raise ValueError()
        user=User.objects.get(pk=payload["sub"], is_active=True)
        client=OIDCClient.objects.get(client_id=payload["aud"], is_active=True)
        caller=OIDCClient.objects.get(client_id=payload["azp"],is_active=True)
        if client != caller and not caller.allowed_audiences.filter(pk=client.pk).exists(): raise ValueError()
        if not client.user_has_access(user): raise ValueError()
        return JsonResponse(user_claims(user, client, payload.get("scope", "")))
    except Exception: return oidc_error("invalid_token", "Bearer token inválido", 401)

@csrf_exempt
@require_POST
def revoke(request):
    client=client_auth(request)
    if not client: return oidc_error("invalid_client","Credenciais do client inválidas",401)
    raw=request.POST.get("token",""); digest=hashlib.sha256(raw.encode()).hexdigest()
    refresh=RefreshToken.objects.filter(token_hash=digest,client=client).first()
    if refresh:
        RefreshToken.objects.filter(family_id=refresh.family_id,revoked_at__isnull=True).update(revoked_at=timezone.now())
        if refresh.oidc_session_id: OIDCSession.objects.filter(pk=refresh.oidc_session_id).update(revoked_at=timezone.now())
        return JsonResponse({})
    try:
        payload=decode_signed_token(raw)
        if payload.get("azp") != client.client_id: raise ValueError()
        RevokedAccessToken.objects.update_or_create(jti=payload["jti"],defaults={"expires_at":timezone.datetime.fromtimestamp(payload["exp"],tz=timezone.get_current_timezone())})
    except Exception: pass
    return JsonResponse({})

@csrf_exempt
@require_POST
def introspect(request):
    client=client_auth(request)
    if not client or client.client_type != OIDCClient.ClientType.CONFIDENTIAL: return oidc_error("invalid_client","Credenciais confidenciais obrigatórias",401)
    raw=request.POST.get("token",""); digest=hashlib.sha256(raw.encode()).hexdigest()
    refresh=RefreshToken.objects.filter(token_hash=digest,client=client,revoked_at__isnull=True,expires_at__gt=timezone.now()).select_related("user").first()
    if refresh and (not refresh.oidc_session or refresh.oidc_session.is_active()) and refresh.client.user_has_access(refresh.user) and refresh.audience.user_has_access(refresh.user): return JsonResponse({"active":True,"client_id":client.client_id,"sub":str(refresh.user_id),"username":refresh.user.username,"scope":refresh.scope,"token_type":"refresh_token","exp":int(refresh.expires_at.timestamp())})
    try:
        payload=decode_signed_token(raw,True,client.client_id)
        if payload.get("token_use") != "access": raise ValueError()
        if RevokedAccessToken.objects.filter(jti=payload.get("jti","")).exists(): raise ValueError()
        if payload.get("sid") and not OIDCSession.objects.get(pk=payload["sid"]).is_active(): raise ValueError()
        caller=OIDCClient.objects.get(client_id=payload["azp"],is_active=True)
        if caller != client and not caller.allowed_audiences.filter(pk=client.pk).exists(): raise ValueError()
        if not str(payload.get("sub","")).startswith("client:"):
            user=User.objects.get(pk=payload["sub"],is_active=True)
            if not client.user_has_access(user): raise ValueError()
        return JsonResponse({"active":True,**{k:v for k,v in payload.items() if k in ("sub","scope","exp","iat","jti","token_use","client_id","auth_time","amr","acr","sid")},"client_id":client.client_id,"token_type":"access_token"})
    except Exception: return JsonResponse({"active":False})

def end_session(request):
    from django.contrib.auth import logout
    uri=request.GET.get("post_logout_redirect_uri", ""); hint=request.GET.get("id_token_hint",""); client=None
    if hint:
        try:
            payload=decode_signed_token(hint); client=OIDCClient.objects.get(client_id=payload["azp"])
            if payload.get("sid"): OIDCSession.objects.filter(pk=payload["sid"]).update(revoked_at=timezone.now())
        except Exception: client=None
    if uri and (not client or uri not in client.uri_list("post_logout_redirect_uris")): uri=""
    if uri and request.GET.get("state"):
        sep="&" if "?" in uri else "?"; uri+=sep+urlencode({"state":request.GET["state"]})
    logout(request); return redirect(uri or "login")

@login_required
def account(request):
    sessions=OIDCSession.objects.filter(user=request.user,revoked_at__isnull=True,expires_at__gt=timezone.now()).select_related("client","audience")
    return render(request, "account/profile.html",{"oidc_sessions":sessions,"email_state":get_email_state(request.user)})


@login_required
def account_profile_edit(request):
    state=get_email_state(request.user)
    form=AccountProfileForm(request.POST or None,instance=request.user)
    if request.method=="POST" and form.is_valid():
        try:
            form.save(request=request)
        except EmailConfirmationThrottled as exc:
            messages.info(request,_("Uma confirmação já foi enviada. Aguarde %(seconds)s segundos para reenviar.")%{"seconds":exc.retry_after})
        except EmailAlreadyInUse:
            form.add_error("email",_("Este endereço de e-mail já está em uso."))
        except Exception:
            form.add_error("email",_("Não foi possível enviar a confirmação agora. Seus dados de nome foram salvos; tente reenviar em instantes."))
        else:
            audit(request,"profile.updated",request.user,{"email_confirmation_requested":bool(form.confirmation)})
            with translation.override(form.cleaned_data["language"].lower()):
                if form.confirmation:
                    notice=_("Dados salvos. Enviamos uma confirmação para o novo e-mail; o endereço atual permanece ativo até a confirmação.")
                else:
                    notice=_("Dados do perfil atualizados.")
            messages.success(request,notice)
            return redirect("account")
        if not form.errors:
            return redirect("account-profile-edit")
    state.refresh_from_db()
    return render(request,"account/profile_edit.html",{
        "form":form,
        "email_state":state,
        "pending_email":state.pending_email,
    },status=400 if request.method=="POST" and form.errors else 200)


@login_required
@require_POST
def account_email_resend(request):
    state=get_email_state(request.user)
    target=state.pending_email or request.user.email
    if not target:
        messages.error(request,_("Informe um endereço de e-mail antes de solicitar a confirmação."))
        return redirect("account-profile-edit")
    try:
        request_email_confirmation(
            request.user,target,request=request,actor=request.user,
            ip_address=request.META.get("REMOTE_ADDR"),
        )
    except EmailConfirmationThrottled as exc:
        messages.info(request,ngettext("A mensagem já foi enviada. Tente novamente em %(count)s segundo.","A mensagem já foi enviada. Tente novamente em %(count)s segundos.",exc.retry_after)%{"count":exc.retry_after})
    except EmailAlreadyInUse:
        messages.error(request,_("Esse endereço pertence a outra conta. Escolha outro e-mail."))
    except Exception:
        messages.error(request,_("Não foi possível enviar a mensagem. Verifique a configuração de e-mail e tente novamente."))
    else:
        if email_delivery_enabled():
            messages.success(request,_("Enviamos um novo link de confirmação."))
        else:
            messages.info(request,_("O envio de e-mails está desativado; nenhum link foi enviado."))
    return redirect("account-profile-edit")


@never_cache
@sensitive_post_parameters("token")
@require_http_methods(["GET","POST"])
def account_email_confirm(request):
    if request.method=="POST":
        raw_token=request.POST.get("token") or request.GET.get("token","")
    else:
        raw_token=request.GET.get("token","")
    if request.method=="POST":
        try:
            user=consume_confirmation_token(
                raw_token,actor=request.user if request.user.is_authenticated else None,
                ip_address=request.META.get("REMOTE_ADDR"),
            )
        except (EmailAlreadyInUse,InvalidEmailConfirmation):
            # Do not reveal whether an address, account, or expired token exists.
            AuditEvent.objects.create(
                action="email.confirmation_failed",target_type="system",
                ip_address=request.META.get("REMOTE_ADDR"),
            )
            response=render(request,"account/email_confirm.html",{
                "valid_token":False,"confirmed":False,
            },status=400)
        else:
            activate_user_language(request,user)
            response=render(request,"account/email_confirm.html",{
                "valid_token":True,"confirmed":True,
            })
    else:
        state=inspect_confirmation_token(raw_token)
        if state: activate_user_language(request,state.user)
        response=render(request,"account/email_confirm.html",{
            "valid_token":bool(state),
            "confirmed":False,
            "target_email":mask_email(state.pending_email) if state else "",
            "token":raw_token if state else "",
        })
    # "no-referrer" faz alguns navegadores enviarem Origin: null em submits de formulário
    # same-origin, o que quebra a checagem de CSRF do Django. "same-origin" já impede o
    # vazamento do Referer (com o token) para terceiros, sem esse efeito colateral.
    response["Referrer-Policy"]="same-origin"
    response["Cache-Control"]="no-store, no-cache, max-age=0, must-revalidate"
    response["Pragma"]="no-cache"
    return response


class PolicyPasswordResetTokenGenerator(PasswordResetTokenGenerator):
    """check_token do Django com a validade lida da política persistida no banco."""
    def check_token(self, user, token):
        if not (user and token):
            return False
        try:
            ts_b36, _ = token.split("-")
            ts = base36_to_int(ts_b36)
        except ValueError:
            return False
        for secret in [self.secret, *self.secret_fallbacks]:
            if constant_time_compare(self._make_token_with_timestamp(user, ts, secret), token):
                break
        else:
            return False
        return (self._num_seconds(self._now()) - ts) <= SecurityPolicy.load().password_reset_timeout


class VerifiedPasswordResetView(auth_views.PasswordResetView):
    form_class=VerifiedEmailPasswordResetForm
    template_name="registration/password_reset_form.html"
    email_template_name="registration/password_reset_email.txt"
    html_email_template_name="registration/password_reset_email.html"
    subject_template_name="registration/password_reset_subject.txt"
    success_url=reverse_lazy("password-reset-done")
    extra_email_context={"site_name":"GateLite"}

    def form_valid(self,form):
        self.from_email = EmailConfiguration.load().from_email or settings.DEFAULT_FROM_EMAIL
        response=super().form_valid(form)
        AuditEvent.objects.create(
            action="password.reset_requested",target_type="system",
            metadata={},ip_address=self.request.META.get("REMOTE_ADDR"),
        )
        return response


class VerifiedPasswordResetDoneView(auth_views.PasswordResetDoneView):
    template_name="registration/password_reset_done.html"


class SecurePasswordResetConfirmView(auth_views.PasswordResetConfirmView):
    form_class=SecureSetPasswordForm
    token_generator=PolicyPasswordResetTokenGenerator()
    template_name="registration/password_reset_confirm.html"
    success_url=reverse_lazy("password-reset-complete")

    def get_user(self,uidb64):
        user=super().get_user(uidb64)
        if user:
            language=activate_user_language(self.request,user)
            self.request.session["password_reset_language"]=language
        return user

    def get_context_data(self,**kwargs):
        context=super().get_context_data(**kwargs)
        context["password_policy"]=SecurityPolicy.load()
        return context

    def form_valid(self,form):
        user=form.user
        response=super().form_valid(form)
        AuditEvent.objects.create(
            action="password.reset_completed",target_type="User",target_id=str(user.pk),
            ip_address=self.request.META.get("REMOTE_ADDR"),
        )
        return response


class SecurePasswordResetCompleteView(auth_views.PasswordResetCompleteView):
    template_name="registration/password_reset_complete.html"

    def dispatch(self,request,*args,**kwargs):
        language=request.session.pop("password_reset_language",None)
        if language:
            translation.activate(language); request.LANGUAGE_CODE=translation.get_language()
        return super().dispatch(request,*args,**kwargs)

@login_required
def account_mfa(request):
    mfa=UserMFA.objects.filter(user=request.user,enabled=True).first()
    return render(request,"account/mfa_status.html",{"mfa":mfa,"disable_form":PasswordAndMFAForm(request.user) if mfa else None,"recovery_form":PasswordAndMFAForm(request.user) if mfa else None})

@login_required
def account_mfa_setup(request):
    if UserMFA.objects.filter(user=request.user,enabled=True).exists(): return redirect("account-mfa")
    if request.GET.get("next"): request.session["mfa_setup_next"]=safe_next(request,request.GET.get("next"))
    encrypted=request.session.get("mfa_setup_secret"); started=request.session.get("mfa_setup_started_at",0)
    if not started or int(timezone.now().timestamp())-started>600: encrypted=None
    try: secret=decrypt_value(base64.b64decode(encrypted),"pending-totp").decode() if encrypted else None
    except Exception: secret=None
    if not secret:
        secret=generate_totp_secret(); request.session["mfa_setup_secret"]=base64.b64encode(encrypt_value(secret.encode(),"pending-totp")).decode(); request.session["mfa_setup_started_at"]=int(timezone.now().timestamp())
    uri=provisioning_uri(request.user,secret); form=MFASetupConfirmForm(request.POST or None)
    if request.method=="POST" and form.is_valid():
        counter=matching_counter(secret,form.cleaned_data["code"])
        if counter is None: form.add_error("code",_("Código inválido. Confira o horário do dispositivo e tente novamente."))
        else:
            codes=enable_mfa(request.user,secret,counter); invalidate_web_sessions(request.user,request.session.session_key); request.session.pop("mfa_setup_secret",None); request.session.pop("mfa_setup_started_at",None); request.session["mfa_verified_user_id"]=request.user.pk; set_auth_assurance(request,timezone.now(),["pwd","otp"]); audit(request,"mfa.enabled",request.user)
            return render(request,"account/mfa_recovery.html",{"recovery_codes":codes,"new_setup":True,"next_url":request.session.pop("mfa_setup_next",reverse("account"))})
    return render(request,"account/mfa_setup.html",{"form":form,"secret":secret,"provisioning_uri":uri,"qr_data_uri":qr_data_uri(uri)})

@login_required
@require_POST
def account_mfa_disable(request):
    form=PasswordAndMFAForm(request.user,request.POST)
    if form.is_valid():
        rotate_security_version(request.user); invalidate_web_sessions(request.user,request.session.session_key); UserMFA.objects.filter(user=request.user).delete(); request.session.pop("mfa_verified_user_id",None); audit(request,"mfa.disabled",request.user); messages.success(request,_("Autenticação em dois fatores desativada.")); return redirect("account-mfa")
    mfa=UserMFA.objects.filter(user=request.user,enabled=True).first()
    return render(request,"account/mfa_status.html",{"mfa":mfa,"disable_form":form,"recovery_form":PasswordAndMFAForm(request.user)},status=400)

@login_required
@require_POST
def account_mfa_recovery(request):
    form=PasswordAndMFAForm(request.user,request.POST)
    if form.is_valid():
        codes=generate_recovery_codes(); mfa=get_object_or_404(UserMFA,user=request.user,enabled=True); mfa.recovery_code_hashes=hash_recovery_codes(codes); mfa.save(update_fields=["recovery_code_hashes","updated_at"]); rotate_security_version(request.user); invalidate_web_sessions(request.user,request.session.session_key); set_auth_assurance(request,timezone.now(),request.session.get("authentication_methods",["pwd","otp"])); audit(request,"mfa.recovery_codes_regenerated",request.user)
        return render(request,"account/mfa_recovery.html",{"recovery_codes":codes,"new_setup":False})
    mfa=UserMFA.objects.filter(user=request.user,enabled=True).first()
    return render(request,"account/mfa_status.html",{"mfa":mfa,"disable_form":PasswordAndMFAForm(request.user),"recovery_form":form},status=400)

@login_required
@require_POST
def revoke_own_session(request,pk):
    session=get_object_or_404(OIDCSession,pk=pk,user=request.user)
    session.revoked_at=timezone.now(); session.save(update_fields=["revoked_at"])
    RefreshToken.objects.filter(oidc_session=session,revoked_at__isnull=True).update(revoked_at=timezone.now())
    messages.success(request,_("Sessão da aplicação encerrada.")); return redirect("account")

@login_required
def change_own_password(request):
    if not request.user.has_perm("identity.change_own_password"):
        return JsonResponse({"error":"access_denied"}, status=403)
    policy = SecurityPolicy.load()
    must_change_password = UserSecurityState.objects.filter(user=request.user,must_change_password=True).exists()
    form = SecureSetPasswordForm(
        request.user, request.POST or None, keep_session_key=request.session.session_key,
    ) if must_change_password else PasswordChangeForm(request.user, request.POST or None)
    for field in form.fields.values(): field.widget.attrs["class"]="input"
    if request.method == "POST" and form.is_valid():
        user=form.save(); update_session_auth_hash(request,user)
        if not must_change_password:
            UserSecurityState.objects.filter(user=user,must_change_password=True).update(must_change_password=False)
            rotate_security_version(user)
        messages.success(request,_("Senha alterada com sucesso. As outras sessões foram encerradas."))
        return redirect(safe_next(request,request.session.pop("password_change_next",None)))
    template = "account/forced_password_change.html" if must_change_password else "account/password.html"
    return render(request,template,{"form":form,"password_policy":policy})

def require_console_permission(request,codename):
    if not (request.user.is_superuser or request.user.has_perm(f"identity.{codename}")): raise PermissionDenied
def has_any_console_permission(user):
    return user.is_superuser or any(user.has_perm(f"identity.{code}") for code in ("view_identity_console","manage_users","manage_groups","manage_clients","manage_security","manage_keys","manage_permissions","view_audit_log"))

@login_required
def dashboard(request):
    if not has_any_console_permission(request.user): raise PermissionDenied
    return render(request,"console/dashboard.html",{"users":User.objects.count(),"groups":Group.objects.count(),"clients":OIDCClient.objects.count(),"keys":SigningKey.objects.count()})

MODELS={"users":(User,UserCreateForm,UserEditForm,"Usuários"),"groups":(Group,GroupForm,GroupForm,"Grupos"),"permissions":(Permission,PermissionForm,PermissionForm,"Permissões"),"clients":(OIDCClient,ClientForm,ClientForm,"Clients OIDC"),"roles":(ClientRole,ClientRoleForm,ClientRoleForm,"Roles por client")}
@login_required
def object_list(request, kind):
    require_console_permission(request,{"users":"manage_users","groups":"manage_groups","clients":"manage_clients","roles":"manage_clients","permissions":"manage_permissions"}[kind])
    model,_,_,title=MODELS[kind]; objects=model.objects.all()
    if kind=="users": objects=objects.order_by("username")
    elif kind=="groups": objects=objects.order_by("name")
    elif kind=="permissions": objects=objects.order_by("content_type__app_label","codename")
    if kind=="permissions": objects=objects.select_related("content_type")
    if kind=="roles": objects=objects.select_related("client").prefetch_related("groups")
    if kind=="groups": objects=objects.prefetch_related("user_set", "oidc_client_roles")
    if kind=="users": objects=objects.prefetch_related("groups","direct_oidc_client_roles")
    if kind=="clients": objects=objects.prefetch_related("roles","scope_assignments__scope")
    query=request.GET.get("q", "").strip()
    if query:
        filters={"users":Q(username__icontains=query)|Q(email__icontains=query)|Q(first_name__icontains=query)|Q(last_name__icontains=query),"groups":Q(name__icontains=query),"clients":Q(name__icontains=query)|Q(client_id__icontains=query),"roles":Q(name__icontains=query)|Q(client__name__icontains=query),"permissions":Q(name__icontains=query)|Q(codename__icontains=query)}
        objects=objects.filter(filters[kind]).distinct()
    status=request.GET.get("status")
    if status in ("active","inactive") and kind in ("users","clients"): objects=objects.filter(is_active=status=="active")
    client_filter=request.GET.get("client")
    if client_filter and kind=="roles": objects=objects.filter(client_id=client_filter)
    page_obj=Paginator(objects,25).get_page(request.GET.get("page"))
    secret=request.session.pop("new_client_secret", None)
    return render(request,"console/list.html",{"objects":page_obj.object_list,"page_obj":page_obj,"kind":kind,"title":title,"new_client_secret":secret,"clients_filter":OIDCClient.objects.all() if kind=="roles" else None})
@login_required
def object_form(request, kind, pk=None):
    require_console_permission(request,{"users":"manage_users","groups":"manage_groups","clients":"manage_clients","roles":"manage_clients","permissions":"manage_permissions"}[kind])
    model,create_form,edit_form,title=MODELS[kind]; obj=get_object_or_404(model,pk=pk) if pk else None; form_class=edit_form if obj else create_form
    form=form_class(request.POST or None, instance=obj)
    if kind=="users": form.request=request
    if form.is_valid():
        item=form.save()
        if kind=="roles":
            UserClientRoleAssignment.objects.filter(role=item,assigned_by__isnull=True).update(assigned_by=request.user); GroupClientRoleAssignment.objects.filter(role=item,assigned_by__isnull=True).update(assigned_by=request.user); ServiceAccountRoleAssignment.objects.filter(role=item,assigned_by__isnull=True).update(assigned_by=request.user)
        elif kind=="users": UserClientRoleAssignment.objects.filter(user=item,assigned_by__isnull=True).update(assigned_by=request.user)
        elif kind=="groups": GroupClientRoleAssignment.objects.filter(group=item,assigned_by__isnull=True).update(assigned_by=request.user)
        if kind=="clients" and item.client_type==OIDCClient.ClientType.PUBLIC:
            item.secrets.filter(revoked_at__isnull=True).update(revoked_at=timezone.now())
        elif kind=="clients" and (not obj or form.cleaned_data.get("generate_secret")):
            raw=secrets.token_urlsafe(40); item.set_secret(raw); request.session["new_client_secret"]=raw
        audit(request,f"{kind}.{'updated' if obj else 'created'}",item)
        if getattr(form,"email_confirmation_error",None):
            messages.warning(request,"Registro salvo, mas o novo e-mail permanece pendente: "+form.email_confirmation_error)
        else:
            messages.success(request,"Registro salvo com sucesso.")
        return redirect("console:list",kind=kind)
    return render(request,"console/form.html",{"form":form,"object":obj,"kind":kind,"title":title})
@login_required
@require_POST
def object_delete(request, kind, pk):
    require_console_permission(request,{"users":"manage_users","groups":"manage_groups","clients":"manage_clients","roles":"manage_clients","permissions":"manage_permissions"}[kind])
    model,*_=MODELS[kind]; item=get_object_or_404(model,pk=pk); audit(request,f"{kind}.deleted",item,{"label":str(item)}); item.delete(); messages.success(request,"Registro removido."); return redirect("console:list",kind=kind)
@login_required
def keys(request):
    require_console_permission(request,"manage_keys"); return render(request,"console/keys.html",{"keys":SigningKey.objects.all()})
@login_required
@require_POST
def rotate_key(request):
    require_console_permission(request,"manage_keys")
    with transaction.atomic():
        SigningKey.objects.select_for_update().filter(active=True).update(active=False,retired_at=timezone.now()); kid,private,jwk=generate_key(); SigningKey.objects.create(kid=kid,encrypted_private_key=private,public_jwk=jwk)
    audit(request,"signing_key.rotated",metadata={"kid":kid}); messages.success(request,"Nova chave de assinatura ativada."); return redirect("console:keys")

@login_required
def audit_log(request):
    require_console_permission(request,"view_audit_log")
    events=AuditEvent.objects.select_related("actor")
    query=request.GET.get("q","").strip()
    if query:
        events=events.filter(Q(action__icontains=query)|Q(actor__username__icontains=query)|Q(target_type__icontains=query)|Q(target_id__icontains=query)|Q(ip_address__icontains=query))
    action=request.GET.get("action","").strip()
    if action: events=events.filter(action=action)
    date_from=parse_date(request.GET.get("from","")); date_to=parse_date(request.GET.get("to",""))
    if date_from: events=events.filter(created_at__date__gte=date_from)
    if date_to: events=events.filter(created_at__date__lte=date_to)
    page_obj=Paginator(events,50).get_page(request.GET.get("page"))
    actions=AuditEvent.objects.order_by("action").values_list("action",flat=True).distinct()
    return render(request,"console/audit.html",{
        "page_obj":page_obj,"events":page_obj.object_list,"actions":actions,
        "retention_days":SecurityPolicy.load().audit_log_retention_days,
    })

# Documentação embutida do console: páginas Markdown versionadas em docs/console/.
DOCS_PAGES = {
    "index": ("Visão geral", "O sistema, os conceitos e o mapa da documentação"),
    "primeiros-passos": ("Primeiros passos", "A ordem recomendada para configurar um ambiente novo"),
    "usuarios": ("Usuários", "Criação, campos, permissões e comportamentos automáticos"),
    "grupos": ("Grupos", "Acessos compartilhados, herança e boas práticas"),
    "clients": ("Clients", "Aplicações OIDC: tipos, fluxos, URLs, scopes e secrets"),
    "roles": ("Roles", "Autorizações por client, composição e atribuições"),
    "configuracoes": ("Configurações", "Cada item da política de segurança, tokens e chaves"),
    "auditoria": ("Auditoria", "Eventos registrados, filtros e retenção do log"),
    "integracao": ("Integração OIDC", "Endpoints, exemplos de código e validação de JWT"),
}

@login_required
def docs_page(request, slug="index"):
    if not has_any_console_permission(request.user): raise PermissionDenied
    if slug not in DOCS_PAGES: raise Http404
    import re as re_module
    import markdown as markdown_module
    source = (settings.BASE_DIR / "docs" / "console" / f"{slug}.md").read_text(encoding="utf-8")
    html = markdown_module.markdown(
        source,
        extensions=["extra", "codehilite"],
        extension_configs={"codehilite": {"css_class": "codehilite", "guess_lang": False}},
    )
    # Links internos entre páginas ("clients", "roles"…) viram URLs do console.
    html = re_module.sub(
        r'href="([a-z-]+)"',
        lambda m: f'href="{reverse("console:docs-page", args=[m.group(1)])}"' if m.group(1) in DOCS_PAGES else m.group(0),
        html,
    )
    title, description = DOCS_PAGES[slug]
    pages = [{"slug": s, "title": t, "description": d, "active": s == slug} for s, (t, d) in DOCS_PAGES.items()]
    return render(request, "console/docs.html", {"content": html, "doc_title": title, "doc_description": description, "pages": pages})

@login_required
@sensitive_post_parameters("password")
def settings_panel(request):
    if not (request.user.is_superuser or any(request.user.has_perm(f"identity.{code}") for code in ("manage_security","manage_keys","manage_permissions"))): raise PermissionDenied
    if request.method=="POST": require_console_permission(request,"manage_security")
    policy=SecurityPolicy.load(); email_configuration=EmailConfiguration.load()
    form=SecurityPolicyForm(request.POST or None,instance=policy)
    email_form=EmailConfigurationForm(request.POST if request.POST.get("email_settings_submitted") else None,instance=email_configuration)
    if request.method=="POST" and form.is_valid() and email_form.is_valid():
        item=form.save()
        if email_form.is_bound:
            email_form.save()
            audit(request,"email_configuration.updated",email_configuration)
        audit(request,"security_policy.updated",item); messages.success(request,"Configurações atualizadas com sucesso."); return redirect("console:settings")
    return render(request,"console/settings.html",{"form":form,"email_form":email_form,"email_configuration":email_configuration,"keys":SigningKey.objects.all()})
