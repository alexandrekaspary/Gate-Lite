from django.http import HttpResponse
from django.utils.cache import patch_vary_headers
import base64
import jwt
from django.shortcuts import redirect
from django.urls import reverse
from django.utils import timezone
from urllib.parse import urlencode

class PasswordChangeRequiredMiddleware:
    def __init__(self,get_response): self.get_response=get_response
    def __call__(self,request):
        user=getattr(request,"user",None)
        exempt=request.path in ("/account/password/","/logout/") or request.path.startswith("/static/")
        if user and user.is_authenticated and not exempt:
            from .models import UserSecurityState
            if UserSecurityState.objects.filter(user=user,must_change_password=True).exists():
                request.session.setdefault("password_change_next",request.get_full_path())
                return redirect("change-own-password")
        return self.get_response(request)

class MFAEnforcementMiddleware:
    def __init__(self,get_response): self.get_response=get_response
    def __call__(self,request):
        user=getattr(request,"user",None); protected=request.path=="/" or request.path.startswith(("/console/","/admin/","/account/"))
        protocol_endpoint=request.path in (
            "/.well-known/openid-configuration", "/oidc/.well-known/openid-configuration",
            "/oidc/jwks/", "/oidc/token/", "/oidc/userinfo/", "/oidc/revoke/",
            "/oidc/introspect/", "/oidc/logout/",
        )
        exempt=protocol_endpoint or request.path.startswith((
            "/login/","/logout/","/account/2fa/","/account/email/confirm/",
            "/password/reset/","/static/",
        ))
        if user and user.is_authenticated and not exempt:
            from .models import SecurityPolicy, UserMFA
            from .views import create_mfa_challenge, is_admin_user
            policy=SecurityPolicy.load(); is_admin=is_admin_user(user)
            required=policy.mfa_mode==SecurityPolicy.MFAMode.ALL or (protected and policy.mfa_mode==SecurityPolicy.MFAMode.ADMINS and is_admin)
            mfa=UserMFA.objects.filter(user=user,enabled=True).first()
            state_version=str(user.security_state.authentication_version) if hasattr(user,"security_state") else None
            assurance_stale=request.session.get("mfa_verified_user_id")!=user.pk or (state_version and request.session.get("authentication_version")!=state_version)
            # Once a user enrolls a second factor, every interactive session
            # must prove it. This also invalidates password-only sessions that
            # existed before MFA was enabled or originated from another login
            # surface.
            if mfa and assurance_stale:
                auth_timestamp=request.session.get("authentication_time"); auth_time=timezone.datetime.fromtimestamp(auth_timestamp,tz=timezone.get_current_timezone()) if auth_timestamp else timezone.now()
                create_mfa_challenge(request,user,request.get_full_path(),auth_time)
                return redirect("login-2fa")
            if required and not mfa:
                return redirect(reverse("account-mfa-setup")+"?"+urlencode({"next":request.get_full_path()}))
        return self.get_response(request)

class OIDCCORSMiddleware:
    paths=("/oidc/token/","/oidc/userinfo/","/oidc/revoke/","/oidc/jwks/","/.well-known/openid-configuration","/oidc/.well-known/openid-configuration")
    def __init__(self,get_response): self.get_response=get_response
    def __call__(self,request):
        origin=request.headers.get("Origin","").rstrip("/")
        allowed=False
        if origin and request.path in self.paths:
            from .models import OIDCClient
            clients=OIDCClient.objects.filter(is_active=True,web_origins__origin=origin).distinct()
            client_id=request.GET.get("client_id")
            if request.method!="OPTIONS":
                if request.path in ("/oidc/token/","/oidc/revoke/"):
                    client_id=request.POST.get("client_id")
                    auth=request.headers.get("Authorization","")
                    if auth.startswith("Basic "):
                        try: client_id=base64.b64decode(auth[6:]).decode().split(":",1)[0]
                        except Exception: client_id=""
                elif request.path=="/oidc/userinfo/":
                    try: client_id=jwt.decode(request.headers.get("Authorization","").removeprefix("Bearer "),options={"verify_signature":False})["azp"]
                    except Exception: client_id=""
            allowed=clients.filter(client_id=client_id).exists() if client_id else clients.exists()
        if request.method=="OPTIONS" and allowed:
            response=HttpResponse(status=204)
        else: response=self.get_response(request)
        if request.path in ("/oidc/token/","/oidc/introspect/","/oidc/revoke/"):
            response["Cache-Control"]="no-store"; response["Pragma"]="no-cache"
        if request.path.startswith(("/login/2fa/","/account/2fa/")):
            response["Cache-Control"]="no-store"; response["Pragma"]="no-cache"; response["Referrer-Policy"]="no-referrer"
        if allowed:
            response["Access-Control-Allow-Origin"]=origin
            response["Access-Control-Allow-Methods"]="GET, POST, OPTIONS"
            response["Access-Control-Allow-Headers"]="Authorization, Content-Type"
            response["Access-Control-Max-Age"]="600"
            patch_vary_headers(response,["Origin"])
        return response
