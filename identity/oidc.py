import base64
import hashlib
import time
import secrets
import re
import jwt
from django.conf import settings
from django.contrib.auth.models import Permission
from django.db.models import Q
from django.db import IntegrityError, transaction
from django.utils import timezone
from .crypto import generate_key, private_pem
from .models import RefreshToken, SecurityPolicy, SigningKey

def active_key():
    key = SigningKey.objects.filter(active=True).first()
    if not key:
        kid, private, jwk = generate_key()
        try:
            with transaction.atomic(): key = SigningKey.objects.create(kid=kid, encrypted_private_key=private, public_jwk=jwk)
        except IntegrityError: key=SigningKey.objects.get(active=True)
    return key

def user_claims(user, client, scope):
    roles=client.effective_role_names(user)
    claims = {"sub": str(user.pk), "preferred_username": user.username,
              "roles":roles, "resource_access":{client.client_id:{"roles":roles}}}
    requested = set(scope.split())
    if "profile" in requested: claims.update({"name": user.get_full_name() or user.username, "given_name":user.first_name, "family_name":user.last_name})
    if "email" in requested:
        email_state=getattr(user,"email_state",None)
        claims.update({
            "email":user.email,
            "email_verified":bool(email_state and email_state.is_current_email_verified()),
        })
    if "groups" in requested: claims["groups"] = client.relevant_group_names(user)
    if "permissions" in requested: claims["permissions"] = roles
    return claims

def signed_token(user, client, scope, token_type="access", nonce="", audience=None, oidc_session=None):
    now = int(time.time()); key = active_key()
    policy=SecurityPolicy.load()
    ttl = policy.id_token_ttl if token_type == "id" else policy.access_token_ttl
    resource = client if token_type == "id" else (audience or client)
    roles=resource.effective_role_names(user)
    payload = {"iss":settings.OIDC_ISSUER, "sub":str(user.pk), "aud":resource.client_id, "azp":client.client_id, "jti":secrets.token_urlsafe(18), "iat":now, "exp":now+ttl, "scope":scope, "token_use":token_type, "roles":roles, "resource_access":{resource.client_id:{"roles":roles}}}
    if oidc_session:
        payload["sid"]=str(oidc_session.pk); payload["auth_time"]=int(oidc_session.auth_time.timestamp()); payload["amr"]=oidc_session.authentication_methods; payload["acr"]=oidc_session.acr
    if token_type == "id":
        payload.update(user_claims(user, client, scope))
        if nonce: payload["nonce"] = nonce
    return jwt.encode(payload, private_pem(key), algorithm="RS256", headers={"kid":key.kid})

def issue_tokens(user, client, scope, nonce="", include_refresh=True, audience=None, oidc_session=None, refresh_family=None, refresh_parent=None, refresh_expires_at=None):
    policy=SecurityPolicy.load()
    audience=audience or client
    result = {"access_token":signed_token(user, client, scope, audience=audience,oidc_session=oidc_session), "id_token":signed_token(user, client, scope, "id", nonce,oidc_session=oidc_session), "token_type":"Bearer", "expires_in":policy.access_token_ttl, "scope":scope}
    if include_refresh and client.refresh_token_enabled and "offline_access" in scope.split():
        kwargs={"client":client,"audience":audience,"user":user,"scope":scope,"oidc_session":oidc_session,"expires_at":refresh_expires_at or timezone.now()+timezone.timedelta(seconds=policy.refresh_token_ttl),"parent":refresh_parent}
        if refresh_family: kwargs["family_id"]=refresh_family
        result["refresh_token"] = RefreshToken.issue(**kwargs)
    return result

def issue_client_credentials_token(client, scope, audience=None):
    now=int(time.time()); key=active_key(); policy=SecurityPolicy.load()
    audience=audience or client
    # Client and expiration must match the same assignment. Keeping these
    # predicates in one filter prevents an active assignment from another
    # service account from making an expired assignment look valid.
    base_roles=audience.roles.filter(
        Q(service_assignments__service_client=client)
        & (Q(service_assignments__expires_at__isnull=True) | Q(service_assignments__expires_at__gt=timezone.now()))
    ).distinct()
    roles=audience.expand_role_names(base_roles)
    payload={"iss":settings.OIDC_ISSUER,"sub":f"client:{client.client_id}","aud":audience.client_id,"azp":client.client_id,"client_id":client.client_id,"jti":secrets.token_urlsafe(18),"iat":now,"exp":now+policy.access_token_ttl,"scope":scope,"token_use":"access","amr":["client_secret"],"acr":"urn:gatelite:acr:client","roles":roles,"resource_access":{audience.client_id:{"roles":roles}}}
    token=jwt.encode(payload,private_pem(key),algorithm="RS256",headers={"kid":key.kid})
    return {"access_token":token,"token_type":"Bearer","expires_in":policy.access_token_ttl,"scope":scope}

def verify_pkce(challenge, verifier, method):
    if not challenge: return True
    if method != "S256" or not verifier or not 43 <= len(verifier) <= 128 or not re.fullmatch(r"[A-Za-z0-9._~-]+",verifier): return False
    actual = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return secrets.compare_digest(actual,challenge)
