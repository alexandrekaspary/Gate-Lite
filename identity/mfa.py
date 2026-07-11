import base64
import hashlib
import hmac
import io
import secrets
import struct
import time
from urllib.parse import quote, urlencode

import qrcode
import qrcode.image.svg
from django.conf import settings
from django.contrib.auth.hashers import check_password, make_password
from django.db import transaction
from django.utils import timezone

ALPHABET="23456789ABCDEFGHJKLMNPQRSTUVWXYZ"

def generate_totp_secret():
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")

def _secret_bytes(secret):
    return base64.b32decode(secret+"="*((8-len(secret)%8)%8),casefold=True)

def totp_code(secret,counter):
    digest=hmac.new(_secret_bytes(secret),struct.pack(">Q",counter),hashlib.sha1).digest()
    offset=digest[-1]&15; value=(struct.unpack(">I",digest[offset:offset+4])[0]&0x7fffffff)%1_000_000
    return f"{value:06d}"

def matching_counter(secret,code,at_time=None,window=1):
    normalized="".join(ch for ch in str(code) if ch.isdigit())
    if len(normalized)!=6: return None
    current=int((at_time if at_time is not None else time.time())//30)
    for counter in range(current-window,current+window+1):
        if hmac.compare_digest(totp_code(secret,counter),normalized): return counter
    return None

def provisioning_uri(user,secret):
    issuer="GateLite"; account=user.email or user.username
    label=quote(f"{issuer}:{account}",safe="")
    return f"otpauth://totp/{label}?"+urlencode({"secret":secret,"issuer":issuer,"algorithm":"SHA1","digits":6,"period":30})

def qr_data_uri(uri):
    image=qrcode.make(uri,image_factory=qrcode.image.svg.SvgPathImage,box_size=7,border=2)
    output=io.BytesIO(); image.save(output)
    return "data:image/svg+xml;base64,"+base64.b64encode(output.getvalue()).decode()

def generate_recovery_codes(count=10):
    return ["-".join("".join(secrets.choice(ALPHABET) for _ in range(4)) for _ in range(5)) for _ in range(count)]

def hash_recovery_codes(codes): return [make_password(code.replace("-","").upper()) for code in codes]

def enable_mfa(user,secret,counter):
    from .models import UserMFA
    codes=generate_recovery_codes(); mfa,_=UserMFA.objects.get_or_create(user=user,defaults={"encrypted_secret":b""})
    mfa.set_secret(secret); mfa.enabled=True; mfa.verified_at=timezone.now(); mfa.last_used_counter=counter; mfa.recovery_code_hashes=hash_recovery_codes(codes); mfa.save()
    rotate_security_version(user)
    return codes

def verify_mfa(user,code):
    from .models import UserMFA
    with transaction.atomic():
        mfa=UserMFA.objects.select_for_update().filter(user=user,enabled=True).first()
        if not mfa or (mfa.locked_until and mfa.locked_until>timezone.now()): return False
        normalized=str(code).strip().replace(" ","").replace("-","").upper()
        if normalized.isdigit() and len(normalized)==6:
            counter=matching_counter(mfa.get_secret(),normalized)
            if counter is None or counter<=mfa.last_used_counter: return False
            mfa.last_used_counter=counter; mfa.failed_attempts=0; mfa.locked_until=None; mfa.save(update_fields=["last_used_counter","failed_attempts","locked_until","updated_at"]); return "otp"
        for index,hashed in enumerate(mfa.recovery_code_hashes):
            if check_password(normalized,hashed):
                codes=list(mfa.recovery_code_hashes); codes.pop(index); mfa.recovery_code_hashes=codes; mfa.failed_attempts=0; mfa.locked_until=None; mfa.save(update_fields=["recovery_code_hashes","failed_attempts","locked_until","updated_at"]); return "recovery"
        return False

def record_mfa_failure(user,max_attempts=5,lock_seconds=300):
    from .models import UserMFA
    with transaction.atomic():
        mfa=UserMFA.objects.select_for_update().filter(user=user,enabled=True).first()
        if not mfa: return 0
        mfa.failed_attempts+=1
        if mfa.failed_attempts>=max_attempts: mfa.locked_until=timezone.now()+timezone.timedelta(seconds=lock_seconds); mfa.failed_attempts=0
        mfa.save(update_fields=["failed_attempts","locked_until","updated_at"]); return mfa.failed_attempts

def rotate_security_version(user):
    import uuid
    from .models import OIDCSession, RefreshToken, UserSecurityState
    state,_=UserSecurityState.objects.get_or_create(user=user); state.authentication_version=uuid.uuid4(); state.save(update_fields=["authentication_version","updated_at"])
    OIDCSession.objects.filter(user=user,revoked_at__isnull=True).update(revoked_at=timezone.now())
    RefreshToken.objects.filter(user=user,revoked_at__isnull=True).update(revoked_at=timezone.now())
    return state.authentication_version

def session_binding(session_key): return hashlib.sha256(session_key.encode()).hexdigest()

def invalidate_web_sessions(user,keep_session_key=None):
    from django.contrib.sessions.models import Session
    for session in Session.objects.filter(expire_date__gt=timezone.now()).iterator():
        try: belongs=str(session.get_decoded().get("_auth_user_id"))==str(user.pk)
        except Exception: belongs=False
        if belongs and session.session_key!=keep_session_key: session.delete()
