import base64
import hashlib
import json
import secrets
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from django.conf import settings

def _b64(data): return base64.urlsafe_b64encode(data).rstrip(b"=").decode()
def _integer(value): return _b64(value.to_bytes((value.bit_length()+7)//8, "big"))
def _master_key(): return hashlib.sha256(settings.KEY_ENCRYPTION_SECRET.encode()).digest()

def encrypt_value(data, purpose):
    nonce=secrets.token_bytes(12); aad=f"gatelite:{purpose}:v1".encode()
    return nonce+AESGCM(_master_key()).encrypt(nonce,data,aad)

def decrypt_value(data, purpose):
    raw=bytes(data); aad=f"gatelite:{purpose}:v1".encode()
    return AESGCM(_master_key()).decrypt(raw[:12],raw[12:],aad)

def encrypt(data):
    nonce = secrets.token_bytes(12)
    return nonce + AESGCM(_master_key()).encrypt(nonce, data, b"gatelite-signing-key-v1")

def decrypt(data):
    raw = bytes(data)
    return AESGCM(_master_key()).decrypt(raw[:12], raw[12:], b"gatelite-signing-key-v1")

def generate_key():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    numbers = key.public_key().public_numbers()
    kid = secrets.token_urlsafe(16)
    return kid, encrypt(private), {"kty":"RSA", "use":"sig", "alg":"RS256", "kid":kid, "n":_integer(numbers.n), "e":_integer(numbers.e)}

def private_pem(signing_key): return decrypt(signing_key.encrypted_private_key)
