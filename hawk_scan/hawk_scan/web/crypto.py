import base64
import json
import os
import hashlib
from cryptography.fernet import Fernet


def _derive_key(secret: str, salt: bytes) -> bytes:
    dk = hashlib.pbkdf2_hmac("sha256", secret.encode(), salt, 100_000, dklen=32)
    return base64.urlsafe_b64encode(dk)


def encrypt_credentials(username: str, password: str, secret: str) -> str:
    salt = os.urandom(16)
    key = _derive_key(secret, salt)
    f = Fernet(key)
    payload = json.dumps({"u": username, "p": password}).encode()
    token = f.encrypt(payload)
    combined = salt + token
    return base64.urlsafe_b64encode(combined).decode()


def decrypt_credentials(encrypted: str, secret: str) -> tuple[str, str]:
    combined = base64.urlsafe_b64decode(encrypted.encode())
    salt = combined[:16]
    token = combined[16:]
    key = _derive_key(secret, salt)
    f = Fernet(key)
    payload = json.loads(f.decrypt(token))
    return payload["u"], payload["p"]
