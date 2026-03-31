"""
Encryption helpers for DB and PGP report encryption.
"""

import base64
import os
from typing import Optional

try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    FERNET_AVAILABLE = True
except ImportError:
    FERNET_AVAILABLE = False

try:
    import pgpy
    PGP_AVAILABLE = True
except ImportError:
    PGP_AVAILABLE = False


def get_fernet_key(env_key: str = "CAM_PWN_DB_KEY", raw_key: Optional[bytes] = None) -> Optional[bytes]:
    """Derive or use 32-byte key for Fernet from env or raw_key."""
    if not FERNET_AVAILABLE:
        return None
    if raw_key and len(raw_key) == 32:
        return base64.urlsafe_b64encode(raw_key)
    key_material = os.environ.get(env_key) or (raw_key.decode() if raw_key else None)
    if not key_material:
        return None
    if len(key_material) == 44 and key_material.endswith("="):
        return key_material.encode()
    # Derive from password
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=b"cam_pwn_salt", iterations=100000)
    key = base64.urlsafe_b64encode(kdf.derive(key_material.encode()))
    return key


def encrypt_field(value: str, env_key: str = "CAM_PWN_DB_KEY") -> Optional[str]:
    """Encrypt a string for storage. Returns base64 ciphertext or None."""
    if not FERNET_AVAILABLE or not value:
        return value
    key = get_fernet_key(env_key)
    if not key:
        return value
    try:
        f = Fernet(key)
        return f.encrypt(value.encode("utf-8")).decode("ascii")
    except Exception:
        return value


def decrypt_field(value: str, env_key: str = "CAM_PWN_DB_KEY") -> str:
    """Decrypt a stored value."""
    if not FERNET_AVAILABLE or not value:
        return value or ""
    key = get_fernet_key(env_key)
    if not key:
        return value
    try:
        f = Fernet(key)
        return f.decrypt(value.encode("ascii")).decode("utf-8")
    except Exception:
        return value


def pgp_encrypt_file(file_path: str, recipient_fingerprint: str) -> bool:
    """Encrypt a file with PGP for the given recipient. Returns True on success."""
    if not PGP_AVAILABLE:
        return False
    try:
        with open(file_path, "rb") as f:
            data = f.read()
        key, _ = pgpy.PGPKey.from_file(recipient_fingerprint) if os.path.isfile(recipient_fingerprint) else (None, None)
        if key is None:
            return False
        msg = pgpy.PGPMessage.new(data)
        enc = key.encrypt(msg)
        with open(file_path + ".pgp", "wb") as f:
            f.write(bytes(enc))
        return True
    except Exception:
        return False
