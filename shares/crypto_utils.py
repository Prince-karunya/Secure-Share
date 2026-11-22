import secrets

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def derive_key(password, salt):
    """Derive a 32-byte AES key from a password and salt."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=bytes(salt),
        iterations=200_000,
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt_bytes(data, password):
    """Encrypt bytes with AES-256-GCM and return ciphertext, salt, and nonce."""
    salt = secrets.token_bytes(16)
    nonce = secrets.token_bytes(12)
    ciphertext = AESGCM(derive_key(password, salt)).encrypt(nonce, data, None)
    return ciphertext, salt, nonce


def decrypt_bytes(ciphertext, password, salt, nonce):
    """Decrypt and authenticate bytes, raising a clear error on failure."""
    try:
        return AESGCM(derive_key(password, salt)).decrypt(bytes(nonce), bytes(ciphertext), None)
    except InvalidTag:
        raise ValueError("The password is wrong or the file was tampered with.")
