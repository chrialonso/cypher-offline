import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def derive_key(master_password, salt):
    """
    Derive a 32-byte AES encryption key from a master password and salt using PBKDF2-HMAC-SHA256.
    """
    kdf = PBKDF2HMAC(algorithm = hashes.SHA256(), length=32, salt=salt, iterations=100000)
    return kdf.derive(master_password.encode())

def generate_salt():
    """
    Generate a 16-byte random salt for key derivation.
    """
    return os.urandom(16)

def encrypt_password(password, key):
    """
    Encrypt the given password with AES-GCM using the provided key.
    Returns raw bytes containing IV + tag + ciphertext.
    """
    iv = os.urandom(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(password.encode()) + encryptor.finalize()
    return iv + encryptor.tag + ciphertext

def decrypt_password(encrypted_blob, key):
    """
    Decrypt data encrypted by encrypt_password.
    """

    iv = encrypted_blob[:12]
    tag = encrypted_blob[12:28]
    ciphertext = encrypted_blob[28:]

    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag))
    decryptor = cipher.decryptor()
    return(decryptor.update(ciphertext) + decryptor.finalize()).decode()
