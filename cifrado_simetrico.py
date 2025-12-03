import os
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes, hmac

# Mantenemos las funciones base iguales
def split_master_key(master_key: bytes):
    # Aseguramos que master_key sea de 32 bytes (lo expandimos a 64 para owner+hmac)
    # En este diseño, usaremos HKDF o un simple hash para expandir si es necesario
    # Para simplificar con la UserManager nueva, asumiremos master_key de 32 bytes
    # y derivaremos las sub-llaves usando un hash simple.
    h1 = hashes.Hash(hashes.SHA256())
    h1.update(master_key + b"owner")
    owner_key = h1.finalize()
    
    h2 = hashes.Hash(hashes.SHA256())
    h2.update(master_key + b"hmac")
    hmac_key = h2.finalize()
    return owner_key, hmac_key

def encrypt_file_with_wrapped_key(master_key: bytes, plaintext: bytes) -> dict:
    file_key = os.urandom(32)
    aesgcm_file = AESGCM(file_key)
    enc_nonce = os.urandom(12)
    ciphertext = aesgcm_file.encrypt(enc_nonce, plaintext, None)
    
    owner_key, hmac_key = split_master_key(master_key)
    
    aesgcm_wrap = AESGCM(owner_key)
    wrap_nonce = os.urandom(12)
    wrapped_filekey = aesgcm_wrap.encrypt(wrap_nonce, file_key, None)
    
    h = hmac.HMAC(hmac_key, hashes.SHA256())
    h.update(enc_nonce + ciphertext)
    mac = h.finalize()
    
    return {
        'enc_nonce': base64.b64encode(enc_nonce).decode(),
        'ciphertext': base64.b64encode(ciphertext).decode(),
        'wrap_nonce': base64.b64encode(wrap_nonce).decode(),
        'wrapped_filekey': base64.b64encode(wrapped_filekey).decode(),
        'mac': base64.b64encode(mac).decode()
    }

def decrypt_file_with_wrapped_key(master_key: bytes, package: dict) -> bytes:
    enc_nonce = base64.b64decode(package['enc_nonce'])
    ciphertext = base64.b64decode(package['ciphertext'])
    wrap_nonce = base64.b64decode(package['wrap_nonce'])
    wrapped_filekey = base64.b64decode(package['wrapped_filekey'])
    mac = base64.b64decode(package['mac'])
    
    owner_key, hmac_key = split_master_key(master_key)
    
    h = hmac.HMAC(hmac_key, hashes.SHA256())
    h.update(enc_nonce + ciphertext)
    h.verify(mac)
    
    aesgcm_wrap = AESGCM(owner_key)
    file_key = aesgcm_wrap.decrypt(wrap_nonce, wrapped_filekey, None)
    
    aesgcm_file = AESGCM(file_key)
    plaintext = aesgcm_file.decrypt(enc_nonce, ciphertext, None)
    return plaintext