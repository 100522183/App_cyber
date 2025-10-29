# Cifrado de archivos con AES-GCM y etiquetado HMAC-SHA256.
import os
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes, hmac

def split_master_key(master_key: bytes):
    if len(master_key) < 64:
        raise ValueError('master_key necesita al menos 64 bytes')
    return master_key[:32], master_key[32:64]

def encrypt_file_with_wrapped_key(master_key: bytes, plaintext: bytes):

    # generar clave de archivo
    file_key = os.urandom(32)  # AES-256 para el archivo
    # cifrar el archivo con file_key
    aesgcm_file = AESGCM(file_key)
    enc_nonce = os.urandom(12)
    ciphertext = aesgcm_file.encrypt(enc_nonce, plaintext, None)
    # derivar owner key y hmac key del master_key
    owner_key, hmac_key = split_master_key(master_key)
    # cifrar file_key con owner_key
    aesgcm_wrap = AESGCM(owner_key)
    wrap_nonce = os.urandom(12)
    wrapped_filekey = aesgcm_wrap.encrypt(wrap_nonce, file_key, None)
    # calcular HMAC sobre nonce + ciphertext
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
    # decodificar campos
    enc_nonce = base64.b64decode(package['enc_nonce'])
    ciphertext = base64.b64decode(package['ciphertext'])
    wrap_nonce = base64.b64decode(package['wrap_nonce'])
    wrapped_filekey = base64.b64decode(package['wrapped_filekey'])
    mac = base64.b64decode(package['mac'])
    # derivar keys
    owner_key, hmac_key = split_master_key(master_key)
    # verificar HMAC
    h = hmac.HMAC(hmac_key, hashes.SHA256())
    h.update(enc_nonce + ciphertext)
    try:
        h.verify(mac)
    except Exception as e:
        raise ValueError('MAC inválida o datos alterados') from e
    # descifrar file_key
    aesgcm_wrap = AESGCM(owner_key)
    file_key = aesgcm_wrap.decrypt(wrap_nonce, wrapped_filekey, None)
    # descifrar archivo
    aesgcm_file = AESGCM(file_key)
    plaintext = aesgcm_file.decrypt(enc_nonce, ciphertext, None)
    return plaintext

def create_share_token_from_package(package: dict, file_key: bytes, passphrase: str):

    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
    salt = os.urandom(16)
    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
    share_key = kdf.derive(passphrase.encode('utf-8'))
    aesgcm = AESGCM(share_key)
    nonce = os.urandom(12)
    wrapped = aesgcm.encrypt(nonce, file_key, None)
    return {
        'salt': base64.b64encode(salt).decode(),
        'nonce': base64.b64encode(nonce).decode(),
        'wrapped_filekey': base64.b64encode(wrapped).decode()
    }

def recover_filekey_from_share_token(token: dict, passphrase: str) -> bytes:

    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
    salt = base64.b64decode(token['salt'])
    nonce = base64.b64decode(token['nonce'])
    wrapped = base64.b64decode(token['wrapped_filekey'])
    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
    share_key = kdf.derive(passphrase.encode('utf-8'))
    aesgcm = AESGCM(share_key)
    file_key = aesgcm.decrypt(nonce, wrapped, None)
    return file_key
