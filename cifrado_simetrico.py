import os
import base64
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.exceptions import InvalidSignature

def derive_subkeys(main_key: bytes):
    """
    Expande la llave principal usando SHA-512 (64 bytes).
    Divide el resultado exacto por la mitad:
    - Primera mitad (32 bytes) -> Cifrado (AES-256)
    - Segunda mitad (32 bytes) -> Integridad (HMAC)
    """
    # Hash simple, sin contextos ni salts extraños
    expanded = hashlib.sha512(main_key).digest()
    
    enc_key = expanded[:32]
    mac_key = expanded[32:]
    
    return enc_key, mac_key

def _aes_ctr_hmac_encrypt(key: bytes, data: bytes) -> dict:
    enc_key, mac_key = derive_subkeys(key)
    
    # 1. Cifrado AES-CTR
    nonce = os.urandom(16)
    cipher = Cipher(algorithms.AES(enc_key), modes.CTR(nonce))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()
    
    # 2. Integridad HMAC
    h = hmac.HMAC(mac_key, hashes.SHA256())
    h.update(nonce + ciphertext)
    mac = h.finalize()
    
    return {
        'nonce': base64.b64encode(nonce).decode(),
        'ciphertext': base64.b64encode(ciphertext).decode(),
        'mac': base64.b64encode(mac).decode()
    }

def _aes_ctr_hmac_decrypt(key: bytes, pkg: dict) -> bytes:
    enc_key, mac_key = derive_subkeys(key)
    
    nonce = base64.b64decode(pkg['nonce'])
    ciphertext = base64.b64decode(pkg['ciphertext'])
    mac_received = base64.b64decode(pkg['mac'])
    
    # Verificar HMAC
    h = hmac.HMAC(mac_key, hashes.SHA256())
    h.update(nonce + ciphertext)
    
    try:
        h.verify(mac_received)
    except InvalidSignature:
        raise ValueError("SEGURIDAD: Fallo de integridad (HMAC inválido).")
        
    # Descifrar AES-CTR
    cipher = Cipher(algorithms.AES(enc_key), modes.CTR(nonce))
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    
    return plaintext

def encrypt_file_with_wrapped_key(master_key: bytes, plaintext: bytes) -> dict:
    # Generar llave aleatoria
    file_key = os.urandom(32)
    
    # Cifrar archivo con esa llave
    encrypted_file = _aes_ctr_hmac_encrypt(file_key, plaintext)
    
    # Cifrar la llave con la master key
    wrapped_key = _aes_ctr_hmac_encrypt(master_key, file_key)
    
    return {
        'enc_nonce': encrypted_file['nonce'],
        'ciphertext': encrypted_file['ciphertext'],
        'mac': encrypted_file['mac'],
        
        'wrap_nonce': wrapped_key['nonce'],
        'wrapped_filekey': wrapped_key['ciphertext'],
        'wrap_mac': wrapped_key['mac']
    }

def decrypt_file_with_wrapped_key(master_key: bytes, package: dict) -> bytes:
    # Descifrar la llave del archivo
    key_pkg = {
        'nonce': package['wrap_nonce'],
        'ciphertext': package['wrapped_filekey'],
        'mac': package['wrap_mac']
    }
    file_key = _aes_ctr_hmac_decrypt(master_key, key_pkg)
    
    # Descifrar el archivo
    file_pkg = {
        'nonce': package['enc_nonce'],
        'ciphertext': package['ciphertext'],
        'mac': package['mac']
    }
    return _aes_ctr_hmac_decrypt(file_key, file_pkg)

def split_master_key(master_key: bytes):
    return derive_subkeys(master_key)