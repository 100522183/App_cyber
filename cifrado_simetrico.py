# cifrado_simetrico.py

import os
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

def encrypt_data(message: bytes, public_key_pem: bytes):
    """
    Cifra datos con AES-GCM y cifra la clave AES con RSA-OAEP.
    """
    # Cargar clave pública RSA del receptor
    public_key = serialization.load_pem_public_key(public_key_pem)
    # Generar clave AES (256 bits) y nonce
    key = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)  # 96-bit nonce recomendado:contentReference[oaicite:16]{index=16}
    ciphertext = aesgcm.encrypt(nonce, message, None)
    # Cifrar la clave AES con RSA-OAEP
    encrypted_key = public_key.encrypt(
        key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    print(f"[Cifrado] AES-256-GCM: datos cifrados (len={len(ciphertext)} bytes).")
    print("[Cifrado] RSA-OAEP: clave AES cifrada con clave pública RSA.")
    return ciphertext, nonce, encrypted_key

def decrypt_data(ciphertext: bytes, nonce: bytes, encrypted_key: bytes, private_key_pem: bytes, password: bytes):
    """
    Descifra la clave AES con RSA-OAEP y luego los datos con AES-GCM.
    """
    # Cargar clave privada RSA del receptor (PEM cifrado con contraseña)
    private_key = serialization.load_pem_private_key(private_key_pem, password=password)
    # Descifrar clave AES
    aes_key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    aesgcm = AESGCM(aes_key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    print("[Descifrado] AES-GCM: datos descifrados correctamente.")
    return plaintext

# Ejemplo de uso
if __name__ == "__main__":
    import base64
    from gestion_de_usuarios import users_db
    # Obtener claves de Alice (registro del módulo anterior)
    alice_pub = base64.b64decode(users_db["alice"]["public_key"])
    alice_priv = base64.b64decode(users_db["alice"]["private_key"])
    alice_pass = "mi_contraseña_segura".encode('utf-8')
    # Texto a cifrar
    data = b"Mensaje secreto para Alice."
    ct, nonce, enc_key = encrypt_data(data, alice_pub)
    # Descifrado usando la clave privada de Alice
    pt = decrypt_data(ct, nonce, enc_key, alice_priv, alice_pass)
    print("Texto original recuperado:", pt)
