# gestión_de_usuarios.py

import os
import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.asymmetric import rsa

# Base de datos simulada: { usuario: {salt, hash, private_key, public_key} }
users_db = {}

def register_user(username: str, password: str):
    """
    Registra un usuario: derive un hash con scrypt, genera par de llaves RSA,
    y almacena salt, hash y claves (privada cifrada con contraseña).
    """
    # Derivar hash de contraseña con salt aleatorio
    salt = os.urandom(16)
    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
    key = kdf.derive(password.encode())
    # Generar par de llaves RSA (2048 bits)
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    # Serializar clave privada en PEM cifrada con la contraseña
    pem_priv = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(password.encode())
    )
    # Serializar clave pública en PEM
    pem_pub = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    # Almacenar usuario (salt y hash codificados en base64 para almacenar)
    users_db[username] = {
        'salt': base64.b64encode(salt).decode(),
        'hash': base64.b64encode(key).decode(),
        'private_key': base64.b64encode(pem_priv).decode(),
        'public_key': base64.b64encode(pem_pub).decode()
    }
    print(f"[Registro] Usuario '{username}' registrado con éxito.")

def authenticate_user(username: str, password: str) -> bool:
    """
    Autentica un usuario. Deriva el hash con el salt almacenado y compara.
    """
    user = users_db.get(username)
    if not user:
        print("[Autenticación] Usuario no encontrado.")
        return False
    salt = base64.b64decode(user['salt'])
    stored_hash = base64.b64decode(user['hash'])
    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
    try:
        kdf.verify(password.encode(), stored_hash)
        print(f"[Autenticación] Usuario '{username}' autenticado correctamente.")
        return True
    except Exception:
        print(f"[Autenticación] Falló la verificación de contraseña para '{username}'.")
        return False

# Ejemplo de uso
if __name__ == "__main__":
    # Registrar usuario y luego autenticar
    register_user("alice", "mi_contraseña_segura")
    authenticate_user("alice", "mi_contraseña_segura")  # Éxito
    authenticate_user("alice", "otra_contraseña")        # Falla
