# gestion_de_usuarios.py
# Registro y autenticación de usuarios usando Scrypt (KDF).
import os
import base64
import json
from pathlib import Path
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

USERS_FILE = Path("users.json")

# base de datos en memoria (simple)
users_db = {}

SCRYPT_PARAMS = dict(length=64, n=2**14, r=8, p=1)


def _load_users():
    global users_db
    if USERS_FILE.exists():
        try:
            with open(USERS_FILE, "r", encoding="utf-8") as f:
                users_db = json.load(f)
            # ensure keys are strings (compat)
        except Exception as e:
            print("[Users] No se pudo cargar users.json:", e)
            users_db = {}
    else:
        users_db = {}


def _save_users():
    # Escritura atómica (temporal → rename)
    try:
        tmp = USERS_FILE.with_suffix(".tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(users_db, f, indent=2, ensure_ascii=False)
        tmp.replace(USERS_FILE)
    except Exception as e:
        print("[Users] Error guardando users.json:", e)


def derive_master_key(password: str, salt: bytes) -> bytes:
    kdf = Scrypt(salt=salt, **SCRYPT_PARAMS)
    return kdf.derive(password.encode("utf-8"))  # 64 bytes


def register_user(username: str, password: str):
    if username in users_db:
        raise ValueError("Usuario ya existe")
    salt = os.urandom(16)
    master = derive_master_key(password, salt)
    users_db[username] = {
        "salt": base64.b64encode(salt).decode(),
        "verifier": base64.b64encode(master).decode(),
    }
    _save_users()
    print(f"[Registro] Usuario '{username}' registrado.")


def authenticate_user(username: str, password: str) -> bool:
    user = users_db.get(username)
    if not user:
        print("[Autenticación] Usuario no encontrado.")
        return False
    salt = base64.b64decode(user["salt"])
    expected = base64.b64decode(user["verifier"])
    try:
        candidate = derive_master_key(password, salt)
        if candidate == expected:
            print(f"[Autenticación] Usuario '{username}' autenticado correctamente.")
            return True
        else:
            print("[Autenticación] Contraseña incorrecta.")
            return False
    except Exception:
        print("[Autenticación] Error en verificación.")
        return False


def get_master_key_for_user(username: str, password: str) -> bytes:
    if not authenticate_user(username, password):
        raise ValueError("Autenticación fallida")
    salt = base64.b64decode(users_db[username]["salt"])
    return derive_master_key(password, salt)


# Cargar usuarios al importar el módulo
_load_users()
