import os
import base64
import json
from pathlib import Path
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import pki_utils

class UserManager:
    def __init__(self):
        self.__USERS_FILE = Path("users.json")
        self._load_users()
        self.__SCRYPT_PARAMS = dict(length=32, n=2**14, r=8, p=1)
        # Cargar la CA al iniciar
        self.ca_key, self.ca_cert = pki_utils.load_or_create_ca()

    def _load_users(self):
        if self.__USERS_FILE.exists():
            try:
                with open(self.__USERS_FILE, "r", encoding="utf-8") as f:
                    self.users_db = json.load(f)
            except Exception as e:
                print("[Users] Error cargando DB:", e)
                self.users_db = {}
        else:
            self.users_db = {}

    def _save_users(self):
        with open(self.__USERS_FILE, "w", encoding="utf-8") as f:
            json.dump(self.users_db, f, indent=2, ensure_ascii=False)

    def _derive_master_key(self, password: str, salt: bytes) -> bytes:
        """Deriva una clave maestra simétrica de 32 bytes."""
        kdf = Scrypt(salt=salt, **self.__SCRYPT_PARAMS)
        return kdf.derive(password.encode("utf-8"))

    def register_user(self, username, password):
        if username in self.users_db:
            raise ValueError("Usuario ya existe")
        
        salt = os.urandom(16)
        master_key = self._derive_master_key(password, salt) # 32 bytes raw

        # 1. Generar par de claves RSA para el usuario
        user_priv_key = pki_utils.generate_user_keypair()
        user_pub_key = user_priv_key.public_key()

        # 2. Emitir certificado (Firmado por CA)
        user_cert_pem = pki_utils.issue_user_certificate(
            self.ca_key, self.ca_cert, user_pub_key, username
        )

        # 3. Cifrar la clave privada del usuario con su master_key (AES-GCM)
        priv_pem = pki_utils.serialize_private_key(user_priv_key)
        aesgcm = AESGCM(master_key)
        nonce = os.urandom(12)
        encrypted_priv_key = aesgcm.encrypt(nonce, priv_pem, None)

        # 4. Guardar todo
        self.users_db[username] = {
            "salt": base64.b64encode(salt).decode(),
            # No guardamos el verificador como antes, validamos intentando descifrar la priv key
            # o podríamos guardar un hash del master_key para validación rápida.
            "check_hash": base64.b64encode(os.urandom(16)).decode(), # Placeholder simplificado
            "certificate": user_cert_pem,
            "enc_priv_key": {
                "nonce": base64.b64encode(nonce).decode(),
                "ciphertext": base64.b64encode(encrypted_priv_key).decode()
            }
        }
        self._save_users()
        print(f"[Registro] Usuario '{username}' registrado y certificado emitido.")

    def login_user(self, username, password):
        """Intenta hacer login. Si es correcto, devuelve (master_key, private_key_pem)."""
        user_data = self.users_db.get(username)
        if not user_data:
            raise ValueError("Usuario no encontrado")

        salt = base64.b64decode(user_data["salt"])
        master_key = self._derive_master_key(password, salt)

        # Intentar descifrar la clave privada para verificar contraseña
        enc_priv = user_data["enc_priv_key"]
        nonce = base64.b64decode(enc_priv["nonce"])
        ciphertext = base64.b64decode(enc_priv["ciphertext"])

        try:
            aesgcm = AESGCM(master_key)
            priv_key_pem = aesgcm.decrypt(nonce, ciphertext, None)
            return master_key, priv_key_pem
        except Exception:
            raise ValueError("Contraseña incorrecta")

    def get_user_certificate(self, username):
        """Obtiene el certificado público (PEM) de un usuario."""
        user = self.users_db.get(username)
        if user:
            return user["certificate"]
        return None