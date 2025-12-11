import os
import json
import base64
import secrets
from pathlib import Path

from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM # Mantenemos GCM solo para cifrar la clave privada (legacy user manager)
from cryptography.hazmat.primitives import serialization
from autoridad_de_certificación import CertificateAuthority
import pki_utils

class UserManager:
    def __init__(self):
        self.DB_FILE = Path("users.json")
        self.CERTS_DIR = Path("public_certs")
        self.CERTS_DIR.mkdir(exist_ok=True)
        self.users = self._load_db()
        self.ca = self._load_ca()

        # Configuración de Scrypt
        # n=16384, r=8, p=1 son valores estándar seguros
        self.SCRYPT_PARAMS = dict(length=32, n=2**14, r=8, p=1)

    def _load_db(self):
        if self.DB_FILE.exists():
            try:
                with open(self.DB_FILE, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                return {}
        return {}

    def _save_db(self):
        with open(self.DB_FILE, "w", encoding="utf-8") as f:
            json.dump(self.users, f, indent=2, ensure_ascii=False)

    def _load_ca(self):
        try:
            if Path("ca_master_key.secret").exists():
                with open("ca_master_key.secret", "r") as f:
                    return CertificateAuthority("CA_ROOT", f.read().strip())
        except Exception as e:
            print(f"[ERROR] CA: {e}")
        return None

    def _derive_scrypt(self, password: str, salt: bytes) -> bytes:
        """Función auxiliar para ejecutar Scrypt."""
        kdf = Scrypt(salt=salt, **self.SCRYPT_PARAMS)
        return kdf.derive(password.encode("utf-8"))

    def register_user(self, username, password):
        if not self.ca: raise RuntimeError("CA no disponible.")
        if username in self.users: raise ValueError("Usuario existe.")

        print(f"[Registro] Procesando '{username}' con seguridad reforzada (Scrypt + AES-CTR)...")

        # AUTENTICACIÓN, creamos el verifier
        auth_nonce = os.urandom(16)
        verifier = self._derive_scrypt(password, auth_nonce)

        # CIFRADO 
        crypto_salt = os.urandom(16)
        master_key = self._derive_scrypt(password, crypto_salt)

        # Crear llaves y certificado, lo firmamos para que la autoridad verifique que somos 
        # nosotros y la autoridad lo devuelve firmado
        priv_key = pki_utils.generate_user_keypair()
        csr_pem = pki_utils.generate_csr(priv_key, username)
        cert_obj = self.ca.sign_csr(csr_pem)
        user_cert_pem = cert_obj.public_bytes(serialization.Encoding.PEM).decode()
        
        cert_path = self.CERTS_DIR / f"{username}.cert"
        with open(cert_path, "w", encoding="utf-8") as f:
            f.write(user_cert_pem)

        # 4. CIFRADO DE CLAVE PRIVADA
        # Nota: Aquí seguimos usando AES-GCM por simplicidad interna para la clave privada RSA, 
        # pero los archivos del usuario irán con AES-CTR vía 'cifrado_simetrico.py'.
        priv_pem = pki_utils.serialize_private_key(priv_key)
        aes = AESGCM(master_key)
        enc_nonce = os.urandom(12)
        encrypted_priv_key = aes.encrypt(enc_nonce, priv_pem, None)

        # GUARDAR
        self.users[username] = {
            "auth_nonce": base64.b64encode(auth_nonce).decode(),
            "verifier": base64.b64encode(verifier).decode(), # Scrypt hash
            "crypto_salt": base64.b64encode(crypto_salt).decode(),
            "certificate": user_cert_pem,
            "certificate_path": str(cert_path),
            "encrypted_private_key": {
                "nonce": base64.b64encode(enc_nonce).decode(),
                "ciphertext": base64.b64encode(encrypted_priv_key).decode()
            }
        }
        self._save_db()
        print(f"[Registro] Usuario '{username}' registrado.")

    def login_user(self, username, password):
        user_data = self.users.get(username)
        if not user_data: raise ValueError("Usuario no encontrado.")

        # VERIFICAR LOGIN CON SCRYPT
        auth_nonce = base64.b64decode(user_data["auth_nonce"])
        stored_verifier = base64.b64decode(user_data["verifier"])

        # Recalculamos usando Scrypt
        computed_verifier = self._derive_scrypt(password, auth_nonce)

        if not secrets.compare_digest(stored_verifier, computed_verifier):
            raise ValueError("Contraseña incorrecta.")
        
        print(f"[Login] Autenticación correcta (Scrypt verificado).")

        # DERIVAR MASTER KEY
        crypto_salt = base64.b64decode(user_data["crypto_salt"])
        master_key = self._derive_scrypt(password, crypto_salt)

        try:
            enc_data = user_data["encrypted_private_key"]
            enc_nonce = base64.b64decode(enc_data["nonce"])
            ciphertext = base64.b64decode(enc_data["ciphertext"])

            aes = AESGCM(master_key)
            priv_key_pem = aes.decrypt(enc_nonce, ciphertext, None)
            return master_key, priv_key_pem

        except Exception:
            raise ValueError("Error fatal descifrando clave privada.")

    def get_user_certificate(self, username):
        user = self.users.get(username)
        return user["certificate"] if user else None