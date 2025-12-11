import os
import base64
from pathlib import Path
from cryptography.exceptions import InvalidSignature

import almacenamiento
import cifrado_simetrico 
import pki_utils

class User:
    def __init__(self, username: str, master_key: bytes, private_key_pem: bytes):
        self.username = username
        self.master_key = master_key
        self.private_key_pem = private_key_pem
        
        # Cargamos las claves en memoria
        self.rsa_private_key = pki_utils.deserialize_private_key(self.private_key_pem)
        
        # Preparamos el gestor de archivos
        self.storage = almacenamiento.UserStorageManager(self.username)

        # Cargamos nuestro certificado público (para firmar envíos)
        self.own_cert_pem = self._load_my_certificate()

    def _load_my_certificate(self) -> str:
        """Busca el certificado en la carpeta pública."""
        cert_path = Path("public_certs") / f"{self.username}.cert"
        if cert_path.exists():
            return cert_path.read_text(encoding="utf-8")
        return None

    def list_my_files(self):
        return self.storage.list_files()

    def list_inbox_files(self):
        return self.storage.list_shared_files()

    def encrypt_and_save_file(self, filename: str, data: bytes):
        """Cifra un archivo y lo guarda."""
        pkg = cifrado_simetrico.encrypt_file_with_wrapped_key(self.master_key, data)
        self.storage.save_package(filename, pkg)

    def load_and_decrypt_file(self, filename: str) -> bytes:
        """Carga y descifra un archivo."""
        pkg = self.storage.load_package(filename)
        return cifrado_simetrico.decrypt_file_with_wrapped_key(self.master_key, pkg)

    def share_file(self, filename: str, recipient_username: str, recipient_cert_pem: str):
        if not self.own_cert_pem:
            raise ValueError("Error: No tengo mi certificado para firmar.")

        # 1. Verificar certificado del destinatario
        recipient_pub_key = pki_utils.verify_cert_and_get_public_key(recipient_cert_pem)
        
        # 2. Cargar mi archivo cifrado
        pkg = self.storage.load_package(filename)
        
        # 3. Sacar la 'file_key' descifrando el envoltorio
        wrap_pkg = {
            'nonce': pkg['wrap_nonce'],
            'ciphertext': pkg['wrapped_filekey'],
            'mac': pkg['wrap_mac']
        }
        
        try:
            # Usamos la master_key para obtener la llave del archivo
            file_key = cifrado_simetrico._aes_ctr_hmac_decrypt(self.master_key, wrap_pkg)
        except Exception:
            raise ValueError("Error al descifrar la llave del archivo original.")

        # 4. Cifrar esa llave para el destinatario (RSA)
        enc_file_key = pki_utils.encrypt_with_public_key(recipient_pub_key, file_key)
        
        # 5. Firmar los datos cifrados (Integridad + Autenticidad)
        data_to_sign = base64.b64decode(pkg['enc_nonce']) + base64.b64decode(pkg['ciphertext'])
        signature = pki_utils.sign_data(self.rsa_private_key, data_to_sign)
        
        # 6. Empaquetar para el envío
        share_pkg = {
            "sender": self.username,
            "filename": filename,
            
            # Datos cifrados (no cambian)
            "enc_nonce": pkg['enc_nonce'],
            "ciphertext": pkg['ciphertext'],
            "mac": pkg['mac'],
            
            # Llave cifrada para el otro
            "rsa_enc_key": base64.b64encode(enc_file_key).decode(),
            
            # Credenciales
            "sender_cert": self.own_cert_pem,
            "signature": base64.b64encode(signature).decode()
        }
        
        # Guardar en el inbox del otro
        recipient_storage = almacenamiento.UserStorageManager(recipient_username)
        recipient_storage.save_shared_package(f"{filename}_de_{self.username}", share_pkg)

    def receive_file(self, share_name: str):
        share_pkg = self.storage.load_shared_package(share_name)
        
        # 1. Verificar quién lo envía (Certificado)
        sender_cert_pem = share_pkg['sender_cert']
        sender_pub_key = pki_utils.verify_cert_and_get_public_key(sender_cert_pem)

        # 2. Verificar la firma del archivo
        signature = base64.b64decode(share_pkg['signature'])
        enc_nonce = base64.b64decode(share_pkg['enc_nonce'])
        ciphertext = base64.b64decode(share_pkg['ciphertext'])
        
        pki_utils.verify_signature(sender_pub_key, signature, enc_nonce + ciphertext)

        # 3. Descifrar la llave RSA con mi privada
        rsa_ct = base64.b64decode(share_pkg['rsa_enc_key'])
        file_key = pki_utils.decrypt_rsa(self.rsa_private_key, rsa_ct)
        
        # 4. Guardar la llave protegida con MI master key (AES-CTR + HMAC)
        wrapped_key_pkg = cifrado_simetrico._aes_ctr_hmac_encrypt(self.master_key, file_key)
        
        # 5. Guardar archivo como propio
        new_pkg = {
            'enc_nonce': share_pkg['enc_nonce'],
            'ciphertext': share_pkg['ciphertext'],
            'mac': share_pkg['mac'],
            
            'wrap_nonce': wrapped_key_pkg['nonce'],
            'wrapped_filekey': wrapped_key_pkg['ciphertext'],
            'wrap_mac': wrapped_key_pkg['mac']
        }
        
        final_name = f"recibido_{share_pkg['filename']}"
        self.storage.save_package(final_name, new_pkg)
        self.storage.remove_shared_package(share_name)
        
        return final_name