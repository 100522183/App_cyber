import os
import base64
from pathlib import Path
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


class CertificateAuthority:

    def __init__(self, ca_root_dir: str, aes_key_base64: str):
        self.root = Path(ca_root_dir)

        # Cargamos las rutas de los archivos encriptados
        enc_key_path = self.root / "root_ca_enc.key"
        nonce_path = self.root / "root_ca_enc.nonce"
        tag_path = self.root / "root_ca_enc.tag"
        cert_path = self.root / "root_ca.cert"

        # Cargamos la contraseña de aes
        aes_key = base64.b64decode(aes_key_base64)

        # Desencriptamos la llave privada
        encrypted_key = enc_key_path.read_bytes()
        nonce = nonce_path.read_bytes()
        tag = tag_path.read_bytes()

        cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce, tag))
        decryptor = cipher.decryptor()
        private_key_pem = decryptor.update(encrypted_key) + decryptor.finalize()

        # Destruimos la llave aes para que no se intercepte
        del aes_key

        # Creamos el objeto llave privada
        self.private_key = serialization.load_pem_private_key(
            private_key_pem,
            password=None
        )

        # Cargamos el certificado de la ca
        self.certificate = x509.load_pem_x509_certificate(cert_path.read_bytes())

    # Firma de certificados
    def sign_csr(self, csr_pem: bytes, valid_days: int = 365) -> x509.Certificate:
        """ Firma un certificado generado por un usuario, manteniendo las claves privadas como tal
        """

        csr = x509.load_pem_x509_csr(csr_pem)

        # Validate the CSR signature: ensures user owns the private key
        if not csr.is_signature_valid:
            raise ValueError("Invalid CSR: Signature mismatch.")

        # Build certificate
        cert = (
            x509.CertificateBuilder()
            .subject_name(csr.subject)
            .issuer_name(self.certificate.subject)
            .public_key(csr.public_key())
            .serial_number(int.from_bytes(os.urandom(16), "big"))
            .not_valid_before(datetime.now(timezone.utc))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=valid_days))
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True
            )
            .sign(self.private_key, hashes.SHA256())
        )

        return cert
