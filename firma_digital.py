# firma_digital.py

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, utils
from cryptography.hazmat.primitives import serialization

def sign_data(message: bytes, private_key_pem: bytes, password: bytes) -> bytes:
    """
    Genera firma digital RSA-PSS del mensaje con la clave privada.
    """
    private_key = serialization.load_pem_private_key(private_key_pem, password=password)
    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    print("[Firma] Mensaje firmado con RSA-PSS (SHA-256).")
    return signature

def verify_signature(message: bytes, signature: bytes, public_key_pem: bytes):
    """
    Verifica la firma RSA-PSS con la clave pública. Lanza excepción si falla.
    """
    public_key = serialization.load_pem_public_key(public_key_pem)
    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print("[Verificación] Firma válida. El mensaje es auténtico.")
    except Exception:
        print("[Verificación] Firma inválida o mensaje alterado.")


