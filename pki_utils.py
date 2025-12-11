
import os
import datetime
from pathlib import Path
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.exceptions import InvalidSignature

# Configuración
CA_ROOT_FOLDER = Path('CA_ROOT')
CA_CERT_FILE = CA_ROOT_FOLDER / "root_ca.cert"

def load_root_ca_cert():
    if not CA_CERT_FILE.exists():
        print(f"[PKI DEBUG] Error: No se encuentra {CA_CERT_FILE.absolute()}")
        raise FileNotFoundError("Error crítico: No se encuentra el certificado Root CA.")
    with open(CA_CERT_FILE, "rb") as f:
        return x509.load_pem_x509_certificate(f.read())

def generate_user_keypair():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)

def generate_csr(user_private_key, username: str) -> bytes:
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"ES"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"SecureShare User"),
        x509.NameAttribute(NameOID.COMMON_NAME, username),
    ])
    csr = x509.CertificateSigningRequestBuilder().subject_name(subject).sign(user_private_key, hashes.SHA256())
    return csr.public_bytes(serialization.Encoding.PEM)

def verify_cert_and_get_public_key(cert_pem_str: str):
    """
    Verifica que el certificado sea válido y devuelve la clave pública.
    """
    print(f"[PKI DEBUG] Iniciando verificación de certificado...")
    
    if isinstance(cert_pem_str, str):
        cert_pem_bytes = cert_pem_str.encode('utf-8')
    else:
        cert_pem_bytes = cert_pem_str

    try:
        user_cert = x509.load_pem_x509_certificate(cert_pem_bytes)
    except Exception as e:
        print(f"[PKI DEBUG] Fallo al cargar PEM: {e}")
        raise ValueError("Certificado con formato inválido.")

    # --- FIX TEMPORAL: Margen de 1 minuto ---
    # Restamos 1 minuto a la fecha de inicio del certificado para evitar fallos
    # si la verificación ocurre en el mismo segundo que la creación.
    now = datetime.datetime.now(datetime.timezone.utc)
    
    # Depuración de fechas
    print(f"[PKI DEBUG] Hora actual (UTC): {now}")
    print(f"[PKI DEBUG] Validez Cert: {user_cert.not_valid_before_utc} hasta {user_cert.not_valid_after_utc}")

    # Chequeo relajado
    if now < (user_cert.not_valid_before_utc - datetime.timedelta(minutes=1)):
        print("[PKI DEBUG] Error: El certificado aún no es válido (Fecha futura).")
        raise ValueError("El certificado aún no es válido.")
        
    if now > user_cert.not_valid_after_utc:
        print("[PKI DEBUG] Error: El certificado ha caducado.")
        raise ValueError("El certificado ha caducado.")

    # Verificar firma de la CA
    try:
        ca_cert = load_root_ca_cert()
        ca_pub_key = ca_cert.public_key()
        
        ca_pub_key.verify(
            user_cert.signature,
            user_cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            user_cert.signature_hash_algorithm,
        )
        print("[PKI DEBUG] Firma de la CA verificada correctamente.")
    except Exception as e:
        print(f"[PKI DEBUG] ERROR DE FIRMA CA: {e}")
        raise ValueError("SEGURIDAD: El certificado NO está firmado por la CA de confianza.")

    return user_cert.public_key()

def encrypt_with_public_key(public_key, data: bytes) -> bytes:
    return public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def decrypt_rsa(private_key, ciphertext: bytes) -> bytes:
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def sign_data(private_key, data: bytes) -> bytes:
    return private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

def verify_signature(public_key, signature: bytes, data: bytes):
    public_key.verify(
        signature,
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

def serialize_private_key(private_key) -> bytes:
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

def deserialize_private_key(pem_bytes):
    return serialization.load_pem_private_key(pem_bytes, password=None)