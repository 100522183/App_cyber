import os
import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from pathlib import Path

# Configuración de la CA
CA_ROOT_FOLDER = Path('CA_ROOT')
CA_KEY_FILE = CA_ROOT_FOLDER / "server_ca.key"
CA_CERT_FILE = CA_ROOT_FOLDER / "server_ca.crt"

def load_or_create_ca():
    """Carga la CA existente o crea una nueva si no existe."""
    CA_ROOT_FOLDER.mkdir(exist_ok=True)
    if os.path.exists(CA_KEY_FILE) and os.path.exists(CA_CERT_FILE):
        with open(CA_KEY_FILE, "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)
        with open(CA_CERT_FILE, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read())
        return private_key, cert
    
    # Crear nueva CA
    print("[PKI] Generando nueva Autoridad de Certificación (CA)...")
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"ES"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"SecureShare Root CA"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"SecureShare CA"),
    ])
    
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=3650)
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=None), critical=True,
    ).sign(private_key, hashes.SHA256())

    # Guardar en disco
    with open(CA_KEY_FILE, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
    with open(CA_CERT_FILE, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
        
    return private_key, cert

def generate_user_keypair():
    """Genera un par de claves RSA para un usuario."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private_key

def issue_user_certificate(ca_key, ca_cert, user_pub_key, username):
    """Emite un certificado firmado por la CA para un usuario."""
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"ES"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"SecureShare Users"),
        x509.NameAttribute(NameOID.COMMON_NAME, username),
    ])
    
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        ca_cert.subject
    ).public_key(
        user_pub_key
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=365)
    ).sign(ca_key, hashes.SHA256())
    
    return cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')

def encrypt_rsa(public_key_pem: str, data: bytes) -> bytes:
    """Cifra datos (ej. file_key) usando la clave pública del destinatario."""
    pub_key = serialization.load_pem_public_key(public_key_pem.encode('utf-8'))
    ciphertext = pub_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

def decrypt_rsa(private_key, ciphertext: bytes) -> bytes:
    """Descifra datos usando la clave privada (objeto cryptography key)."""
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext

def serialize_private_key(private_key) -> bytes:
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

def deserialize_private_key(pem_bytes):
    return serialization.load_pem_private_key(pem_bytes, password=None)