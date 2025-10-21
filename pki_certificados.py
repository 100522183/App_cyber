# pki_certificados.py

import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

def create_root_ca():
    """
    Genera clave privada RSA para CA raíz y su certificado auto-firmado.
    """
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, u"Mi CA Raíz"),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    print("[PKI] CA raíz creada (autofirmada).")
    return key, cert

def create_intermediate_ca(root_key, root_cert):
    """
    Genera clave privada RSA para CA intermedia y su certificado firmado por CA raíz.
    """
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, u"CA Intermedia"),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(root_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=1825))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(root_key, hashes.SHA256())
    )
    print("[PKI] CA intermedia creada y firmada por CA raíz.")
    return key, cert

def sign_user_certificate(username: str, user_public_key_pem: bytes, int_key, int_cert):
    """
    Genera un certificado X.509 para el usuario, firmado por la CA intermedia.
    """
    user_pub = serialization.load_pem_public_key(user_public_key_pem)
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, username),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(int_cert.subject)
        .public_key(user_pub)
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(int_key, hashes.SHA256())
    )
    print(f"[PKI] Certificado X.509 generado para usuario '{username}'.")
    return cert
