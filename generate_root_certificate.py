import os
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography import x509
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta, timezone  # Import timezone
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import shutil
import base64
from cryptography.hazmat.primitives.serialization import NoEncryption

def encrypt_with_aes(key: bytes, plaintext: bytes):
    """Esta función encripta un texto en plano usando una llave usando aesgcm para verificar la integridad del mensaje

    Args:
        key (bytes): La llave provista 
        plaintext (bytes): El texto en plano a cifrar

    Returns:
        list: lista de los parámetros necesarios para desencriptar posteriormente: nonce, ciphertext y tag
    """
    # Genera un nonce
    nonce = os.urandom(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce))
    encryptor = cipher.encryptor()
    
    # Cifra el texto en plano
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return nonce, ciphertext, encryptor.tag

def create_ca():
    """Genera la carpeta en la que se guardarán los archivos necesarios para el funcionamiento de la ca:
    Certificado: Guardado sin encriptar como root_ca.cert, autofirmado
    Clave privada: Encriptada guardada como root_ca_enc.key usando Aesgcm
    Tag: Necesaria para verificar que la clave privada no ha sido alterada sin permiso 
    Nonce: Necesario para descifrar la clave privada
    También se imprime una passphrase que el usuario debe guardar para poder acceder a la ca y desencriptar la clave privada
    """
    # Genera la carpeta de la autoridad si no existe
    shutil.rmtree("CA_ROOT", ignore_errors=True)
    root_path = Path("CA_ROOT")
    root_path.mkdir(parents=True, exist_ok=True)

    # Genera una llave privada
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    # Construye el certificado autofirmado
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"ES"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Madrid"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Leganés"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Secure Share"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"Root CA"),
    ])
    
    certificate = (x509.CertificateBuilder()
                   .subject_name(subject)
                   .issuer_name(issuer)
                   .public_key(private_key.public_key())
                   .serial_number(int.from_bytes(os.urandom(16), "big"))
                   .not_valid_before(datetime.now(timezone.utc))  # Use timezone-aware UTC datetime
                   .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
                   .sign(private_key, hashes.SHA256()))

    # Genera una llave aes
    aes_key = os.urandom(32)

    # Encripta la clave privada usando aes
    private_key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=NoEncryption()
    )

    nonce, encrypted_key, tag = encrypt_with_aes(aes_key, private_key_bytes)

    # Guardamos los datos a los archivos
    encrypted_key_path = root_path / "root_ca_enc.key"
    nonce_path = root_path / "root_ca_enc.nonce"
    tag_path = root_path / "root_ca_enc.tag"
    certificate_path = root_path / "root_ca.cert"
    
    with encrypted_key_path.open("wb") as key_file:
        key_file.write(encrypted_key)

    with nonce_path.open("wb") as nonce_file:
        nonce_file.write(nonce)

    with tag_path.open("wb") as tag_file:
        tag_file.write(tag)

    with certificate_path.open("wb") as cert_file:
        cert_file.write(certificate.public_bytes(serialization.Encoding.PEM))

    # Devolvemos la clave aes en un formato seguro como base64, lo guardamos en un archivo para facilitar la práctica, esto no se debería hacer así
    aes_key_base64 = base64.b64encode(aes_key).decode('utf-8')
    print("CA certificate and encrypted key created successfully.")
    print(f"Your AES key (store it securely): {aes_key_base64}")
    with open("ca_master_key.secret", "w") as f:
                f.write(aes_key_base64)

if __name__ == "__main__":
    create_ca()
