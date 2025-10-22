# main.py
"""
Aplicación principal: demostración de almacenamiento seguro
Cumple con los requisitos de la práctica de Criptografía y Seguridad Informática.
"""
import base64
from gestion_de_usuarios import register_user, users_db, authenticate_user
from cifrado_simetrico import encrypt_data, decrypt_data
from firma_digital import sign_data, verify_signature
from pki_certificados import create_root_ca, create_intermediate_ca, sign_user_certificate

def main():
    print("\n=== 🔐 DEMOSTRACIÓN DE SISTEMA DE ALMACENAMIENTO SEGURO ===\n")

    # 1️⃣ Registro y autenticación de usuario
    print("→ Registrando usuario...")
    register_user("alice", "mi_contraseña_segura")

    print("→ Autenticando usuario...")
    authenticate_user("alice", "mi_contraseña_segura")

    # 2️⃣ Obtener claves del usuario
    alice_pub = base64.b64decode(users_db["alice"]["public_key"])
    alice_priv = base64.b64decode(users_db["alice"]["private_key"])
    alice_pass = "mi_contraseña_segura".encode("utf-8")

    # 3️⃣ Crear infraestructura PKI (CA raíz + intermedia)
    print("\n→ Creando infraestructura de certificados (PKI)...")
    root_key, root_cert = create_root_ca()
    inter_key, inter_cert = create_intermediate_ca(root_key, root_cert)
    user_cert = sign_user_certificate("alice", alice_pub, inter_key, inter_cert)
    print("Certificado emitido para:", user_cert.subject)

    # 4️⃣ Cifrar un archivo / mensaje
    mensaje = b"Este es un archivo confidencial almacenado de forma segura."
    print("\n→ Cifrando archivo con AES-GCM y RSA-OAEP...")
    ciphertext, nonce, enc_key = encrypt_data(mensaje, alice_pub)

    # 5️⃣ Descifrar el archivo
    print("\n→ Descifrando archivo...")
    texto_descifrado = decrypt_data(ciphertext, nonce, enc_key, alice_priv, alice_pass)
    print("Texto descifrado:", texto_descifrado.decode("utf-8"))

    # 6️⃣ Firmar el archivo
    print("\n→ Firmando archivo con clave privada de Alice (RSA-PSS)...")
    firma = sign_data(mensaje, alice_priv, alice_pass)
    print("Firma generada:", base64.b64encode(firma).decode()[:80], "...")

    # 7️⃣ Verificar la firma
    print("\n→ Verificando la firma digital...")
    verify_signature(mensaje, firma, alice_pub)

    print("\n✅ Proceso completado correctamente.")
    print("Todos los requisitos criptográficos se demostraron en esta ejecución.")

if __name__ == "__main__":
    main()
