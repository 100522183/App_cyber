# CLI SecureShare con sesión persistente
import argparse
import sys
import os 
import base64
import json
from gestion_de_usuarios import register_user, get_master_key_for_user
from cifrado_simetrico import (
    encrypt_file_with_wrapped_key,
    decrypt_file_with_wrapped_key,
    create_share_token_from_package,
    recover_filekey_from_share_token,
)
import storage

SESSION_FILE = "session.json"


def save_session(user: str, master_key: bytes):
    data = {"user": user, "master": base64.b64encode(master_key).decode()}
    with open(SESSION_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f)
    print(f"[Sesión] Guardada sesión activa de '{user}'.")


def load_session():
    if not os.path.exists(SESSION_FILE):
        return None
    with open(SESSION_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)
    data["master"] = base64.b64decode(data["master"])
    return data


def clear_session():
    if os.path.exists(SESSION_FILE):
        os.remove(SESSION_FILE)
        print("[Sesión] Cerrada y eliminada.")


def require_login():
    session = load_session()
    if not session:
        print("Por favor haz login primero.")
        return None
    return session


def cmd_register(args):
    try:
        register_user(args.user, args.password)
    except Exception as e:
        print("Error registrando:", e)


def cmd_login(args):
    try:
        master = get_master_key_for_user(args.user, args.password)
        save_session(args.user, master)
        print(f"Sesión iniciada como {args.user}")
    except Exception as e:
        print("Login fallido:", e)


def cmd_logout(args):
    clear_session()


def cmd_upload(args):
    session = require_login()
    if not session:
        return
    if not os.path.exists(args.path):
        print("Ruta de fichero no encontrada.")
        return
    with open(args.path, "rb") as f:
        data = f.read()
    package = encrypt_file_with_wrapped_key(session["master"], data)
    storage.save_package(session["user"], args.name or os.path.basename(args.path), package)


def cmd_list(args):
    session = require_login()
    if not session:
        return
    files = storage.list_files(session["user"])
    print("Archivos de", session["user"])
    for f in files:
        print(" -", f)


def cmd_download(args):
    session = require_login()
    if not session:
        return
    try:
        pkg = storage.load_package(session["user"], args.name)
        plaintext = decrypt_file_with_wrapped_key(session["master"], pkg)
        out_dir = "downloads"
        os.makedirs(out_dir, exist_ok=True)
        out_path = os.path.join(out_dir, args.name)
        with open(out_path, "wb") as f:
            f.write(plaintext)
        print("Archivo descifrado guardado en", out_path)
    except Exception as e:
        print("Error descargando:", e)


def cmd_share(args):
    session = require_login()
    if not session:
        return
    try:
        pkg = storage.load_package(session["user"], args.name)
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        owner_key = session["master"][:32]
        wrap_nonce = base64.b64decode(pkg["wrap_nonce"])
        wrapped_filekey = base64.b64decode(pkg["wrapped_filekey"])
        aesgcm_wrap = AESGCM(owner_key)
        file_key = aesgcm_wrap.decrypt(wrap_nonce, wrapped_filekey, None)
        token = create_share_token_from_package(pkg, file_key, args.passphrase)
        tname = args.token_name or (args.name + "_token")
        storage.save_share_token(session["user"], tname, token)
        print("Token creado. Entrega token + passphrase al destinatario.")
    except Exception as e:
        print("Error compartiendo archivo:", e)


def cmd_receive(args):
    """El receptor recibe un token y un paquete cifrado del remitente, 
    reenvuelve la clave de archivo con su propia master key y recalcula el HMAC."""
    session = require_login()
    if not session:
        return
    try:
        import json, base64, os
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives import hashes, hmac

        # Cargar el token de compartición (desde ruta o desde almacenamiento local)
        if args.token_path:
            with open(args.token_path, 'r', encoding='utf-8') as f:
                token = json.load(f)
        else:
            token = storage.load_share_token(session['user'], args.token_name)

        # Recuperar la file_key usando la passphrase
        from cifrado_simetrico import recover_filekey_from_share_token
        file_key = recover_filekey_from_share_token(token, args.passphrase)

        # Cargar el paquete original (.pkg.json) del remitente
        if not args.pkg_path:
            print("Debes proporcionar --pkg-path (ruta al paquete original del propietario).")
            return
        with open(args.pkg_path, 'r', encoding='utf-8') as f:
            orig_pkg = json.load(f)

        # Reenvolver la file_key con la master key del receptor (su propio owner_key)
        recipient_owner_key = session["master"][:32]
        aesgcm_wrap = AESGCM(recipient_owner_key)
        new_wrap_nonce = os.urandom(12)
        new_wrapped = aesgcm_wrap.encrypt(new_wrap_nonce, file_key, None)

        # Recalcular nuevo HMAC con la hmac_key del receptor
        recipient_hmac_key = session["master"][32:64]
        enc_nonce = base64.b64decode(orig_pkg["enc_nonce"])
        ciphertext = base64.b64decode(orig_pkg["ciphertext"])
        h = hmac.HMAC(recipient_hmac_key, hashes.SHA256())
        h.update(enc_nonce + ciphertext)
        new_mac = base64.b64encode(h.finalize()).decode()

        # Construir el nuevo paquete completo
        new_pkg = {
            "enc_nonce": orig_pkg["enc_nonce"],
            "ciphertext": orig_pkg["ciphertext"],
            "wrap_nonce": base64.b64encode(new_wrap_nonce).decode(),
            "wrapped_filekey": base64.b64encode(new_wrapped).decode(),
            "mac": new_mac,
        }

        # Guardar el paquete cifrado en el almacenamiento del receptor
        target_name = args.save_as or (
            "received_" + os.path.basename(args.pkg_path).replace(".pkg.json", "")
        )
        storage.save_package(session["user"], target_name, new_pkg)

        print(f"[Receive] Archivo recibido y guardado como '{target_name}'.")
        print("[Receive] Nuevo HMAC recalculado correctamente para el receptor.")

    except Exception as e:
        print("Error recibiendo archivo:", e)

def build_parser():
    p = argparse.ArgumentParser(description="SecureShare CLI")
    sp = p.add_subparsers(dest="cmd")

    sp.add_parser("logout").set_defaults(func=cmd_logout)

    reg = sp.add_parser("register")
    reg.add_argument("user")
    reg.add_argument("password")
    reg.set_defaults(func=cmd_register)

    login = sp.add_parser("login")
    login.add_argument("user")
    login.add_argument("password")
    login.set_defaults(func=cmd_login)

    upl = sp.add_parser("upload")
    upl.add_argument("path")
    upl.add_argument("--name", default=None)
    upl.set_defaults(func=cmd_upload)

    lst = sp.add_parser("list")
    lst.set_defaults(func=cmd_list)

    dwn = sp.add_parser("download")
    dwn.add_argument("name")
    dwn.set_defaults(func=cmd_download)

    shr = sp.add_parser("share")
    shr.add_argument("name")
    shr.add_argument("passphrase")
    shr.add_argument("--token-name", dest="token_name")
    shr.set_defaults(func=cmd_share)

    rcv = sp.add_parser("receive")
    rcv.add_argument("passphrase")
    rcv.add_argument("--token-path", default=None)
    rcv.add_argument("--pkg-path", default=None)
    rcv.add_argument("--save-as", default=None)
    rcv.set_defaults(func=cmd_receive)

    return p


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if not hasattr(args, "func"):
        parser.print_help()
        return
    args.func(args)


if __name__ == "__main__":
    main()
