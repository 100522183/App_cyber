import argparse
import sys
import os
import base64
from gestion_de_usuarios import register_user, authenticate_user, get_master_key_for_user, users_db
from cifrado_simetrico import encrypt_file_with_wrapped_key, decrypt_file_with_wrapped_key, create_share_token_from_package, recover_filekey_from_share_token
import storage

SESSION = {'user': None, 'master': None}

def cmd_register(args):
    try:
        register_user(args.user, args.password)
    except Exception as e:
        print('Error registrando:', e)

def cmd_login(args):
    try:
        master = get_master_key_for_user(args.user, args.password)
        SESSION['user'] = args.user
        SESSION['master'] = master
        print(f"Sesión iniciada como {args.user}")
    except Exception as e:
        print('Login fallido:', e)

def require_login():
    if not SESSION['user']:
        print('Por favor haz login primero.')
        return False
    return True

def cmd_upload(args):
    if not require_login():
        return
    if not os.path.exists(args.path):
        print('Ruta de fichero no encontrada.')
        return
    with open(args.path, 'rb') as f:
        data = f.read()
    package = encrypt_file_with_wrapped_key(SESSION['master'], data)
    storage.save_package(SESSION['user'], args.name or os.path.basename(args.path), package)

def cmd_list(args):
    if not require_login():
        return
    files = storage.list_files(SESSION['user'])
    print('Archivos de', SESSION['user'])
    for f in files:
        print(' -', f)

def cmd_download(args):
    if not require_login():
        return
    try:
        pkg = storage.load_package(SESSION['user'], args.name)
        plaintext = decrypt_file_with_wrapped_key(SESSION['master'], pkg)
        out_dir = 'downloads'
        os.makedirs(out_dir, exist_ok=True)
        out_path = os.path.join(out_dir, args.name)
        with open(out_path, 'wb') as f:
            f.write(plaintext)
        print('Archivo descifrado guardado en', out_path)
    except Exception as e:
        print('Error descargando:', e)

def cmd_share(args):
    if not require_login():
        return
    try:
        pkg = storage.load_package(SESSION['user'], args.name)
        # Need to recover file_key to create token: decrypt wrapped_filekey with master
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        import base64
        owner_key = SESSION['master'][:32]
        wrap_nonce = base64.b64decode(pkg['wrap_nonce'])
        wrapped_filekey = base64.b64decode(pkg['wrapped_filekey'])
        aesgcm_wrap = AESGCM(owner_key)
        file_key = aesgcm_wrap.decrypt(wrap_nonce, wrapped_filekey, None)
        token = create_share_token_from_package(pkg, file_key, args.passphrase)
        # Save token for owner
        tname = args.token_name or (args.name + '_token')
        storage.save_share_token(SESSION['user'], tname, token)
        print('Token creado. Entrega token + passphrase al destinatario.')
    except Exception as e:
        print('Error compartiendo archivo:', e)

def cmd_receive(args):
    # recipient loads token file from another user's storage manually (simulate by path)
    if not require_login():
        return
    try:
        # load token from path provided
        if args.token_path:
            import json
            with open(args.token_path, 'r', encoding='utf-8') as f:
                token = json.load(f)
        else:
            # or load from own storage (if teacher saved)
            token = storage.load_share_token(SESSION['user'], args.token_name)
        file_key = recover_filekey_from_share_token(token, args.passphrase)
        # Now we need to create a new package that uses our master to wrap this file_key so we can store it
        # For simplicity, require user to also provide original pkg path (owner's pkg) path via args.pkg_path
        if not args.pkg_path:
            print('Para recibir necesita --pkg-path (ruta al paquete .pkg.json original del propietario).')
            return
        import json, base64
        with open(args.pkg_path, 'r', encoding='utf-8') as f:
            orig_pkg = json.load(f)
        # Re-wrap file_key with recipient master
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        recipient_owner_key = SESSION['master'][:32]
        aesgcm_wrap = AESGCM(recipient_owner_key)
        new_wrap_nonce = os.urandom(12)
        new_wrapped = aesgcm_wrap.encrypt(new_wrap_nonce, file_key, None)
        # Build new package: keep enc_nonce and ciphertext and mac from original, replace wrap fields
        new_pkg = {
            'enc_nonce': orig_pkg['enc_nonce'],
            'ciphertext': orig_pkg['ciphertext'],
            'wrap_nonce': base64.b64encode(new_wrap_nonce).decode(),
            'wrapped_filekey': base64.b64encode(new_wrapped).decode(),
            'mac': orig_pkg['mac']
        }
        # Save into recipient storage with provided new name
        target_name = args.save_as or ('received_' + os.path.basename(args.pkg_path).replace('.pkg.json',''))
        storage.save_package(SESSION['user'], target_name, new_pkg)
        print('Archivo recibido y almacenado como', target_name)
    except Exception as e:
        print('Error recibiendo archivo:', e)

def cmd_logout(args):
    SESSION['user'] = None
    SESSION['master'] = None
    print('Sesión cerrada.')

def build_parser():
    p = argparse.ArgumentParser(description='SecureShare CLI')
    sp = p.add_subparsers(dest='cmd')

    p_register = sp.add_parser('register')
    p_register.add_argument('user')
    p_register.add_argument('password')
    p_register.set_defaults(func=cmd_register)

    p_login = sp.add_parser('login')
    p_login.add_argument('user')
    p_login.add_argument('password')
    p_login.set_defaults(func=cmd_login)

    p_upload = sp.add_parser('upload')
    p_upload.add_argument('path')
    p_upload.add_argument('--name', default=None)
    p_upload.set_defaults(func=cmd_upload)

    p_list = sp.add_parser('list')
    p_list.set_defaults(func=cmd_list)

    p_download = sp.add_parser('download')
    p_download.add_argument('name')
    p_download.set_defaults(func=cmd_download)

    p_share = sp.add_parser('share')
    p_share.add_argument('name')
    p_share.add_argument('passphrase')
    p_share.add_argument('--token-name', dest='token_name')
    p_share.set_defaults(func=cmd_share)

    p_receive = sp.add_parser('receive')
    p_receive.add_argument('passphrase')
    p_receive.add_argument('--token-path', default=None)
    p_receive.add_argument('--pkg-path', default=None)
    p_receive.add_argument('--save-as', default=None)
    p_receive.set_defaults(func=cmd_receive)

    p_logout = sp.add_parser('logout')
    p_logout.set_defaults(func=cmd_logout)

    return p

def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if not hasattr(args, 'func'):
        parser.print_help()
        return
    args.func(args)

if __name__ == '__main__':
    main()
