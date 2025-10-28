# Funciones simples para guardar y leer paquetes cifrados y metadatos en disco.
import os
import json
import base64
from pathlib import Path

STORAGE_ROOT = Path('storage')
STORAGE_ROOT.mkdir(exist_ok=True)

def user_dir(username: str):
    d = STORAGE_ROOT / username
    d.mkdir(parents=True, exist_ok=True)
    return d

def save_package(username: str, filename: str, package: dict):
    d = user_dir(username)
    file_id = filename
    pkg_path = d / f"{file_id}.pkg.json"
    with open(pkg_path, 'w', encoding='utf-8') as f:
        json.dump(package, f, indent=2)
    print(f"[Storage] Archivo guardado como {pkg_path}")

def load_package(username: str, filename: str) -> dict:
    d = user_dir(username)
    pkg_path = d / f"{filename}.pkg.json"
    if not pkg_path.exists():
        raise FileNotFoundError('Archivo no encontrado en storage')
    with open(pkg_path, 'r', encoding='utf-8') as f:
        return json.load(f)

def list_files(username: str):
    d = user_dir(username)
    files = []
    for p in d.glob('*.pkg.json'):
        name = p.stem
        if name.endswith('.pkg'):
            name = name[:-4]
        files.append(name)
    return files

def save_share_token(username: str, token_name: str, token: dict):
    d = user_dir(username)
    tpath = d / f"{token_name}.share.json"
    with open(tpath, 'w', encoding='utf-8') as f:
        json.dump(token, f, indent=2)
    print(f"[Storage] Token de compartición guardado en {tpath}")

def load_share_token(username: str, token_name: str) -> dict:
    d = user_dir(username)
    tpath = d / f"{token_name}.share.json"
    if not tpath.exists():
        raise FileNotFoundError('Token no encontrado')
    with open(tpath, 'r', encoding='utf-8') as f:
        return json.load(f)
