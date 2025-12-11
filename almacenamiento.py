import os
import json
from pathlib import Path

class UserStorageManager:
    def __init__(self, user: str):
        self.__user = user
        # Carpeta raíz donde se guardan los datos de todos los usuarios
        self.STORAGE_ROOT = Path('storage_data') 
        self.STORAGE_ROOT.mkdir(exist_ok=True)
        # Crear carpeta del usuario
        self.user_dir = self.STORAGE_ROOT / self.__user
        self.user_dir.mkdir(parents=True, exist_ok=True)
        # Crear buzón de entrada para archivos compartidos
        self.inbox_dir = self.user_dir / "inbox"
        self.inbox_dir.mkdir(exist_ok=True)

    def get_dir(self):
        return self.user_dir

    def save_package(self, filename: str, package: dict):
        """Guarda un archivo cifrado propio."""
        pkg_path = self.user_dir / f"{filename}.pkg.json"
        with open(pkg_path, 'w', encoding='utf-8') as f:
            json.dump(package, f, indent=2)

    def load_package(self, filename: str) -> dict:
        """Carga un archivo propio."""
        # Si el nombre viene con extension .pkg.json, limpiarlo para evitar duplicados
        if not filename.endswith(".pkg.json"):
            filename = f"{filename}.pkg.json"
            
        pkg_path = self.user_dir / filename
        if not pkg_path.exists():
            raise FileNotFoundError(f'Archivo {filename} no encontrado')
        with open(pkg_path, 'r', encoding='utf-8') as f:
            return json.load(f)

    def list_files(self):
        """Lista los archivos propios (excluyendo el inbox)."""
        files = []
        for p in self.user_dir.glob('*.pkg.json'):
            # Quitamos la extensión .pkg.json para mostrar el nombre limpio
            name = p.name.replace(".pkg.json", "")
            files.append(name)
        return files

    def save_shared_package(self, filename: str, package: dict):
        """Guarda un paquete en el INBOX de este usuario (usado al recibir shares)."""
        share_path = self.inbox_dir / f"{filename}.rsa.json"
        with open(share_path, 'w', encoding='utf-8') as f:
            json.dump(package, f, indent=2)

    def load_shared_package(self, filename: str) -> dict:
        """Carga un paquete del INBOX."""
        if not filename.endswith(".rsa.json"):
            filename = f"{filename}.rsa.json"
        
        share_path = self.inbox_dir / filename
        if not share_path.exists():
            raise FileNotFoundError('Archivo compartido no encontrado')
        with open(share_path, 'r', encoding='utf-8') as f:
            return json.load(f)
            
    def list_shared_files(self):
        """Lista archivos pendientes en el inbox."""
        files = []
        for p in self.inbox_dir.glob('*.rsa.json'):
            name = p.name.replace(".rsa.json", "")
            files.append(name)
        return files

    def remove_shared_package(self, filename: str):
        """Borra un archivo del inbox después de procesarlo."""
        if not filename.endswith(".rsa.json"):
            filename = f"{filename}.rsa.json"
        os.remove(self.inbox_dir / filename)