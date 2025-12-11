import os
import base64
import io
from flask import Flask, request, render_template, redirect, url_for, flash, session, send_file
from clase_usuario import User
from gestion_de_usuarios import UserManager
import pki_utils 

app = Flask(__name__)
app.secret_key = 'CLAVE_SECRETA_PARA_SESIONES' 

# Gestor global de usuarios
user_manager = UserManager()

def get_current_user() -> User:
    if 'user' not in session:
        return None
    
    username = session['user']
    try:
        master_key = base64.b64decode(session['master_key_b64'])
        priv_key_pem = session['priv_key_pem'].encode('utf-8')
        # Recuperamos el certificado de la sesión si existe, sino lo buscamos en disco (vía UserManager)
        # Nota: clase_usuario ahora lo busca solo, pero por seguridad pasamos el dummy si la sesión lo tiene
        # aunque la clase User lo gestiona internamente en el __init__ nuevo.
        # Para ser coherentes con la última versión de clase_usuario.py que hicimos (que solo pedía 3 args):
        return User(username, master_key, priv_key_pem)
    except Exception:
        return None

# --- RUTAS ---

@app.route('/')
def index():
    user = get_current_user()
    if user:
        # Si está logueado, vamos al Dashboard
        return render_template(
            'dashboard.html', # Usamos el archivo HTML
            user=user.username,
            files=user.list_my_files(), 
            shared=user.list_inbox_files()
        )
    # Si no, mostramos Login
    return render_template('login.html')

@app.route('/register_page')
def register_page():
    return render_template('register.html')

@app.route('/register', methods=['POST'])
def register():
    try:
        user_manager.register_user(request.form['username'], request.form['password'])
        flash("¡Cuenta creada exitosamente! Por favor, inicia sesión.")
        return redirect('/') # Redirige al login
    except Exception as e:
        flash(f"Error de registro: {e}")
        return redirect('/register_page')

@app.route('/login', methods=['POST'])
def login():
    try:
        username = request.form['username']
        master_key, priv_key_pem = user_manager.login_user(username, request.form['password'])
        
        session['user'] = username
        session['master_key_b64'] = base64.b64encode(master_key).decode()
        session['priv_key_pem'] = priv_key_pem.decode()
        
        flash("Bienvenido de nuevo.")
    except Exception as e:
        flash(f"Error de acceso: {e}")
    return redirect(url_for('index'))

@app.route('/logout')
def logout():
    session.clear()
    flash("Has cerrado sesión correctamente.")
    return redirect(url_for('index'))

@app.route('/upload', methods=['POST'])
def upload():
    user = get_current_user()
    if not user: return redirect('/')
    
    f = request.files['file']
    if f and f.filename:
        try:
            data = f.read()
            user.encrypt_and_save_file(f.filename, data)
            flash(f"Archivo '{f.filename}' protegido y guardado.")
        except Exception as e:
            flash(f"Error subiendo archivo: {e}")
    return redirect('/')

@app.route('/download/<path:filename>')
def download(filename):
    user = get_current_user()
    if not user: return redirect('/')
    
    try:
        plaintext = user.load_and_decrypt_file(filename)
        return send_file(
            io.BytesIO(plaintext),
            download_name=filename,
            as_attachment=True
        )
    except Exception as e:
        flash(f"Error descargando: {e}")
        return redirect('/')

@app.route('/share', methods=['POST'])
def share():
    user = get_current_user()
    if not user: return redirect('/')
    
    recipient = request.form['recipient']
    filename = request.form['filename']
    
    if user.username == recipient:
        flash("Error: No puedes compartir contigo mismo.")
        return redirect('/')

    dest_cert_pem = user_manager.get_user_certificate(recipient)
    if not dest_cert_pem:
        flash(f"El usuario '{recipient}' no existe o no tiene certificado.")
        return redirect('/')
        
    try:
        user.share_file(filename, recipient, dest_cert_pem)
        flash(f"Archivo enviado de forma segura a {recipient}.")
    except Exception as e:
        flash(f"Fallo al compartir: {e}")
        
    return redirect('/')

@app.route('/receive/<path:share_name>', methods=['POST'])
def receive(share_name):
    user = get_current_user()
    if not user: return redirect('/')
    
    try:
        final_name = user.receive_file(share_name)
        flash(f"Archivo verificado y descifrado: '{final_name}'")
    except Exception as e:
        flash(f"ERROR DE SEGURIDAD: {e}")
        
    return redirect('/')

if __name__ == '__main__':
    if not os.path.exists("CA_ROOT") or not os.path.exists("ca_master_key.secret"):
        print(">> Inicializando Infraestructura PKI...")
        import generate_root_certificate
        generate_root_certificate.create_ca()
        
    app.run(debug=True, port=5000)