import os
import json
import base64
import io
from flask import Flask, request, render_template_string, redirect, url_for, flash, session, send_file

# IMPORTANTE: Importamos el módulo renombrado
import almacenamiento 
from gestion_de_usuarios import UserManager
import cifrado_simetrico
import pki_utils
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

app = Flask(__name__)
app.secret_key = 'CLAVE_SECRETA_PARA_SESIONES' 

user_manager = UserManager()

# --- HTML TEMPLATES ---
LOGIN_HTML = """
<!doctype html>
<html>
<head><title>SecureShare</title></head>
<body>
<h1>SecureShare (PKI + AES)</h1>
{% with messages = get_flashed_messages() %}
  {% if messages %}
    <div style="background:#f0f0f0; padding:10px; border:1px solid #ccc;">
        <ul>{% for msg in messages %}<li>{{ msg }}</li>{% endfor %}</ul>
    </div>
  {% endif %}
{% endwith %}

<div style="float:left; width:45%; border-right:1px solid #ccc; padding-right:10px;">
    <h3>Iniciar Sesión</h3>
    <form method="post" action="/login">
        Usuario: <input type="text" name="username" required><br>
        Clave: <input type="password" name="password" required><br><br>
        <input type="submit" value="Entrar">
    </form>
</div>
<div style="float:right; width:45%;">
    <h3>Registrarse</h3>
    <form method="post" action="/register">
        Usuario: <input type="text" name="username" required><br>
        Clave: <input type="password" name="password" required><br><br>
        <input type="submit" value="Crear Cuenta">
    </form>
</div>
</body>
</html>
"""

DASHBOARD_HTML = """
<!doctype html>
<html>
<head><title>Dashboard - {{ session['user'] }}</title></head>
<body>
<h2>Bienvenido, {{ session['user'] }} <small>(<a href="/logout">Salir</a>)</small></h2>

{% with messages = get_flashed_messages() %}
  {% if messages %}
    <div style="background:#e8f4f8; padding:10px; margin-bottom:10px; border:1px solid #bce8f1;">
        <ul>{% for msg in messages %}<li>{{ msg }}</li>{% endfor %}</ul>
    </div>
  {% endif %}
{% endwith %}

<hr>
<h3>1. Subir Nuevo Archivo</h3>
<form method="post" action="/upload" enctype="multipart/form-data">
    <input type="file" name="file" required>
    <input type="submit" value="Cifrar y Guardar">
</form>

<hr>
<h3>2. Mis Archivos Protegidos</h3>
{% if files %}
    <ul>
    {% for f in files %}
        <li style="margin-bottom: 8px;">
            <b>{{ f }}</b> 
            [<a href="/download/{{ f }}">Descargar</a>]
            
            <form action="/share" method="post" style="display:inline; margin-left: 20px;">
                <input type="hidden" name="filename" value="{{ f }}">
                Compartir con: <input type="text" name="recipient" placeholder="Usuario destino" required size="10">
                <input type="submit" value="Enviar (RSA)">
            </form>
        </li>
    {% endfor %}
    </ul>
{% else %}
    <p><i>No tienes archivos guardados.</i></p>
{% endif %}

<hr>
<h3>3. Bandeja de Entrada (Archivos Compartidos)</h3>
{% if shared %}
    <ul>
    {% for s in shared %}
        <li>
            <b>{{ s }}</b> 
            <form action="/receive/{{ s }}" method="post" style="display:inline;">
                 <input type="submit" value="Importar y Descifrar">
            </form>
        </li>
    {% endfor %}
    </ul>
{% else %}
    <p><i>No tienes archivos compartidos pendientes.</i></p>
{% endif %}

</body>
</html>
"""

@app.route('/')
def index():
    if 'user' in session:
        # Usamos almacenamiento en lugar de storage
        st = almacenamiento.UserStorageManager(session['user'])
        
        my_files = st.list_files()
        inbox_files = st.list_shared_files()
        
        return render_template_string(DASHBOARD_HTML, files=my_files, shared=inbox_files)
    return render_template_string(LOGIN_HTML)

@app.route('/register', methods=['POST'])
def register():
    try:
        user_manager.register_user(request.form['username'], request.form['password'])
        flash("Usuario registrado exitosamente. Certificado generado.")
    except Exception as e:
        flash(f"Error de registro: {e}")
    return redirect(url_for('index'))

@app.route('/login', methods=['POST'])
def login():
    try:
        user = request.form['username']
        master_key, priv_key_pem = user_manager.login_user(user, request.form['password'])
        
        session['user'] = user
        # Guardamos claves en sesión (en Base64 para ser JSON serializable)
        session['master_key_b64'] = base64.b64encode(master_key).decode()
        session['priv_key_pem'] = priv_key_pem.decode()
        
        flash("Inicio de sesión correcto.")
    except Exception as e:
        flash(f"Error login: {e}")
    return redirect(url_for('index'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/upload', methods=['POST'])
def upload():
    if 'user' not in session: return redirect('/')
    f = request.files['file']
    if f and f.filename:
        try:
            data = f.read()
            mk = base64.b64decode(session['master_key_b64'])
            # Cifrar
            pkg = cifrado_simetrico.encrypt_file_with_wrapped_key(mk, data)
            # Guardar
            st = almacenamiento.UserStorageManager(session['user'])
            st.save_package(f.filename, pkg)
            flash(f"Archivo '{f.filename}' cifrado y almacenado correctamente.")
        except Exception as e:
            flash(f"Error subiendo archivo: {e}")
    return redirect('/')

@app.route('/download/<path:filename>')
def download(filename):
    if 'user' not in session: return redirect('/')
    try:
        st = almacenamiento.UserStorageManager(session['user'])
        pkg = st.load_package(filename)
        mk = base64.b64decode(session['master_key_b64'])
        plaintext = cifrado_simetrico.decrypt_file_with_wrapped_key(mk, pkg)
        
        return send_file(
            io.BytesIO(plaintext),
            download_name=filename,
            as_attachment=True
        )
    except Exception as e:
        flash(f"Error descargando/descifrando: {e}")
        return redirect('/')

@app.route('/share', methods=['POST'])
def share():
    if 'user' not in session: return redirect('/')
    
    sender = session['user']
    recipient = request.form['recipient']
    filename = request.form['filename']
    
    # Evitar compartir con uno mismo (opcional)
    if sender == recipient:
        flash("No puedes compartir archivos contigo mismo (ya los tienes).")
        return redirect('/')

    # 1. Obtener certificado (Clave Pública) del destinatario
    dest_cert_pem = user_manager.get_user_certificate(recipient)
    if not dest_cert_pem:
        flash(f"El usuario '{recipient}' no existe.")
        return redirect('/')
        
    try:
        # 2. Cargar mi archivo cifrado
        st_sender = almacenamiento.UserStorageManager(sender)
        pkg = st_sender.load_package(filename)
        
        # 3. Descifrar la 'file_key' usando mi clave maestra
        mk = base64.b64decode(session['master_key_b64'])
        owner_key, _ = cifrado_simetrico.split_master_key(mk)
        aesgcm_wrap = AESGCM(owner_key)
        
        file_key = aesgcm_wrap.decrypt(
            base64.b64decode(pkg['wrap_nonce']), 
            base64.b64decode(pkg['wrapped_filekey']), 
            None
        )
        
        # 4. Cifrar la 'file_key' con la Clave Pública RSA del destinatario
        enc_file_key = pki_utils.encrypt_rsa(dest_cert_pem, file_key)
        
        # 5. Crear el paquete de compartición (Metadata + Datos Cifrados + Key RSA)
        share_pkg = {
            "sender": sender,
            "filename": filename,
            "enc_nonce": pkg['enc_nonce'],
            "ciphertext": pkg['ciphertext'], # El contenido pesado no se re-cifra, solo la llave
            "rsa_enc_key": base64.b64encode(enc_file_key).decode() 
        }
        
        # 6. Guardar en el inbox del destinatario
        st_recipient = almacenamiento.UserStorageManager(recipient)
        st_recipient.save_shared_package(f"{filename}_de_{sender}", share_pkg)
            
        flash(f"Archivo compartido exitosamente con {recipient}.")
        
    except Exception as e:
        flash(f"Error al compartir: {e}")
        
    return redirect('/')

@app.route('/receive/<path:share_name>', methods=['POST'])
def receive(share_name):
    """Importa un archivo compartido al almacenamiento propio."""
    if 'user' not in session: return redirect('/')
    
    try:
        st = almacenamiento.UserStorageManager(session['user'])
        
        # 1. Cargar el paquete compartido
        share_pkg = st.load_shared_package(share_name)
            
        # 2. Descifrar la file_key usando mi Clave Privada RSA
        priv_pem = session['priv_key_pem'].encode()
        priv_key = pki_utils.deserialize_private_key(priv_pem)
        
        rsa_ct = base64.b64decode(share_pkg['rsa_enc_key'])
        file_key = pki_utils.decrypt_rsa(priv_key, rsa_ct)
        
        # 3. Re-envolver la file_key con mi Clave Maestra AES (para guardarlo como propio)
        mk = base64.b64decode(session['master_key_b64'])
        owner_key, hmac_key = cifrado_simetrico.split_master_key(mk)
        
        aesgcm_wrap = AESGCM(owner_key)
        wrap_nonce = os.urandom(12)
        wrapped_filekey = aesgcm_wrap.encrypt(wrap_nonce, file_key, None)
        
        # Recalcular HMAC para el nuevo envoltorio
        enc_nonce_bytes = base64.b64decode(share_pkg['enc_nonce'])
        ciphertext_bytes = base64.b64decode(share_pkg['ciphertext'])
        
        from cryptography.hazmat.primitives import hashes, hmac
        h = hmac.HMAC(hmac_key, hashes.SHA256())
        h.update(enc_nonce_bytes + ciphertext_bytes)
        mac = h.finalize()
        
        # 4. Crear el paquete de formato propio
        new_pkg = {
            'enc_nonce': share_pkg['enc_nonce'],
            'ciphertext': share_pkg['ciphertext'],
            'wrap_nonce': base64.b64encode(wrap_nonce).decode(),
            'wrapped_filekey': base64.b64encode(wrapped_filekey).decode(),
            'mac': base64.b64encode(mac).decode()
        }
        
        # 5. Guardar en mi almacenamiento
        final_name = f"recibido_{share_pkg['filename']}"
        st.save_package(final_name, new_pkg)
        
        # 6. Borrar del inbox
        st.remove_shared_package(share_name)
        
        flash(f"Archivo importado correctamente como '{final_name}'")
        
    except Exception as e:
        flash(f"Error recibiendo archivo: {e}")
        
    return redirect('/')

if __name__ == '__main__':
    # Generar CA si no existe (llamando a la utilidad)
    pki_utils.load_or_create_ca()
    app.run(debug=True, port=5000)