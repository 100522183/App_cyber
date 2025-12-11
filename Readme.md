# Objetivo:
Aprender a implementar los principios criptográficos en python
# Requisitos:
1. Registro y autenticación de usuarios
- Autenticación basada en contraseñas o en tokens o en rasgos biométricos
2. Cifrado/descifrado simétrico y/o asimétrico (o con cifrado autenticado)
- Todos los cifrados deben mostrar los resultados y la longitud de clave en un log o mensaje de depuración
3. Generación/verificación de etiquetas de autenticación de mensajes (e.g., con funciones
hash y HMAC) (o con cifrado autenticado)
- Debemos usar cifrado autenticado y mostrar el resultado en un log o mensaje de depuración
4. Generación/verificación de firma digital
- Mínimo se debe generar en el sistema, es opcional que las generen los usuarios
- Las claves deben ser seguras
- Es aconsejable mostrar un log
5. Autenticación de las claves públicas mediante certificados (despliegue de PKI) 
- Hay una autoridad, pueden haber autoridades subordinadas que pueden emitir certificados de clave pública.

# Instalación rápida para que el codigo funcione (VS Code)
1. Abrir la carpeta del proyecto en VS Code.
2. Activar entorno virtual (venv):
   .\venv\Scripts\activate
3. Instalar dependencias:
   pip install -r requirements.txt