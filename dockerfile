# Usamos una imagen base ligera de Python
FROM python:3.9-slim

# Establecemos el directorio de trabajo
WORKDIR /app

# Copiamos los archivos de requerimientos e instalamos dependencias
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copiamos el resto del código
COPY . .

# Inicializamos la base de datos (Script simple para que funcione al arrancar)
# NOTA: En producción real, la DB no debería estar dentro del contenedor de esta forma.
RUN python -c "import sqlite3; conn = sqlite3.connect('example.db'); conn.execute('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT)'); conn.execute('CREATE TABLE IF NOT EXISTS comments (id INTEGER PRIMARY KEY, user_id INTEGER, comment TEXT)'); conn.close()"

# Exponemos el puerto 5000
EXPOSE 5000

# Comando para ejecutar la app
CMD ["python", "vulnerable_flask_app.py"]