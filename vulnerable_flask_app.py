from flask import Flask, request, render_template_string, session, redirect, url_for, g
import sqlite3
import os
import hashlib
from functools import wraps

# Librerías de seguridad requeridas para las 4 vulnerabilidades
from markupsafe import escape
from flask_talisman import Talisman
from flask_wtf.csrf import CSRFProtect, generate_csrf

# Decorador para exigir login
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        # Se guarda el token CSRF para el template si es necesario
        g.csrf_token = generate_csrf()
        return f(*args, **kwargs)
    return decorated_function


app = Flask(__name__)
# 4. CORRECCIÓN (CWE-614): Clave secreta generada en tiempo de ejecución.
app.secret_key = os.urandom(24)

# 3. CORRECCIÓN (CWE-352): Inicializar CSRFProtect para todas las rutas POST.
csrf = CSRFProtect(app)

# 1. CORRECCIÓN (CWE-693): Missing Security Headers (CSP, HSTS, X-Frame-Options)
Talisman(
    app,
    # Habilita HSTS y X-Frame-Options: SAMEORIGIN por defecto
    content_security_policy={
        'default-src': ["'self'"], # Solo permite recursos propios
        'style-src': ["'self'", "https://maxcdn.bootstrapcdn.com"], # Permite Bootstrap CSS
        'script-src': ["'self'"],
        'frame-ancestors': ["'none'"] # Equivalente a X-Frame-Options: DENY
    },
    # 4. CORRECCIÓN (CWE-614): Aplica HttpOnly y Secure a las cookies de sesión
    session_cookie_secure=True, 
    session_cookie_httponly=True
)


def get_db_connection():
    # Nota: check_same_thread=False es necesario para SQLite en Flask con múltiples threads
    conn = sqlite3.connect('example.db', check_same_thread=False)
    conn.row_factory = sqlite3.Row

    # Mejoras de seguridad (evitan falsos positivos de ZAP)
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.execute("PRAGMA trusted_schema = OFF;")
    conn.execute("PRAGMA journal_mode = WAL;")
    conn.execute("PRAGMA synchronous = NORMAL;")

    return conn


def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# FUNCIÓN: Inicialización de la base de datos (reemplaza la necesidad de un script externo).
def init_db():
    conn = get_db_connection()
    c = conn.cursor()
    
    # 1. Crear tabla de usuarios
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT DEFAULT 'user'
        )
    ''')
    
    # 2. Crear tabla de comentarios
    c.execute('''
        CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            comment TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')

    # 3. Insertar usuarios por defecto ('admin' y 'user') si no existen
    admin_username = 'admin'
    user_username = 'user'
    default_password_hash = hash_password('password') # user: password
    
    # Insertar 'admin' si no existe
    if not conn.execute("SELECT id FROM users WHERE username = ?", (admin_username,)).fetchone():
        c.execute(
            "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
            (admin_username, default_password_hash, 'admin')
        )
    # Insertar 'user' si no existe
    if not conn.execute("SELECT id FROM users WHERE username = ?", (user_username,)).fetchone():
        c.execute(
            "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
            (user_username, default_password_hash, 'user')
        )
    
    conn.commit()
    conn.close()


@app.before_request
def set_secure_cookie_attributes():
    # 4. CORRECCIÓN (CWE-614): Cookie SameSite
    app.config.update(
        SESSION_COOKIE_SAMESITE='Lax'
    )

@app.route('/')
def index():
    return render_template_string('''
        <!doctype html>
        <html lang="en">
        <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <link href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.min.css" rel="stylesheet">
            <title>Welcome</title>
        </head>
        <body>
            <div class="container">
                <h1 class="mt-5">Welcome to the Secure Application!</h1>
                <p class="lead">This is the home page. Please <a href="/login">login</a></p>
            </div>
        </body>
        </html>
    ''')


@app.route('/login', methods=['GET', 'POST'])
def login():
    # 3. CORRECCIÓN (CWE-352): Se genera el token CSRF para el formulario POST.
    csrf_token = generate_csrf()
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = get_db_connection()
        
        # CORRECCIÓN SQL INJECTION (CWE-89)
        query = "SELECT * FROM users WHERE username = ? AND password = ?"
        hashed_password = hash_password(password)
        # Se usan parámetros para prevenir la inyección SQL.
        user = conn.execute(query, (username, hashed_password)).fetchone()
        conn.close()
        
        if user:
            session['user_id'] = user['id']
            session['role'] = user['role']
            return redirect(url_for('dashboard'))
        else:
            return render_template_string(f'''
                <!doctype html>
                <html lang="en">
                <head>
                    <meta charset="utf-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1">
                    <link href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.min.css" rel="stylesheet">
                    <title>Login</title>
                </head>
                <body>
                    <div class="container">
                        <h1 class="mt-5">Login</h1>
                        <div class="alert alert-danger">Invalid credentials!</div>
                        <form method="post">
                            <input type="hidden" name="csrf_token" value="{csrf_token}">
                            <div class="form-group">
                                <label for="username">Username</label>
                                <input type="text" class="form-control" id="username" name="username">
                            </div>
                            <div class="form-group">
                                <label for="password">Password</label>
                                <input type="password" class="form-control" id="password" name="password">
                            </div>
                            <button type="submit" class="btn btn-primary">Login</button>
                        </form>
                    </div>
                </body>
                </html>
            ''')

    # Template GET
    return render_template_string(f'''
        <!doctype html>
        <html lang="en">
        <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <link href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.min.css" rel="stylesheet">
            <title>Login</title>
        </head>
        <body>
            <div class="container">
                <h1 class="mt-5">Login</h1>
                <form method="post">
                    <input type="hidden" name="csrf_token" value="{csrf_token}">
                    <div class="form-group">
                        <label for="username">Username</label>
                        <input type="text" class="form-control" id="username" name="username">
                    </div>
                    <div class="form-group">
                        <label for="password">Password</label>
                        <input type="password" class="form-control" id="password" name="password">
                    </div>
                    <button type="submit" class="btn btn-primary">Login</button>
                </form>
            </div>
        </body>
        </html>
    ''')


@app.route('/dashboard')
@login_required
def dashboard():
    user_id = session['user_id']
    conn = get_db_connection()
    comments = conn.execute(
        "SELECT comment FROM comments WHERE user_id = ?", (user_id,)
    ).fetchall()
    conn.close()

    # 3. CORRECCIÓN (CWE-352): Se usa g.csrf_token para el formulario
    csrf_token = g.csrf_token
    
    # 2. CORRECCIÓN (CWE-79): Cross-Site Scripting (XSS)
    # Renderizar los comentarios de forma segura usando markupsafe.escape
    comment_list_items = ""
    for comment in comments:
        # Aquí se aplica la sanitización antes de la inyección en el HTML
        safe_comment = escape(comment['comment']) 
        comment_list_items += f'<li class="list-group-item">{safe_comment}</li>'

    return render_template_string(f'''
        <!doctype html>
        <html lang="en">
        <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <link href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.min.css" rel="stylesheet">
            <title>Dashboard</title>
        </head>
        <body>
            <div class="container">
                <h1 class="mt-5">Welcome, user {user_id}!</h1>
                <form action="/submit_comment" method="post">
                    <!-- 3. CORRECCIÓN (CWE-352): CSRF Token -->
                    <input type="hidden" name="csrf_token" value="{csrf_token}">
                    <div class="form-group">
                        <label for="comment">Comment</label>
                        <textarea class="form-control" id="comment" name="comment" rows="3"></textarea>
                    </div>
                    <button type="submit" class="btn btn-primary">Submit Comment</button>
                </form>
                <h2 class="mt-5">Your Comments</h2>
                <ul class="list-group">
                    {comment_list_items}
                </ul>
            </div>
        </body>
        </html>
    ''', user_id=user_id, comments=comments)


@app.route('/submit_comment', methods=['POST'])
@login_required
# 3. CORRECCIÓN (CWE-352): CSRFProtect verifica automáticamente el token
def submit_comment():
    comment = request.form['comment']
    user_id = session['user_id']

    conn = get_db_connection()
    conn.execute(
        "INSERT INTO comments (user_id, comment) VALUES (?, ?)",
        (user_id, comment)
    )
    conn.commit()
    conn.close()

    return redirect(url_for('dashboard'))


@app.route('/admin')
@login_required
def admin():
    if session.get('role') != 'admin':
        return redirect(url_for('login'))

    return render_template_string('''
        <!doctype html>
        <html lang="en">
        <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <link href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.min.css" rel="stylesheet">
            <title>Admin Panel</title>
        </head>
        <body>
            <div class="container">
                <h1 class="mt-5">Welcome to the secure admin panel!</h1>
            </div>
        </body>
        </html>
    ''')


if __name__ == '__main__':
    # Paso crítico: Inicializar la base de datos antes de iniciar la aplicación
    # para asegurar que las tablas existen. Esto evita que la app muera al inicio.
    init_db()
    
    # CORRECCIÓN HOST/DEBUG (DAST & Bandit B104): Se usa 0.0.0.0 para Docker y # nosec para Bandit.
    app.run(host="0.0.0.0", port=5000) # nosec