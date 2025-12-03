# ...existing code...
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
        g.csrf_token = generate_csrf()
        return f(*args, **kwargs)
    return decorated_function


app = Flask(__name__)

# 4. CORRECCIÓN (CWE-614): Clave secreta generada en tiempo de ejecución.
app.secret_key = os.urandom(24)





# 3. CORRECCIÓN (CWE-352): Inicializar CSRFProtect para todas las rutas POST.
csrf = CSRFProtect(app)










# Configurar cookies segurass
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=False  # False en desarrollo, True en producción con HTTPS
)

# 1. CORRECCIÓN (CWE-693): Content Security Policy ampliada para cubrir directivas sin fallbackjbjjj
Talisman(
    app,
    content_security_policy={
        # políticas de recursos
        'default-src': ["'self'"],
        'script-src': ["'self'"],
        'style-src': ["'self'", "https://maxcdn.bootstrapcdn.com"],
        'img-src': ["'self'", "data:"],                 
        'font-src': ["'self'", "https://maxcdn.bootstrapcdn.com"],
        'connect-src': ["'self'"],
        # directivas que no hacen fallback a default-src, se definen explícitamente
        'form-action': ["'self'"],
        'frame-ancestors': ["'none'"],
        'base-uri': ["'self'"],
        'object-src': ["'none'"]
    },
    force_https=False,  # False en desarrollo, True en producción
    strict_transport_security=False,  # False en desarrollo, True en producción
    strict_transport_security_max_age=31536000
)


def get_db_connection():
    conn = sqlite3.connect('example.db', check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


# FUNCIÓN: Inicialización de la base de datos
def init_db():
    conn = get_db_connection()
    c = conn.cursor()
    
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT DEFAULT 'user'
        )
    ''')
    
    c.execute('''
        CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            comment TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')

    admin_username = 'admin'
    user_username = 'user'
    default_password_hash = hash_password('password')
    
    if not conn.execute("SELECT id FROM users WHERE username = ?", (admin_username,)).fetchone():
        c.execute(
            "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
            (admin_username, default_password_hash, 'admin')
        )
    
    if not conn.execute("SELECT id FROM users WHERE username = ?", (user_username,)).fetchone():
        c.execute(
            "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
            (user_username, default_password_hash, 'user')
        )
    
    conn.commit()
    conn.close()


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
    csrf_token = generate_csrf()
    
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')

        conn = get_db_connection()
        
        # CORRECCIÓN SQL INJECTION (CWE-89)
        query = "SELECT * FROM users WHERE username = ? AND password = ?"
        hashed_password = hash_password(password)
        user = conn.execute(query, (username, hashed_password)).fetchone()
        conn.close()
        
        if user:
            session['user_id'] = user['id']
            session['role'] = user['role']
            session.permanent = True
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
                                <input type="text" class="form-control" id="username" name="username" required>
                            </div>
                            <div class="form-group">
                                <label for="password">Password</label>
                                <input type="password" class="form-control" id="password" name="password" required>
                            </div>
                            <button type="submit" class="btn btn-primary">Login</button>
                        </form>
                    </div>
                </body>
                </html>
            ''')

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
                        <input type="text" class="form-control" id="username" name="username" required>
                    </div>
                    <div class="form-group">
                        <label for="password">Password</label>
                        <input type="password" class="form-control" id="password" name="password" required>
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

    csrf_token = g.csrf_token
    
    # 2. CORRECCIÓN (CWE-79): Cross-Site Scripting (XSS)
    comment_list_items = ""
    for comment in comments:
        safe_comment =  escape(comment['comment']) # Escapar contenido para prevenir XSS
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
                    <input type="hidden" name="csrf_token" value="{csrf_token}">
                    <div class="form-group">
                        <label for="comment">Comment</label>
                        <textarea class="form-control" id="comment" name="comment" rows="3" required></textarea>
                    </div>
                    <button type="submit" class="btn btn-primary">Submit Comment</button>
                </form>
                <h2 class="mt-5">Your Comments</h2>
                <ul class="list-group">
                    {comment_list_items}
                </ul>
                <a href="/logout" class="btn btn-secondary mt-3">Logout</a>
            </div>
        </body>
        </html>
    ''')


@app.route('/submit_comment', methods=['POST'])
@login_required
def submit_comment():
    comment = request.form.get('comment', '')
    user_id = session['user_id']

    conn = get_db_connection()
    conn.execute(
        "INSERT INTO comments (user_id, comment) VALUES (?, ?)",
        (user_id, comment)
    )
    conn.commit()
    conn.close()

    return redirect(url_for('dashboard'))


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))


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
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=False)  # nosec 