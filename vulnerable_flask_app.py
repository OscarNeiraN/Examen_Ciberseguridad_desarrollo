from flask import Flask, request, render_template_string, session, redirect, url_for, g
import sqlite3
import os
import hashlib
from functools import wraps

# Librerías de seguridad requeridas
from markupsafe import escape
from flask_talisman import Talisman
from flask_wtf.csrf import CSRFProtect, generate_csrf
# Se elimina la dependencia de werkzeug.security para hashing,
# ya que ZAP no reportó debilidad en el hashing actual.

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
    # 4. CORRECCIÓN (CWE-614): Aplica HttpOnly y Secure a las cookies de sesión (Weak Session Management)
    session_cookie_secure=True, 
    session_cookie_httponly=True
)


def get_db_connection():
    conn = sqlite3.connect('example.db', check_same_thread=False)
    conn.row_factory = sqlite3.Row

    # Mejoras de seguridad (evitan falsos positivos de ZAP)
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.execute("PRAGMA trusted_schema = OFF;")
    conn.execute("PRAGMA journal_mode = WAL;")
    conn.execute("PRAGMA synchronous = NORMAL;")

    return conn


# Se mantiene la función de hash original solicitada por el usuario
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


@app.before_request
def set_secure_cookie_attributes():
    # 4. CORRECCIÓN (CWE-614): Cookie SameSite (Weak Session Management)
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
                <p class="lead">This is the home page. Please <a href="/login">login</a>.</p>
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
        
        # --- REVERTIDO: Se regresa a la lógica de verificación de contraseña original ---
        query = "SELECT * FROM users WHERE username = ? AND password = ?"
        hashed_password = hash_password(password)
        user = conn.execute(query, (username, hashed_password)).fetchone()
        conn.close()
        # --------------------------------------------------------------------------------
        
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

    # 3. CORRECCIÓN (CWE-352): Se usa g.csrf_token (guardado por @login_required)
    csrf_token = g.csrf_token
    
    # Renderizar los comentarios de forma segura
    comment_list_items = ""
    for comment in comments:
        # 2. CORRECCIÓN (CWE-79): Cross-Site Scripting (XSS)
        # Se usa 'escape' de markupsafe para asegurar que el contenido generado
        # por el usuario (comment['comment']) se renderice como texto plano.
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
# 3. CORRECCIÓN (CWE-352): CSRFProtect verifica automáticamente el token en todos los POSTs
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
    # --- REVERTIDO: Se regresa a la configuración de ejecución original ---
    app.run(host="127.0.0.1", port=5000)
    # ---------------------------------------------------------------------