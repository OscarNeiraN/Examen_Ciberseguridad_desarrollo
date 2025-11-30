FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN python -c "import sqlite3; conn = sqlite3.connect('example.db'); conn.execute('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT)'); conn.execute('CREATE TABLE IF NOT EXISTS comments (id INTEGER PRIMARY KEY, user_id INTEGER, comment TEXT)'); conn.close()"

EXPOSE 5000

CMD ["python", "vulnerable_flask_app.py"]