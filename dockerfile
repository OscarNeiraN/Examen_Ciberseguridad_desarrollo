FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN python -c "from vulnerable_flask_app import init_db; init_db()"

EXPOSE 5000

CMD ["python", "vulnerable_flask_app.py"]