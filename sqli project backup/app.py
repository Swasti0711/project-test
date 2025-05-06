from flask import Flask, request, jsonify, render_template, redirect, url_for, flash, session, abort, g
import joblib
import psycopg2
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from config import DATABASE_CONFIG
import re
import os

app = Flask(__name__)
app.config.from_pyfile('config.py')
app.config['SECRET_KEY'] = 'sqli_secret_key'

# --------- Load Model and Vectorizer ---------
MODEL_PATH = os.path.join(os.getcwd(), 'Models', 'sql_injection_model.pkl')
VECTORIZER_PATH = os.path.join(os.getcwd(), 'Models', 'vectorizer.pkl')

if not os.path.exists(MODEL_PATH) or not os.path.exists(VECTORIZER_PATH):
    raise FileNotFoundError("❗ Model or Vectorizer file not found in 'Models/' folder. Please check.")

model = joblib.load(MODEL_PATH)
vectorizer = joblib.load(VECTORIZER_PATH)
# ---------------------------------------------


# --------- PostgreSQL Connection ---------
def get_db():
    if 'conn' not in g:
        g.conn = psycopg2.connect(**DATABASE_CONFIG)
        g.cursor = g.conn.cursor()
    return g.conn, g.cursor

@app.teardown_appcontext
def close_db(exception):
    conn = g.pop('conn', None)
    cursor = g.pop('cursor', None)
    if cursor is not None:
        cursor.close()
    if conn is not None:
        conn.close()
# -----------------------------------------


# --------- Table Creation for Flask 3.x ---------
@app.before_request
def create_tables_once():
    if not hasattr(g, '_tables_created'):
        conn, cursor = get_db()
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
        ''')
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS logs (
            id SERIAL PRIMARY KEY,
            timestamp TIMESTAMP,
            query TEXT,
            is_sql_injection BOOLEAN,
            injection_type TEXT
        )
        ''')
        conn.commit()
        g._tables_created = True
# -----------------------------------------------


# --------- SQL Injection Detection ---------
def is_sql_injection(query):
    query_tfidf = vectorizer.transform([query])
    prediction = model.predict(query_tfidf)[0]
    return bool(prediction)

def classify_sql_injection(query):
    patterns = {
        "Union-based SQLi": [r"(?i)\bUNION\b\s+\bSELECT\b"],
        "Boolean-based Blind SQLi": [
            r"(?i)\bAND\b\s*'[^']*'='[^']*'\s*(?:--|#)?",
            r"(?i)\bOR\b\s*'[^']*'='[^']*'\s*(?:--|#)?",
            r"(?i)\bAND\b\s*\d+\s*=\s*\d+\s*(?:--|#)?",
            r"(?i)\bOR\b\s*\d+\s*=\s*\d+\s*(?:--|#)?",
        ],
        "Time-based Blind SQLi": [r"(?i)\bSLEEP\(\d+\)", r"(?i)\bpg_sleep\(\d+\)"],
        "Out-of-band SQLi": [
            r"(?i)\b(SELECT|UPDATE|DELETE|INSERT)\b\s+\w+\s+\bINTO\b\s+\bOUTFILE\b",
            r"(?i)\b(SELECT|UPDATE|DELETE|INSERT)\b\s+\w+\s+\bINTO\b\s+\bDUMPFILE\b",
        ],
        "Error-based SQLi": [
            r"(?i)'.*?(?:--|#)",
            r'(?i)".*?(?:--|#)',
            r"(?i)\bAND\b\s*\d+\s*=\s*\d+\s*(?:--|#)?",
            r"(?i)\bOR\b\s*\d+\s*=\s*\d+\s*(?:--|#)?",
        ]
    }

    for attack, regex_list in patterns.items():
        if any(re.search(pattern, query) for pattern in regex_list):
            return attack
    return "Unknown"

def log_attempt(query, is_sql_injection, injection_type):
    conn, cursor = get_db()
    cursor.execute('''
    INSERT INTO logs (timestamp, query, is_sql_injection, injection_type)
    VALUES (%s, %s, %s, %s)
    ''', (datetime.now(), query, is_sql_injection, injection_type))
    conn.commit()
    print(f"Query: {query}, SQL Injection: {is_sql_injection}, Type: {injection_type}")

def detect_and_log_request():
    for key, value in request.form.items():
        if is_sql_injection(value):
            injection_type = classify_sql_injection(value)
            log_attempt(value, True, injection_type)
            abort(400, description=f"SQL Injection Detected: {injection_type}")
    for key, value in request.args.items():
        if is_sql_injection(value):
            injection_type = classify_sql_injection(value)
            log_attempt(value, True, injection_type)
            abort(400, description=f"SQL Injection Detected: {injection_type}")

@app.before_request
def before_request():
    if request.method in ['POST', 'GET']:
        detect_and_log_request()
# ------------------------------------------------


@app.route('/register', methods=['GET', 'POST'])
def register():
    sql_injection_detected = False
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')

        if is_sql_injection(username) or is_sql_injection(password):
            sql_injection_detected = True
        else:
            hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
            try:
                conn, cursor = get_db()
                cursor.execute('''
                INSERT INTO users (username, password) VALUES (%s, %s)
                ''', (username, hashed_password))
                conn.commit()
                flash('Registered successfully.', 'success')
                return redirect(url_for('login'))
            except psycopg2.IntegrityError as e:
                conn.rollback()
                if 'unique constraint' in str(e):
                    flash('User already exists.', 'danger')
                else:
                    flash('Registration problem, try again.', 'danger')

    return render_template('register.html', sql_injection_detected=sql_injection_detected)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')

        conn, cursor = get_db()
        cursor.execute('SELECT * FROM users WHERE username = %s', (username,))
        user = cursor.fetchone()

        if user and check_password_hash(user[2], password):
            session['username'] = username
            flash('Logged in successfully!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password.', 'danger')
            return redirect(url_for('login'))

    return render_template('login.html')


@app.route('/logout')
def logout():
    session.pop('username', None)
    flash('Logged out.', 'info')
    return redirect(url_for('login'))


@app.route('/')
def dashboard():
    if 'username' in session:
        conn, cursor = get_db()
        cursor.execute('SELECT * FROM logs')
        logs = cursor.fetchall()
        return render_template('dashboard.html', logged_in=True, logs=logs)
    else:
        return render_template('dashboard.html', logged_in=False, logs=[])


@app.route('/check_query', methods=['POST'])
def check_query():
    data = request.get_json()
    query = data.get('query', '')

    is_injection = is_sql_injection(query)
    injection_type = classify_sql_injection(query)
    log_attempt(query, is_injection, injection_type)

    if is_injection:
        return jsonify({'error': f'SQL Injection Detected: {injection_type}'}), 400

    return jsonify({'is_sql_injection': "Safe Query"})


@app.route('/logs', methods=['GET'])
def get_logs():
    if 'username' in session:
        conn, cursor = get_db()
        cursor.execute('SELECT * FROM logs')
        logs = cursor.fetchall()
        return jsonify(logs)
    else:
        return jsonify({'error': 'Unauthorized access'}), 401


if __name__ == '__main__':
    app.run(debug=True)
