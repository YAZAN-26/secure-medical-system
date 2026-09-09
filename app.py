from flask import Flask, render_template, request, redirect, url_for, session, send_file
import os
from cryptography.fernet import Fernet
import sqlite3
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'super_secret_medical_key'

UPLOAD_FOLDER = 'uploads'
ENCRYPTED_FOLDER = 'encrypted_files'
KEY_FILE = 'secret.key'
DB_NAME = 'medical_system.db'

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(ENCRYPTED_FOLDER, exist_ok=True)

def load_or_create_key():
    if not os.path.exists(KEY_FILE):
        key = Fernet.generate_key()
        with open(KEY_FILE, 'wb') as key_file:
            key_file.write(key)
    else:
        with open(KEY_FILE, 'rb') as key_file:
            key = key_file.read()
    return key

encryption_key = load_or_create_key()
cipher = Fernet(encryption_key)

def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL,
            encrypted_filename TEXT NOT NULL,
            uploaded_by TEXT NOT NULL,
            upload_date TEXT NOT NULL
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            action TEXT NOT NULL,
            timestamp TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

init_db()

def log_action(username, action):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute('INSERT INTO audit_logs (username, action, timestamp) VALUES (?, ?, ?)', (username, action, now))
    conn.commit()
    conn.close()

@app.route('/')
def home():
    if 'user' not in session:
        return redirect(url_for('login'))
    
    search_query = request.args.get('search', '')
    
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    if session['role'] == 'Patient':
        if search_query:
            cursor.execute('SELECT id, filename, encrypted_filename, uploaded_by, upload_date FROM records WHERE uploaded_by = ? AND filename LIKE ?', 
                           (session['user'], f'%{search_query}%'))
        else:
            cursor.execute('SELECT id, filename, encrypted_filename, uploaded_by, upload_date FROM records WHERE uploaded_by = ?', (session['user'],))
    else:
        if search_query:
            cursor.execute('SELECT id, filename, encrypted_filename, uploaded_by, upload_date FROM records WHERE filename LIKE ? OR uploaded_by LIKE ?', 
                           (f'%{search_query}%', f'%{search_query}%'))
        else:
            cursor.execute('SELECT id, filename, encrypted_filename, uploaded_by, upload_date FROM records')
        
    records = cursor.fetchall()
    
    logs = []
    if session['role'] == 'Doctor':
        cursor.execute('SELECT username, action, timestamp FROM audit_logs ORDER BY id DESC LIMIT 10')
        logs = cursor.fetchall()
        
    conn.close()
    return render_template('index.html', records=records, logs=logs, user=session['user'], role=session['role'], search=search_query)

@app.route('/profile')
def profile():
    if 'user' not in session:
        return redirect(url_for('login'))
        
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    # إحصائيات المستخدم الشخصية
    cursor.execute('SELECT COUNT(*) FROM records WHERE uploaded_by = ?', (session['user'],))
    user_files_count = cursor.fetchone()[0]
    
    cursor.execute('SELECT action, timestamp FROM audit_logs WHERE username = ? ORDER BY id DESC LIMIT 5', (session['user'],))
    user_logs = cursor.fetchall()
    
    conn.close()
    return render_template('profile.html', user=session['user'], role=session['role'], files_count=user_files_count, user_logs=user_logs)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        raw_password = request.form['password']
        role = request.form['role']
        hashed_password = generate_password_hash(raw_password)
        
        try:
            conn = sqlite3.connect(DB_NAME)
            cursor = conn.cursor()
            cursor.execute('INSERT INTO users (username, password, role) VALUES (?, ?, ?)', (username, hashed_password, role))
            conn.commit()
            conn.close()
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            return "اسم المستخدم موجود مسبقاً! <a href='/register'>حاول مرة أخرى</a>"
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        raw_password = request.form['password']
        
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
        user = cursor.fetchone()
        conn.close()
        
        if user and check_password_hash(user[2], raw_password):
            session['user'] = user[1]
            session['role'] = user[3]
            log_action(user[1], "تسجيل دخول بنجاح")
            return redirect(url_for('home'))
        else:
            return "خطأ في بيانات الدخول! <a href='/login'>إعادة المحاولة</a>"
    return render_template('login.html')

@app.route('/logout')
def logout():
    if 'user' in session:
        log_action(session['user'], "تسجيل خروج")
    session.clear()
    return redirect(url_for('login'))

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'user' not in session:
        return redirect(url_for('login'))
        
    if 'medical_file' not in request.files:
        return "لم يتم اختيار ملف!"
    
    file = request.files['medical_file']
    if file.filename == '':
        return "اسم الملف فارغ!"
    
    if file:
        file_data = file.read()
        encrypted_data = cipher.encrypt(file_data)
        
        original_name = file.filename
        encrypted_filename = original_name + '.enc'
        encrypted_path = os.path.join(ENCRYPTED_FOLDER, encrypted_filename)
        
        with open(encrypted_path, 'wb') as enc_file:
            enc_file.write(encrypted_data)
            
        now = datetime.now().strftime("%Y-%m-%d %H:%M")
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute('INSERT INTO records (filename, encrypted_filename, uploaded_by, upload_date) VALUES (?, ?, ?, ?)', 
                       (original_name, encrypted_filename, session['user'], now))
        conn.commit()
        conn.close()
        
        log_action(session['user'], f"رفع وتشفير السجل: {original_name}")
        return redirect(url_for('home'))

@app.route('/download/<path:filename>')
def download_file(filename):
    if 'user' not in session:
        return redirect(url_for('login'))
        
    encrypted_path = os.path.join(ENCRYPTED_FOLDER, filename)
    if not os.path.exists(encrypted_path):
        return "الملف غير موجود!"
    
    with open(encrypted_path, 'rb') as enc_file:
        encrypted_data = enc_file.read()
        
    decrypted_data = cipher.decrypt(encrypted_data)
    
    original_filename = filename[:-4] if filename.endswith('.enc') else filename
    decrypted_path = os.path.join(UPLOAD_FOLDER, original_filename)
    
    with open(decrypted_path, 'wb') as dec_file:
        dec_file.write(decrypted_data)
        
    log_action(session['user'], f"فك وتنزيل السجل: {original_filename}")
    return send_file(decrypted_path, as_attachment=True)

@app.route('/delete/<int:record_id>')
def delete_record(record_id):
    if 'user' not in session:
        return redirect(url_for('login'))
        
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('SELECT filename, encrypted_filename, uploaded_by FROM records WHERE id = ?', (record_id,))
    record = cursor.fetchone()
    
    if record:
        filename, encrypted_filename, uploaded_by = record
        if session['role'] == 'Doctor' or session['user'] == uploaded_by:
            encrypted_path = os.path.join(ENCRYPTED_FOLDER, encrypted_filename)
            if os.path.exists(encrypted_path):
                os.remove(encrypted_path)
                
            cursor.execute('DELETE FROM records WHERE id = ?', (record_id,))
            conn.commit()
            log_action(session['user'], f"حذف السجل: {filename}")
            
    conn.close()
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=True)