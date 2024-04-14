import hashlib
import uuid
from flask import Flask, render_template, request, session, redirect, url_for, jsonify
import sqlite3
from cryptography.fernet import Fernet
import pyperclip

app = Flask(__name__)
app.secret_key = 'nNrS3J!SxaM@t6i8'

# Chiave costante per la crittografia delle password
# NOTA: Non utilizzare questa chiave in un ambiente di produzione, è solo a scopo dimostrativo
KEY = b'_H85BhMJeAYFl9oW9-z1D8t7aHk5j6tE88FYoybl3JQ='
cipher_suite = Fernet(KEY)

def create_users_table():
    conn = sqlite3.connect('password_manager.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            salt TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()


def create_passwords_table():
    conn = sqlite3.connect('password_manager.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS passwords (
            id INTEGER PRIMARY KEY,
            user_id INTEGER NOT NULL,
            website TEXT NOT NULL,
            email TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            password_encrypted TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        
        salt = uuid.uuid4().hex
        hashed_password = hashlib.sha512((password + salt).encode('utf-8')).hexdigest()
        
        conn = sqlite3.connect('password_manager.db')
        cursor = conn.cursor()
        cursor.execute('SELECT id FROM users WHERE email = ?', (email,))
        user = cursor.fetchone()
        
        if user:
            conn.close()
            return 'Email already registered'

        cursor.execute('''
            INSERT INTO users (username, email, password, salt)
            VALUES (?, ?, ?, ?)
        ''', (username, email, hashed_password, salt))
        conn.commit()
        conn.close()
        
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        conn = sqlite3.connect('password_manager.db')
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
        user = cursor.fetchone()
        
        if user and check_password(user[3], password, user[4]):
            session['user_id'] = user[0]
            session['username'] = user[1]
            return redirect(url_for('index'))
        else:
            return 'Invalid email or password'
    
    return render_template('login.html')

def check_password(stored_password, password, salt):
    hashed_password = hashlib.sha512((password + salt).encode('utf-8')).hexdigest()
    return hashed_password == stored_password

@app.route('/add_account', methods=['GET', 'POST'])
def add_account():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        website = request.form['website']
        email = request.form['email']
        password = request.form['password']
        
        user_id = session['user_id']
        
        # Crittografa la password prima di salvarla nel database
        password_encrypted = cipher_suite.encrypt(password.encode('utf-8')).decode('utf-8')
        
        conn = sqlite3.connect('password_manager.db')
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO passwords (user_id, website, email, password_hash, password_encrypted)
            VALUES (?, ?, ?, ?, ?)
        ''', (user_id, website, email, password_encrypted, password_encrypted))  # Passa la password crittografata due volte
        conn.commit()
        conn.close()
        
        return redirect(url_for('view_accounts'))
    
    return render_template('add_account.html')


@app.route('/view_accounts')
def view_accounts():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    
    conn = sqlite3.connect('password_manager.db')
    cursor = conn.cursor()
    cursor.execute('SELECT id, website, email, password_encrypted FROM passwords WHERE user_id = ?', (user_id,))
    accounts = cursor.fetchall()
    
    decrypted_accounts = []
    for account in accounts:
        decrypted_password = cipher_suite.decrypt(account[3].encode('utf-8')).decode('utf-8')
        decrypted_accounts.append((account[0], account[1], account[2], decrypted_password))
    
    conn.close()
    
    return render_template('view_accounts.html', accounts=decrypted_accounts)

@app.route('/copy_password', methods=['POST'])
def copy_password():
    password = request.form.get('password', '')
    pyperclip.copy(password)
    return jsonify({"message": "Password copied to clipboard"})

@app.route('/delete_account/<int:account_id>', methods=['GET', 'POST'])
def delete_account(account_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']

    conn = sqlite3.connect('password_manager.db')
    cursor = conn.cursor()
    cursor.execute('DELETE FROM passwords WHERE id = ? AND user_id = ?', (account_id, user_id))
    conn.commit()
    conn.close()

    return redirect(url_for('view_accounts'))

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    return redirect(url_for('index'))

@app.route('/')
def index():
    if 'user_id' in session:
        return render_template('index.html', username=session['username'])
    else:
        return redirect(url_for('login'))

if __name__ == "__main__":
    create_users_table()
    create_passwords_table()
    app.run(debug=True)
