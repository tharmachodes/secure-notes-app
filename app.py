from flask import Flask, render_template, request, redirect, url_for, session
import sqlite3
import os
import re
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
# Use environment variable for secret key, fallback for development
app.secret_key = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')

# Initialize database
def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT)''')
    conn.commit()
    conn.close()

init_db()

def validate_password(password):
    """Enforce a basic password policy."""
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if not re.search(r'[A-Za-z]', password):
        return False, "Password must contain at least one letter."
    if not re.search(r'\d', password):
        return False, "Password must contain at least one digit."
    return True, ""

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        # Use parameterized query to prevent SQL injection
        c.execute("SELECT id, username, password FROM users WHERE username = ?", (username,))
        user = c.fetchone()
        conn.close()
        
        if user and check_password_hash(user[2], password):
            session['user_id'] = user[0]
            session['username'] = user[1]
            return redirect(url_for('notes'))
        else:
            return render_template('login.html', error='Invalid credentials')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Validate password strength
        valid, msg = validate_password(password)
        if not valid:
            return render_template('register.html', error=msg)
        
        # Hash password before storing
        password_hash = generate_password_hash(password)
        
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        try:
            c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password_hash))
            conn.commit()
        except sqlite3.IntegrityError:
            return render_template('register.html', error='Username already exists.')
        finally:
            conn.close()
        
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/notes')
def notes():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # Simple note display - not implemented fully
    return f"Welcome {session['username']}! Your notes will appear here."

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    # Disable debug mode in production
    app.run(debug=False)