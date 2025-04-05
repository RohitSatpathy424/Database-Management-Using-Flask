from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_mysqldb import MySQL
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import MySQLdb.cursors
import re

app = Flask(__name__)

# 🔹 Configuration
app.secret_key = 'your_secret_key'
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'Rohit@424'
app.config['MYSQL_DB'] = 'flask_db'

# 🔹 Initialize MySQL & Bcrypt
mysql = MySQL(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# 🔹 User Loader for Flask-Login
class User(UserMixin):
    def __init__(self, id, username):
        self.id = id
        self.username = username

@login_manager.user_loader
def load_user(user_id):
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    user = cursor.fetchone()
    if user:
        return User(user['id'], user['username'])
    return None

# 🔹 Route: Home Page
@app.route('/')
def home():
    return render_template('index.html')

# 🔹 Route: Signup
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')

        cursor = mysql.connection.cursor()
        cursor.execute("INSERT INTO users (username, password) VALUES (%s, %s)", (username, hashed_pw))
        mysql.connection.commit()
        flash("Account created successfully!", "success")
        return redirect(url_for('login'))

    return render_template('signup.html')

# 🔹 Route: Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
        user = cursor.fetchone()

        if user and bcrypt.check_password_hash(user['password'], password):
            login_user(User(user['id'], user['username']))
            flash("Login successful!", "success")
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid username or password", "danger")

    return render_template('login.html')

# 🔹 Route: Dashboard (After Login)
@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', username=current_user.username)

# 🔹 Route: Logout
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("You have been logged out", "info")
    return redirect(url_for('login'))

# 🔹 Route: Profile Update
@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        new_username = request.form['username']
        cursor = mysql.connection.cursor()
        cursor.execute("UPDATE users SET username = %s WHERE id = %s", (new_username, current_user.id))
        mysql.connection.commit()
        flash("Profile updated successfully!", "success")
        return redirect(url_for('dashboard'))

    return render_template('profile.html', username=current_user.username)

# 🔹 Route: Reset Password
@app.route('/reset_password', methods=['GET', 'POST'])
@login_required
def reset_password():
    if request.method == 'POST':
        new_password = request.form['password']
        hashed_pw = bcrypt.generate_password_hash(new_password).decode('utf-8')

        cursor = mysql.connection.cursor()
        cursor.execute("UPDATE users SET password = %s WHERE id = %s", (hashed_pw, current_user.id))
        mysql.connection.commit()
        flash("Password reset successfully!", "success")
        return redirect(url_for('dashboard'))

    return render_template('reset_password.html')

# 🔹 Route: View Grades (Read-only)
@app.route('/grades')
@login_required
def grades():
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("SELECT * FROM grades WHERE user_id = %s", (current_user.id,))
    grades = cursor.fetchall()
    return render_template('grades.html', grades=grades)

# 🔹 Run the Flask App
if __name__ == '__main__':
    app.run(debug=True)
