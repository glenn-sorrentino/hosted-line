from flask import Flask, request, render_template, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from dotenv import load_dotenv
from flask_bcrypt import Bcrypt
import logging
from logging.handlers import RotatingFileHandler
import os
import pyotp
import qrcode
import io
import base64

# Load environment variables
load_dotenv()

# Retrieve database credentials and secret key from environment
db_user = os.getenv('DB_USER')
db_pass = os.getenv('DB_PASS')
db_name = os.getenv('DB_NAME')
secret_key = os.getenv('SECRET_KEY')

app = Flask(__name__)
app.config['SECRET_KEY'] = secret_key
app.config['SQLALCHEMY_DATABASE_URI'] = f"mysql+pymysql://{db_user}:{db_pass}@localhost/{db_name}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize extensions
bcrypt = Bcrypt(app)
db = SQLAlchemy(app)

# Setup file handler
file_handler = RotatingFileHandler('flask.log', maxBytes=1024 * 1024 * 100, backupCount=20)
file_handler.setLevel(logging.DEBUG)
file_handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'))

# Add it to the Flask logger
app.logger.addHandler(file_handler)
app.logger.setLevel(logging.DEBUG)

# Database Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('messages', lazy=True))
    totp_secret = db.Column(db.String(100))

# Error Handler
@app.errorhandler(Exception)
def handle_exception(e):
    # Log the error and stacktrace
    app.logger.error(f'Error: {e}', exc_info=True)
    return "An internal server error occurred", 500

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    try:
        if request.method == 'POST':
            username = request.form['username']
            password = request.form['password']
            password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
            new_user = User(username=username, password_hash=password_hash)

            db.session.add(new_user)
            db.session.commit()

            session['user_id'] = new_user.id
            return redirect(url_for('inbox', username=username))

        return render_template('register.html')
    except Exception as e:
        app.logger.error(f'Error in registration: {e}', exc_info=True)
        raise

@app.route('/enable-2fa', methods=['GET', 'POST'])
def enable_2fa():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    if request.method == 'POST':
        user.totp_secret = pyotp.random_base32()
        db.session.commit()
        return redirect(url_for('show_qr_code'))
    return render_template('enable_2fa.html')

@app.route('/show-qr-code')
def show_qr_code():
    user = User.query.get(session['user_id'])
    if not user or not user.totp_secret:
        return redirect(url_for('enable_2fa'))

    totp_uri = pyotp.totp.TOTP(user.totp_secret).provisioning_uri(name=user.username, issuer_name="YourAppName")
    img = qrcode.make(totp_uri)

    # Convert QR code to a data URI
    buffered = io.BytesIO()
    img.save(buffered, format="PNG")
    img_str = base64.b64encode(buffered.getvalue()).decode()
    qr_code_img = f"data:image/png;base64,{img_str}"

    return render_template('show_qr_code.html', qr_code_img=qr_code_img, user_secret=user.totp_secret)

@app.route('/verify-2fa-setup', methods=['POST'])
def verify_2fa_setup():
    user = User.query.get(session['user_id'])
    if not user:
        return redirect(url_for('login'))

    verification_code = request.form['verification_code']
    totp = pyotp.TOTP(user.totp_secret)
    if totp.verify(verification_code):
        flash('2FA setup successful. Please log in again.')
        return redirect(url_for('logout'))
    else:
        flash('Invalid 2FA code. Please try again.')
        return redirect(url_for('show_qr_code'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user and bcrypt.check_password_hash(user.password_hash, password):
        session['user_id'] = user.id
        if user.totp_secret:
            return redirect(url_for('verify_2fa_login'))
        return redirect(url_for('inbox', username=username))
        else:
            flash('Invalid username or password')

    return render_template('login.html')

@app.route('/verify-2fa-login', methods=['GET', 'POST'])
def verify_2fa_login():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    if request.method == 'POST':
        verification_code = request.form['verification_code']
        totp = pyotp.TOTP(user.totp_secret)
        if totp.verify(verification_code):
            return redirect(url_for('inbox', username=user.username))
        else:
            flash('Invalid 2FA code. Please try again.')
    return render_template('verify_2fa_login.html')

@app.route('/inbox/<username>')
def inbox(username):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user = User.query.filter_by(username=username).first()
    if user and session['user_id'] == user.id:
        messages = Message.query.filter_by(user_id=user.id).all()
        return render_template('inbox.html', messages=messages, username=username)
    else:
        return 'Unauthorized', 401

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('index'))

@app.route('/submit_message/<username>', methods=['GET', 'POST'])
def submit_message(username):
    if request.method == 'POST':
        user = User.query.filter_by(username=username).first()
        if user:
            content = request.form['content']
            message = Message(content=content, user_id=user.id)
            db.session.add(message)
            db.session.commit()
            return 'Message sent!'
        return 'User not found', 404
    return render_template('submit_message.html', username=username)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, host='0.0.0.0', port=5000)
