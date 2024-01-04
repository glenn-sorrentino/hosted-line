from flask import Flask, request, render_template, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError  # Import IntegrityError
from dotenv import load_dotenv
from flask_bcrypt import Bcrypt
from datetime import datetime
import logging
from logging.handlers import RotatingFileHandler
import os
import pyotp
import qrcode
import io
import base64
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from werkzeug.security import generate_password_hash, check_password_hash
import gnupg

# Load environment variables
load_dotenv()

# Retrieve database credentials and secret key from environment
db_user = os.getenv("DB_USER")
db_pass = os.getenv("DB_PASS")
db_name = os.getenv("DB_NAME")
secret_key = os.getenv("SECRET_KEY")

app = Flask(__name__)
app.config["SECRET_KEY"] = secret_key
app.config[
    "SQLALCHEMY_DATABASE_URI"
] = f"mysql+pymysql://{db_user}:{db_pass}@localhost/{db_name}"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Initialize GPG with expanded home directory
gpg_home = os.path.expanduser("~/.gnupg")
gpg = gnupg.GPG(gnupghome=gpg_home)

# Initialize extensions
bcrypt = Bcrypt(app)
db = SQLAlchemy(app)

# Setup file handler
file_handler = RotatingFileHandler(
    "flask.log", maxBytes=1024 * 1024 * 100, backupCount=20
)
file_handler.setLevel(logging.DEBUG)
file_handler.setFormatter(
    logging.Formatter(
        "%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]"
    )
)

# Add it to the Flask logger
app.logger.addHandler(file_handler)
app.logger.setLevel(logging.DEBUG)


# Database Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255))
    totp_secret = db.Column(db.String(100))
    email = db.Column(db.String(255))
    smtp_server = db.Column(db.String(255))
    smtp_port = db.Column(db.Integer)
    smtp_username = db.Column(db.String(255))
    smtp_password = db.Column(db.String(255))
    pgp_key = db.Column(db.Text)


class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    user = db.relationship("User", backref=db.backref("messages", lazy=True))


class InviteCode(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(255), unique=True, nullable=False)
    expiration_date = db.Column(db.DateTime, nullable=False)
    used = db.Column(db.Boolean, default=False, nullable=False)

    def __repr__(self):
        return "<InviteCode %r>" % self.code


# Error Handler
@app.errorhandler(Exception)
def handle_exception(e):
    # Log the error and stacktrace
    app.logger.error(f"Error: {e}", exc_info=True)
    return "An internal server error occurred", 500


# Routes
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        invite_code = request.form.get("invite_code")

        # Check if invite code is valid
        valid_code = InviteCode.query.filter_by(code=invite_code, used=False).first()
        if valid_code is None or valid_code.expiration_date < datetime.utcnow():
            flash("Invalid or expired invite code.")
            return redirect(url_for("register"))

        # Check for existing user
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash("Username already exists.")
            return redirect(url_for("register"))

        # Create new user with hashed password
        hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")
        new_user = User(username=username, password_hash=hashed_password)
        db.session.add(new_user)

        # Mark invite code as used
        valid_code.used = True
        db.session.commit()

        flash("Registration successful! Please log in.")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/enable-2fa", methods=["GET", "POST"])
def enable_2fa():
    user_id = session.get("user_id")
    if not user_id:
        return redirect(url_for("login"))

    user = User.query.get(user_id)
    if request.method == "POST":
        verification_code = request.form["verification_code"]
        temp_totp_secret = session.get("temp_totp_secret")
        if temp_totp_secret and pyotp.TOTP(temp_totp_secret).verify(verification_code):
            user.totp_secret = temp_totp_secret
            db.session.commit()
            session.pop("temp_totp_secret", None)
            flash("2FA setup successful. Please log in again with 2FA.")
            return redirect(url_for("logout"))  # Redirect to logout
        else:
            flash("Invalid 2FA code. Please try again.")
            return redirect(url_for("enable_2fa"))

    # Generate new 2FA secret and QR code
    temp_totp_secret = pyotp.random_base32()
    session["temp_totp_secret"] = temp_totp_secret
    session["is_setting_up_2fa"] = True
    totp_uri = pyotp.totp.TOTP(temp_totp_secret).provisioning_uri(
        name=user.username, issuer_name="YourAppName"
    )
    img = qrcode.make(totp_uri)
    buffered = io.BytesIO()
    img.save(buffered)
    qr_code_img = (
        "data:image/png;base64," + base64.b64encode(buffered.getvalue()).decode()
    )

    # Pass the text-based pairing code to the template
    return render_template(
        "enable_2fa.html", qr_code_img=qr_code_img, text_code=temp_totp_secret
    )


@app.route("/disable-2fa", methods=["POST"])
def disable_2fa():
    user_id = session.get("user_id")
    if not user_id:
        return redirect(url_for("login"))

    user = db.session.get(User, user_id)
    user.totp_secret = None
    db.session.commit()
    flash("2FA has been disabled.")
    return redirect(url_for("settings"))


@app.route("/confirm-disable-2fa", methods=["GET"])
def confirm_disable_2fa():
    return render_template("confirm_disable_2fa.html")


@app.route("/show-qr-code")
def show_qr_code():
    user = User.query.get(session["user_id"])
    if not user or not user.totp_secret:
        return redirect(url_for("enable_2fa"))

    totp_uri = pyotp.totp.TOTP(user.totp_secret).provisioning_uri(
        name=user.username, issuer_name="Hush Line"
    )
    img = qrcode.make(totp_uri)

    # Convert QR code to a data URI
    buffered = io.BytesIO()
    img.save(buffered)  # Removed the 'format' argument
    img_str = base64.b64encode(buffered.getvalue()).decode()
    qr_code_img = f"data:image/png;base64,{img_str}"

    return render_template(
        "show_qr_code.html", qr_code_img=qr_code_img, user_secret=user.totp_secret
    )


@app.route("/verify-2fa-setup", methods=["POST"])
def verify_2fa_setup():
    user = User.query.get(session["user_id"])
    if not user:
        return redirect(url_for("login"))

    verification_code = request.form["verification_code"]
    totp = pyotp.TOTP(user.totp_secret)
    if totp.verify(verification_code):
        flash("2FA setup successful. Please log in again.")
        session.pop("is_setting_up_2fa", None)
        return redirect(url_for("logout"))
    else:
        flash("Invalid 2FA code. Please try again.")
        return redirect(url_for("show_qr_code"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        app.logger.debug(f"Attempting login for user: {username}")

        user = User.query.filter_by(username=username).first()

        # Check password and if 2FA is enabled
        if user and bcrypt.check_password_hash(user.password_hash, password):
            session["user_id"] = user.id
            session["username"] = user.username

            if user.totp_secret:
                return redirect(url_for("verify_2fa_login"))
            else:
                return redirect(url_for("inbox", username=username))
        else:
            flash("Invalid username or password")
            app.logger.debug("Login failed: Invalid username or password")

    return render_template("login.html")


@app.route("/verify-2fa-login", methods=["GET", "POST"])
def verify_2fa_login():
    if "user_id" not in session:
        return redirect(url_for("login"))

    user = User.query.get(session["user_id"])
    if not user:
        flash("User not found. Please login again.")
        return redirect(url_for("login"))

    if request.method == "POST":
        verification_code = request.form["verification_code"]
        totp = pyotp.TOTP(user.totp_secret)
        if totp.verify(verification_code):
            session["2fa_verified"] = True  # Set 2FA verification flag
            return redirect(url_for("inbox", username=user.username))
        else:
            flash("Invalid 2FA code. Please try again.")

    return render_template("verify_2fa_login.html")


@app.route("/inbox/<username>")
def inbox(username):
    app.logger.debug(
        f"Session Username: {session.get('username')}, URL Username: {username}"
    )

    if "user_id" not in session:
        app.logger.debug("No user_id in session")
        return "Unauthorized", 401
    if session.get("username") != username:
        app.logger.debug("Session username does not match URL username")
        return "Unauthorized", 401

    user = User.query.filter_by(username=username).first()
    if not user:
        app.logger.debug("No user found with this username")
        return "Unauthorized", 401
    app.logger.debug(
        f"Session User ID: {session.get('user_id')}, DB User ID: {user.id}"
    )
    if session["user_id"] != user.id:
        app.logger.debug("Session user_id does not match DB user ID")
        return "Unauthorized", 401

    messages = Message.query.filter_by(user_id=user.id).all()
    return render_template("inbox.html", messages=messages, user=user)


@app.route("/settings", methods=["GET", "POST"])
def settings():
    user_id = session.get("user_id")
    if not user_id:
        return redirect(url_for("login"))

    user = db.session.get(User, user_id)
    if user.totp_secret and not session.get("2fa_verified", False):
        return redirect(url_for("verify_2fa_login"))

    return render_template("settings.html", user=user)


@app.route("/toggle-2fa", methods=["POST"])
def toggle_2fa():
    user_id = session.get("user_id")
    if not user_id:
        return redirect(url_for("login"))

    user = db.session.get(User, user_id)
    if user.totp_secret:
        return redirect(url_for("disable_2fa"))
    else:
        return redirect(url_for("enable_2fa"))


@app.route("/change-password", methods=["POST"])
def change_password():
    user_id = session.get("user_id")
    if not user_id:
        return redirect(url_for("login"))

    user = db.session.get(User, user_id)
    old_password = request.form["old_password"]
    new_password = request.form["new_password"]

    if bcrypt.check_password_hash(user.password_hash, old_password):
        user.password_hash = bcrypt.generate_password_hash(new_password).decode("utf-8")
        db.session.commit()
        flash("Password successfully changed.")
    else:
        flash("Incorrect old password.")

    return redirect(url_for("settings"))


@app.route("/change-username", methods=["POST"])
def change_username():
    user_id = session.get("user_id")
    if not user_id:
        return redirect(url_for("login"))

    user = db.session.get(User, user_id)
    new_username = request.form["new_username"]
    existing_user = User.query.filter_by(username=new_username).first()

    if not existing_user:
        user.username = new_username
        db.session.commit()
        session["username"] = new_username  # Update username in session
        flash("Username successfully changed.")
    else:
        flash("This username is already taken.")

    return redirect(url_for("settings"))


@app.route("/logout")
def logout():
    session.pop("user_id", None)
    session.pop("2fa_verified", None)  # Clear 2FA verification flag
    return redirect(url_for("index"))


@app.route("/submit_message/<username>", methods=["GET", "POST"])
def submit_message(username):
    if request.method == "POST":
        user = User.query.filter_by(username=username).first()
        if not user:
            flash("User not found")
            return redirect(url_for("submit_message", username=username))

        content = request.form["content"]
        email_content = content  # Default to original content
        email_sent = False  # Flag to track email sending status

        if user.pgp_key:
            encrypted_content = encrypt_message(content, "tips@scidsg.org")
            if encrypted_content:
                message = Message(content=encrypted_content, user_id=user.id)
                email_content = encrypted_content  # Use encrypted content for email
            else:
                flash("Failed to encrypt message with PGP key.")
                return redirect(url_for("submit_message", username=username))
        else:
            message = Message(content=content, user_id=user.id)

        db.session.add(message)
        db.session.commit()

        # Checking if SMTP settings are configured
        if (
            user.email
            and user.smtp_server
            and user.smtp_port
            and user.smtp_username
            and user.smtp_password
        ):
            email_sent = send_email(user.email, "New Message", email_content, user)

        # Custom flash message for both scenarios
        if email_sent:
            flash("Message submitted and emailed")
        else:
            flash("Message submitted")

        return redirect(url_for("submit_message", username=username))

    return render_template("submit_message.html", username=username)


def send_email(recipient, subject, body, user):
    app.logger.debug(
        f"SMTP settings being used: Server: {user.smtp_server}, Port: {user.smtp_port}, Username: {user.smtp_username}"
    )
    msg = MIMEMultipart()
    msg["From"] = user.email
    msg["To"] = recipient
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain"))

    try:
        app.logger.debug("Attempting to connect to SMTP server")
        with smtplib.SMTP(user.smtp_server, user.smtp_port) as server:
            app.logger.debug("Starting TLS")
            server.starttls()

            app.logger.debug("Attempting to log in to SMTP server")
            server.login(user.smtp_username, user.smtp_password)

            app.logger.debug("Sending email")
            text = msg.as_string()
            server.sendmail(user.email, recipient, text)
            app.logger.info("Email sent successfully.")
            return True
    except Exception as e:
        app.logger.error(f"Error sending email: {e}", exc_info=True)
        return False


def is_valid_pgp_key(key):
    app.logger.debug(f"Attempting to import key: {key}")
    try:
        imported_key = gpg.import_keys(key)
        app.logger.info(f"Key import attempt: {imported_key.results}")
        return imported_key.count > 0
    except Exception as e:
        app.logger.error(f"Error importing PGP key: {e}")
        return False


@app.route("/update_pgp_key", methods=["POST"])
def update_pgp_key():
    """
    Route to update the user's PGP key.
    """
    user_id = session.get("user_id")
    if not user_id:
        flash("User not authenticated.")
        return redirect(url_for("login"))

    user = db.session.get(User, user_id)
    if not user:
        flash("User not found.")
        return redirect(url_for("settings"))

    pgp_key = request.form.get("pgp_key")
    if pgp_key and is_valid_pgp_key(pgp_key):
        user.pgp_key = pgp_key
        db.session.commit()
        flash("PGP key updated successfully.")
    else:
        flash("Invalid PGP key format or import failed.")

    return redirect(url_for("settings"))


def encrypt_message(message, recipient):
    # Get the absolute path to the .gnupg directory
    gpg_home = os.path.expanduser("~/.gnupg")

    # Initialize GPG with the absolute path and custom options
    gpg = gnupg.GPG(gnupghome=gpg_home, options=["--trust-model", "always"])

    app.logger.info(f"Encrypting message for recipient: {recipient}")

    # Perform encryption
    encrypted_data = gpg.encrypt(message, recipients=recipient, always_trust=True)

    if not encrypted_data.ok:
        app.logger.error(f"Encryption failed: {encrypted_data.status}")
        return None

    return str(encrypted_data)


def list_keys():
    try:
        public_keys = gpg.list_keys()
        app.logger.info("Public keys in the keyring:")
        for key in public_keys:
            app.logger.info(f"Key: {key}")
    except Exception as e:
        app.logger.error(f"Error listing keys: {e}")


# Call this function after key import or during troubleshooting
list_keys()


@app.route("/update_smtp_settings", methods=["POST"])
def update_smtp_settings():
    user_id = session.get("user_id")
    if not user_id:
        return redirect(url_for("login"))

    user = db.session.get(User, user_id)
    if not user:
        flash("User not found")
        return redirect(url_for("settings"))

    # Updating SMTP settings from form data
    user.email = request.form.get("email")
    user.smtp_server = request.form.get("smtp_server")
    user.smtp_port = request.form.get("smtp_port")
    user.smtp_username = request.form.get("smtp_username")
    user.smtp_password = request.form.get("smtp_password")

    db.session.commit()
    flash("SMTP settings updated successfully")
    return redirect(url_for("settings"))

    msg.attach(MIMEText(body, "plain"))

    try:
        with smtplib.SMTP(user.smtp_server, user.smtp_port) as server:
            server.starttls()
            server.login(
                user.smtp_username, user.smtp_password
            )  # Use user's SMTP credentials
            text = msg.as_string()
            server.sendmail(user.email, recipient, text)
        app.logger.info("Email sent successfully.")
        return True
    except Exception as e:
        app.logger.error(f"Error sending email: {e}")
        return False


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True, host="0.0.0.0", port=5000)
