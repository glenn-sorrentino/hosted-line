from flask import Flask, request, render_template, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from dotenv import load_dotenv
import os

load_dotenv()  # Load environment variables from .env file

app = Flask(__name__)
db_user = os.getenv('DB_USER')
db_pass = os.getenv('DB_PASS')
db_name = os.getenv('DB_NAME')
app.config['SQLALCHEMY_DATABASE_URI'] = f'mysql+pymysql://{db_user}:{db_pass}@localhost/{db_name}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Database Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('messages', lazy=True))

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        new_user = User(username=username)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('inbox', username=username))
    return render_template('register.html')

@app.route('/inbox/<username>')
def inbox(username):
    user = User.query.filter_by(username=username).first()
    if user:
        messages = Message.query.filter_by(user_id=user.id).all()
        return render_template('inbox.html', messages=messages, username=username)
    return 'Inbox not found', 404

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
    db.create_all()
    app.run(debug=True)
