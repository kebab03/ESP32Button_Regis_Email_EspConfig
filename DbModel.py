from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from flask_login import UserMixin

app = Flask(__name__)

# Configure your database connection details here (e.g., SQLALCHEMY_DATABASE_URI)
#app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///NewDb.db'


db = SQLAlchemy(app)



class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), nullable=False, unique=True)
    email = db.Column(db.String(150), nullable=False, unique=True)
    password_hash = db.Column(db.String(100), nullable=False)
    old_password_hash = db.Column(db.String(100), nullable=False)
    settings = db.relationship('ButtonSettings', backref='user', uselist=False)

    def __init__(self, email, password, username ,old_password):
        self.email = email
        self.password_hash = self.set_password(password)
        self.old_password_hash = self.set_password(old_password)
        self.username = username

    def set_password(self, password):
        return generate_password_hash(password, method='pbkdf2:sha256')  # Use a valid hash method

    def check_password(self, password):
        print("30 from DbModel Stored password hash:", self.password_hash)
        print("31 Input password:", password)
        print("32  from DbModel ",check_password_hash(self.password_hash, password))

        return check_password_hash(self.password_hash, password)

    def get_reset_token(self, expires_sec=1800):
        s = Serializer(app.secret_key, expires_sec)
        return s.dumps({'user_id': self.id}).decode('utf-8')

    @staticmethod
    def verify_reset_token(token):
        s = Serializer(app.secret_key)
        try:
            user_id = s.loads(token)['user_id']
        except:
            return None
        print(" 48 User.query.get(user_id)",User.query.get(user_id))
        return User.query.get(user_id)

class ButtonSettings(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    num_buttons = db.Column(db.Integer, nullable=False)
    button_labels = db.Column(db.JSON, nullable=False)
    button_states = db.Column(db.String, nullable=False)  
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __init__(self, num_buttons, button_labels, button_states, user_id):
        self.num_buttons = num_buttons
        self.button_labels = button_labels
        self.button_states = button_states
        self.user_id = user_id        

    def __repr__(self):
        return f'<ButtonSettings for {self.user.username}>'

#Create tables (if not already created)
# with app.app_context():
#     db.create_all()
