import datetime
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_cors import CORS
import os
import oauthlib
from werkzeug.security import generate_password_hash, check_password_hash
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView
from authlib.integrations.flask_client import OAuth
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask import redirect, url_for, request, jsonify
from werkzeug.security import check_password_hash



app = Flask(__name__)
CORS(app)
oauth = OAuth(app)

google = oauth.register(
    name='google',
    client_id='ВАШ_GOOGLE_CLIENT_ID',
    client_secret='ВАШ_GOOGLE_CLIENT_SECRET',
    access_token_url='https://accounts.google.com/o/oauth2/token',
    access_token_params=None,
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    authorize_params=None,
    api_base_url='https://www.googleapis.com/oauth2/v1/',
    client_kwargs={'scope': 'openid email profile'}
)


app.config["JWT_SECRET_KEY"] = "super-secret-key"
jwt = JWTManager(app)

USERNAME = os.getenv('DB_USERNAME', 'root')
PASSWORD = os.getenv('DB_PASSWORD', 'Kolokola2006')
DATABASE = os.getenv('DB_DATABASE', 'hackFlask')
HOST = os.getenv('DB_HOST', 'localhost')
app.config['SQLALCHEMY_DATABASE_URI'] = f'mysql+pymysql://{USERNAME}:{PASSWORD}@{HOST}/{DATABASE}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    google_id = db.Column(db.String(255), unique=True, nullable=False)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(80), unique=True, nullable=False)
    img = db.Column(db.String(80), unique=True, nullable=True)
    lvl = db.Column(db.Integer, nullable=True)
    profile_completed = db.Column(db.Boolean, default=False)
    last_profile_update = db.Column(db.DateTime, default=datetime.datetime.day) 
    password = db.Column(db.String(255), nullable=False)
    is_busy = db.Column(db.Boolean, default=False)


class AdminUser(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)


class MeetingPreference(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('preferences', lazy=True))
    preferred_meeting_day = db.Column(db.String(10))  # например, 'Monday'
    meeting_duration = db.Column(db.Integer)  # в минутах, например, 10, 15, 30
    last_agreed_to_meet = db.Column(db.DateTime)  # Последняя дата, когда пользователь согласился на встречу

class Meeting(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    initiator_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    participant_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    initiator = db.relationship('User', foreign_keys=[initiator_id])
    participant = db.relationship('User', foreign_keys=[participant_id])
    scheduled_time = db.Column(db.DateTime)  # Фактическое запланированное время встречи
    duration = db.Column(db.Integer)  # Продолжительность встречи
    meeting_type = db.Column(db.String(50))  # 'Онлайн' или 'Оффлайн'
    status = db.Column(db.String(50), default='Scheduled')  # Может быть 'Scheduled', 'Completed', 'Cancelled'



# Flask-Admin view setup
admin_panel = Admin(app, name='Admin Panel', template_mode='bootstrap3')
admin_panel.add_view(ModelView(User, db.session))
admin_panel.add_view(ModelView(AdminUser, db.session))

@app.route('/login/google', methods=['GET'])
def login_google():
    token = oauth.google.authorize_access_token()
    resp = oauth.google.get('userinfo')
    user_info = resp.json()
    user = User.query.filter_by(google_id=user_info['id']).first()
    
    if not user:
        # Создание нового пользователя, если он не найден
        new_user = User(
            google_id=user_info['id'],
            email=user_info['email'],
            username=user_info['name'],  # Или другой способ получения имени пользователя
            img=user_info.get('picture', None),
            profile_completed=True
        )
        db.session.add(new_user)
        db.session.commit()
        user = new_user

    access_token = create_access_token(identity=user.id)
    return jsonify({'access_token': access_token}), 200

@app.route('/authorize')
def authorize():
    token = oauth.google.authorize_access_token()
    resp = oauth.google.get('userinfo')
    user_info = resp.json()
    # Сохранение данных пользователя или другие операции
    return jsonify(user_info)

@app.route('/admin/register', methods=['POST'])
def admin_register():
    data = request.get_json()
    username = data['username']
    email = data['email']
    password = data['password']
    hashed_password = generate_password_hash(password)
    existing_admin = AdminUser.query.filter_by(username=username).first()
    if existing_admin:
        existing_admin.username = username
        existing_admin.password = hashed_password
        existing_admin.email = email
    else:
        new_admin = AdminUser(username=username, password=hashed_password, email=email)
        db.session.add(new_admin)
    db.session.commit()
    return jsonify({"message": "Admin created or updated successfully"}), 201

@app.route('/admin/login', methods=['POST'])
def admin_login():
    data = request.get_json()
    username = data['username']
    password = data['password']
    admin = AdminUser.query.filter_by(username=username).first()
    if admin and check_password_hash(admin.password, password):
        access_token = create_access_token(identity=username)
        return jsonify(access_token=access_token)
    return jsonify({"message": "Invalid credentials"}), 401

# Admin routes for managing users
@app.route('/admin/users', methods=['GET'])
@jwt_required()
def get_users():
    if get_jwt_identity():
        users = User.query.all()
        return jsonify([{'id': user.id, 'username': user.username, 'email': user.email} for user in users]), 200
    return jsonify({"message": "Unauthorized"}), 403

@app.route('/admin/users/<int:user_id>', methods=['GET'])
@jwt_required()
def get_user(user_id):
    if get_jwt_identity():
        user = User.query.get(user_id)
        if user:
            return jsonify({'id': user.id, 'username': user.username, 'email': user.email})
        return jsonify({'message': 'User not found'}), 404
    return jsonify({"message": "Unauthorized"}), 403


@app.route('/admin/users/<int:user_id>', methods=['PUT'])
@jwt_required()
def update_user(user_id):
    if get_jwt_identity():
        user = User.query.get(user_id)
        if user:
            data = request.get_json()
            user.username = data.get('username', user.username)
            user.email = data.get('email', user.email)
            db.session.commit()
            return jsonify({'message': 'User updated successfully'})
        return jsonify({'message': 'User not found'}), 404
    return jsonify({"message": "Unauthorized"}), 403

@app.route('/admin/users/<int:user_id>', methods=['DELETE'])
@jwt_required()
def delete_user(user_id):
    if get_jwt_identity():
        user = User.query.get(user_id)
        if user:
            db.session.delete(user)
            db.session.commit()
            return jsonify({'message': 'User deleted successfully'}), 200
        return jsonify({'message': 'User not found'}), 404
    return jsonify({"message": "Unauthorized"}), 403

@app.route('/user/<int:user_id>/set_busy', methods=['POST'])
@jwt_required()
def set_user_busy(user_id):
    user = User.query.get(user_id)
    if user:
        user.is_busy = True
        db.session.commit()
        return jsonify({"message": "User status updated to busy"}), 200
    return jsonify({"message": "User not found"}), 404




@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    
    if User.query.filter((User.username == username) | (User.email == email)).first():
        return jsonify({'message': 'Username or email already exists'}), 409
    
    hashed_password = generate_password_hash(password)
    new_user = User(
        username=username,
        email=email,
        password=hashed_password
    )
    
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'User registered successfully'}), 201
 


@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    user = User.query.filter_by(email=email).first()
    if user and check_password_hash(user.password, password):
        access_token = create_access_token(identity=user.id)
        return jsonify(access_token=access_token), 200

    return jsonify({'me1ssage': 'Invalid credentials'}), 401


if __name__ == '__main__':
    app.run(debug=True, port=5001)

