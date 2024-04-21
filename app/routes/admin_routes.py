from flask import Blueprint, jsonify, request
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
from flask_admin import Admin
import app

from . import User, AdminUser, db

from werkzeug.security import check_password_hash

admin_bp = Blueprint('admin_bp', __name__)

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
    return jsonify({"message": "Ошибка"}), 401

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
            return jsonify({'message': 'Обнов'})
        return jsonify({'message': 'Ненайд'}), 404
    return jsonify({"message": "3"}), 403

@app.route('/admin/users/<int:user_id>', methods=['DELETE'])
@jwt_required()
def delete_user(user_id):
    if get_jwt_identity():
        user = User.query.get(user_id)
        if user:
            db.session.delete(user)
            db.session.commit()
            return jsonify({'message': 'Пользователь удален'}), 200
        return jsonify({'message': 'Пользователя нет'}), 404
    return jsonify({"message": "ошибка"}), 403
