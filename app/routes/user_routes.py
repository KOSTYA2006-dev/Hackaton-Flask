from flask import Blueprint, jsonify, request
from flask_jwt_extended import jwt_required, get_jwt_identity
from . import db
from . import User

from flask import Blueprint, jsonify

user_bp = Blueprint('user_bp', __name__)

@user_bp.route('/profile', methods=['GET'])
@jwt_required()
def get_user_profile():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    if user:
        user_data = {
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'level': user.lvl,
            'profile_completed': user.profile_completed,
            'last_profile_update': user.last_profile_update.isoformat(),
            'is_busy': user.is_busy
        }
        return jsonify(user_data), 200
    else:
        return jsonify({'message': 'Пользователь не найден'}), 404

@user_bp.route('/update', methods=['PUT'])
@jwt_required()
def update_user_profile():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    if user:
        data = request.get_json()
        user.username = data.get('username', user.username)
        user.email = data.get('email', user.email)
        db.session.commit()
        return jsonify({'message': 'Профиль обнавлен'}), 200
    else:
        return jsonify({'message': 'Пользователь не найден'}), 404

@user_bp.route('/set_busy', methods=['POST'])
@jwt_required()
def set_user_busy():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    if user:
        user.is_busy = True
        db.session.commit()
        return jsonify({"message": "Обнов"}), 200
    return jsonify({"message": "Не найден"}), 404
