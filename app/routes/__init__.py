from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager
from flask_socketio import SocketIO
from flask_cors import CORS
from config import Config

# Инициализация расширений
db = SQLAlchemy()
jwt = JWTManager()
socketio = SocketIO()

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    db.init_app(app)
    jwt.init_app(app)
    socketio.init_app(app)
    CORS(app)

    # Импорт модулей маршрутизации внутри функции создания приложения
    from routes import auth_routes, user_routes, admin_routes

    # Регистрация blueprint'ов
    app.register_blueprint(auth_routes.auth_bp)
    app.register_blueprint(user_routes.user_bp)
    app.register_blueprint(admin_routes.admin_bp)

    return app
