import os  # Убедитесь, что библиотека os правильно импортирована

class Config:
    """Базовый конфигурационный класс."""
    DB_USERNAME = os.getenv("DB_USERNAME", "root")
    DB_PASSWORD = os.getenv("DB_PASSWORD", "Kolokola2006")
    DB_HOST = os.getenv("DB_HOST", "localhost")
    DB_DATABASE = os.getenv("DB_DATABASE", "hackFlask")
    SECRET_KEY = os.getenv('SECRET_KEY', 'your-default-secret-key')
    SQLALCHEMY_DATABASE_URI = f'mysql+pymysql://{DB_USERNAME}:{DB_PASSWORD}@{DB_HOST}/{DB_DATABASE}'
    JWT_SECRET_KEY = "super-secret-key"
    SQLALCHEMY_TRACK_MODIFICATIONS = False

