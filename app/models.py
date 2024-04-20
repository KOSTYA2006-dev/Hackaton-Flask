from flask_sqlalchemy import SQLAlchemy

# Создание экземпляра SQLAlchemy
db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    google_id = db.Column(db.String(255), unique=True, nullable=False)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(80), unique=True, nullable=False)
    img = db.Column(db.String(80), unique=True, nullable=True)
    lvl = db.Column(db.Integer, nullable=True)
    profile_completed = db.Column(db.Boolean, default=False)
    last_profile_update = db.Column(db.DateTime)
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
    preferred_meeting_day = db.Column(db.String(10))  # Например, 'Monday'
    meeting_duration = db.Column(db.Integer)  # Продолжительность в минутах, например, 10, 15, 30
    last_agreed_to_meet = db.Column(db.DateTime)  # Последняя дата согласия на встречу

class Meeting(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    initiator_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    participant_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    initiator = db.relationship('User', foreign_keys=[initiator_id])
    participant = db.relationship('User', foreign_keys=[participant_id])
    scheduled_time = db.Column(db.DateTime)  # Запланированное время встречи
    duration = db.Column(db.Integer)  # Продолжительность встречи
    meeting_type = db.Column(db.String(50))  # 'Онлайн' или 'Оффлайн'
    status = db.Column(db.String(50), default='Scheduled')  # Может быть 'Scheduled', 'Completed', 'Cancelled'
