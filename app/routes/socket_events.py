from flask_socketio import emit
from . import socketio

def setup_socket_events():

    @socketio.on('connect')
    def handle_connect():
        print("Client connected")

    @socketio.on('disconnect')
    def handle_disconnect():
        print("Client disconnected")

    @socketio.on('message')
    def handle_message(data):
        print(f"Received message: {data} from {data['username']}")
        # Эхо-ответ всем клиентам
        emit('message', data, broadcast=True)
