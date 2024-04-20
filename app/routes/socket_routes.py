def setup_socketio_events(socketio):

    @socketio.on('connect')
    def handle_connect():
        print("Client connected")

    @socketio.on('disconnect')
    def handle_disconnect():
        print("Client disconnected")

    @socketio.on('message')
    def handle_message(data):
        print(f"Received message: {data} from {data['username']}")
        socketio.emit('message', data, broadcast=True)
