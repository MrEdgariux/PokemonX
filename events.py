from . import socketio
socketio = SocketIO(app)

@socketio.on('connect')
def handle_connection():
    print("Client connected")

@socketio.on('disconnect')
def handle_disconnection():
    print("Client disconnected")

@socketio.on('user_joined')
def handle_user_joined(data):
    print(f"User {data} joined")

@socketio.on('send_message')
def handle_send_message(data):
    print(f"Message received: {data['message']} by {data['username']}")
    emit('chat', data, broadcast=True)