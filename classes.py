from functions import *

# ----- [ Command Handler ] ----- #

class ChatCommandHandler:
    def __init__(self, user_id):
        self.user_id = user_id
        self.commands = {
            '/help': self.help,
            '/start': self.start,
            '/message': self.message,
            '/ban': self.banUser,
            '/clearchat': self.clearMessages,
            # Add more commands here
        }

    def handle_command(self, command, args):
        if command in self.commands:
            # Call the corresponding function
            data = {}
            data['message'] = self.commands[command](args)
            data['is_system'] = True
            data['username'] = get_user_by_id(self.user_id)[1]
            return data

        else:
            data = {}
            data['message'] = f'Unknown command: {command}'
            data['is_system'] = True
            data['username'] = get_user_by_id(self.user_id)[1]
            return data

    def help(self, args):
        if get_user_by_id(self.user_id)[5] != 'admin':
            message = """ Commands: <br>
            <ul>
            <li>/help - Show this help message
            <li>/start - Start command
            </ul>
            """
            return message
        else:
            message = """ Commands:

            /help - Show this help message
            /start - Start command
            /message <message> - Send a message to all users
            """
            return message
        
    def start(self, args):
        return "This is default system message"

    def banUser(self, args):
        if get_user_by_id(self.user_id)[5] != 'admin':
            message = "You don't have permission to use this command"
            return message
        if len(args) < 2:
            message = "Invalid arguments. Usage: /ban <user_id> <reason>"
            return message
        user_id = args[0]
        reason = ' '.join(args[1:])
        user = get_user_by_id(user_id)
        if user is None:
            message = "User not found"
            return message
        if user[5] == 'admin':
            message = "You can't ban admin"
            return message
        
        return "User banned"
        

    def message(self, args):
        if get_user_by_id(self.user_id)[5] != 'admin':
            message = "You don't have permission to use this command"
            return message
        if len(args) < 1:
            message = "Invalid arguments. Usage: /message <message>"
            return message
        message = ' '.join(args)
        return message
    
    def clearMessages(self, args):
        if get_user_by_id(self.user_id)[5] != 'admin':
            message = "You don't have permission to use this command"
            return message
        conn = sqlite3.connect(__file__ + f'/../maindb_{version_db}.db')
        cursor = conn.cursor()
        cursor.execute('''DELETE FROM chat_messages''')
        conn.commit()
        emit('refresh', broadcast=True)
        message = "Messages cleared"
        return message
    
# Errors
class NoDBSet(Exception):
    """Custom exception class."""
    def __init__(self, message="An database in configuration haven't been set or invalid."):
        self.message = message
        super().__init__(self.message)
