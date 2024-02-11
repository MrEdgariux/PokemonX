import sqlite3, pymysql
from config import *
from flask_socketio import emit

from classes import ChatCommandHandler

# ----- [ Validation Functions ] ----- #

def validate_tables():
    db = sqlite3.connect(__file__ + f'/../maindb_{version_db}.db')
    cursor = db.cursor()

    # Create the table if it doesn't exist
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS pokemons(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            type TEXT NOT NULL,
            name TEXT NOT NULL,
            price_money INTEGER NOT NULL,
            price_gems INTEGER NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(name)
        )
    ''')
    # cursor.execute('''
    #     CREATE TABLE IF NOT EXISTS pokemons(
    #         id INTEGER PRIMARY KEY AUTOINCREMENT,
    #         type TEXT NOT NULL,
    #         name TEXT NOT NULL,
    #         price_money INTEGER NOT NULL,
    #         price_gems INTEGER NOT NULL,
                   
    #         pokemon_health INTEGER NOT NULL DEFAULT 100,
    #         pokemon_attack INTEGER NOT NULL DEFAULT 10,
    #         pokemon_defense INTEGER NOT NULL DEFAULT 10,
    #         pokemon_speed INTEGER NOT NULL DEFAULT 10,
    #         pokemon_type TEXT NOT NULL,
    #         pokemon_special_attack INTEGER NOT NULL,
    #         pokemon_special_defense INTEGER NOT NULL DEFAULT 10,
                   
    #         created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    #         FOREIGN KEY(pokemon_special_attack) REFERENCES pokemon_special_attacks(id),
    #         UNIQUE(name)
    #     )
    # ''')

    # cursor.execute('''
    #     CREATE TABLE IF NOT EXISTS pokemon_special_attacks(
    #         id INTEGER PRIMARY KEY AUTOINCREMENT,
    #         name TEXT NOT NULL,
    #         attack_power INTEGER NOT NULL,
    #         attack_type TEXT NOT NULL,
    #         created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    #         UNIQUE(name)
    #     )
    # ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS user_favourite_pokemons(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            pokemon_id INTEGER NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY(pokemon_id) REFERENCES pokemons(id) ON DELETE CASCADE
        )
    ''')

    # cursor.execute('''
    #     CREATE TABLE IF NOT EXISTS battles(
    #         id INTEGER PRIMARY KEY AUTOINCREMENT,
    #         user_id INTEGER NOT NULL,
    #         pokemon_id INTEGER NOT NULL,
    #         pokemon_level INTEGER NOT NULL,
    #         pokemon_experience INTEGER NOT NULL,
    #         battle_date DATETIME DEFAULT CURRENT_TIMESTAMP,
    #         FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
    #         FOREIGN KEY(pokemon_id) REFERENCES pokemons(id) ON DELETE CASCADE
    #     )
    # ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password TEXT,
            money INTEGER NOT NULL DEFAULT 0,
            gems INTEGER NOT NULL DEFAULT 0,
            role TEXT NOT NULL DEFAULT 'user',
            UNIQUE(username)
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS pokemons_have(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            pokemon_id INTEGER NOT NULL,
            pokemon_level INTEGER NOT NULL DEFAULT 1,
            pokemon_experience INTEGER NOT NULL DEFAULT 0,
            purchase_date DATETIME DEFAULT CURRENT_TIMESTAMP,
            purchase_type TEXT NOT NULL,
            purchase_price INTEGER NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY(pokemon_id) REFERENCES pokemons(id) ON DELETE CASCADE
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS page_visits(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT NOT NULL,
            page_name TEXT NOT NULL,
            ref TEXT,
            visit_time TEXT NOT NULL,
            method TEXT NOT NULL,
            status_code INTEGER NOT NULL
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS user_activities(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            page_uri TEXT NOT NULL,
            visit_time TEXT NOT NULL,
            method TEXT NOT NULL,
            status_code INTEGER NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS chat_messages(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            message TEXT NOT NULL,
            is_command TEXT NOT NULL,
            message_time DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    ''')

    db.commit()
    db.close()

def validate_credentials(username, password):
    db = sqlite3.connect(__file__ + f'/../maindb_{version_db}.db')
    cursor = db.cursor()
    cursor.execute('''SELECT * FROM users WHERE username=?''', (username,))
    user = cursor.fetchone()
    db.close()
    if user is None:
        return False
    return verify_passwords(password, username)

def validate_purchase_code(purchaseCode):
    db = sqlite3.connect(__file__ + f'/../maindb_{version_db}.db')
    cursor = db.cursor()
    cursor.execute('''SELECT * FROM users WHERE purchaseCode=?''', (purchaseCode,))
    user = cursor.fetchone()
    db.close()
    if user is None:
        return False
    return True

def validate_admin(username):
    db = sqlite3.connect(__file__ + f'/../maindb_{version_db}.db')
    cursor = db.cursor()
    cursor.execute('''SELECT * FROM users WHERE username=? AND role='admin' ''', (username,))
    user = cursor.fetchone()
    db.close()
    if user is None:
        return False
    return True

# ----- [ User Authentification Functions ] ----- #


def register_user(username, password):
    db = sqlite3.connect(__file__ + f'/../maindb_{version_db}.db')
    cursor = db.cursor()
    cursor.execute('''SELECT * FROM users WHERE username=?''', (username,))
    user = cursor.fetchone()
    if user is not None:
        return False
    cursor.execute('''INSERT INTO users(username, password) VALUES(?, ?)''', (username, password))
    db.commit()
    db.close()
    return True

# ----- [ Pokemon Functions ] ----- #

def create_pokemon(name, type, price, price_gems):
    db = sqlite3.connect(__file__ + f'/../maindb_{version_db}.db')
    cursor = db.cursor()
    if get_pokemon(name) is not None:
        return False
    cursor.execute('''INSERT INTO pokemons(name, type, price_money, price_gems) VALUES(?, ?, ?, ?)''', (name, type, price, price_gems))
    db.commit()
    db.close()
    return True

def modify_pokemon(name, type, price, price_gems, pokemon_id):
    db = sqlite3.connect(__file__ + f'/../maindb_{version_db}.db')
    cursor = db.cursor()
    cursor.execute('''UPDATE pokemons SET name=?, type=?, price_money=?, price_gems=? WHERE id=?''', (name, type, price, price_gems, pokemon_id))
    db.commit()
    db.close()
    return True

def verify_pokemons():
    from config import gems_price
    # Verify if all pokemons have a correct gems price
    db = sqlite3.connect(__file__ + f'/../maindb_{version_db}.db')
    cursor = db.cursor()
    cursor.execute('''SELECT * FROM pokemons''')
    pokemons = cursor.fetchall()
    if pokemons is None:
        return False
    for pokemon in pokemons:
        if pokemon[4] is None:
            gems_price = pokemon[3] / gems_price
            cursor.execute('''UPDATE pokemons SET price_gems=? WHERE id=?''', (gems_price, pokemon[0]))
        elif pokemon[4] != (pokemon[3] / gems_price):
            gems_price = pokemon[3] / gems_price
            cursor.execute('''UPDATE pokemons SET price_gems=? WHERE id=?''', (gems_price, pokemon[0]))
    db.commit()
    db.close()
    return True

def delete_pokemon(pokemon_id):
    db = sqlite3.connect(__file__ + f'/../maindb_{version_db}.db')
    cursor = db.cursor()
    cursor.execute('''DELETE FROM pokemons WHERE id=?''', (pokemon_id,))
    db.commit()
    db.close()
    return True

def get_pokemons():
    db = sqlite3.connect(__file__ + f'/../maindb_{version_db}.db')
    cursor = db.cursor()
    cursor.execute('''SELECT * FROM pokemons''')
    pokemons = cursor.fetchall()
    db.close()
    return pokemons

def get_pokemon(pokemon):
    db = sqlite3.connect(__file__ + f'/../maindb_{version_db}.db')
    cursor = db.cursor()
    cursor.execute('''SELECT * FROM pokemons WHERE name=?''', (pokemon,))
    pokemon = cursor.fetchone()
    db.close()
    return pokemon

def get_pokemon_by_id(pokemon_id):
    db = sqlite3.connect(__file__ + f'/../maindb_{version_db}.db')
    cursor = db.cursor()
    cursor.execute('''SELECT * FROM pokemons WHERE id=?''', (pokemon_id,))
    pokemon = cursor.fetchone()
    db.close()
    return pokemon

def get_users_by_pokemon(pokemon_id):
    db = sqlite3.connect(__file__ + f'/../maindb_{version_db}.db')
    cursor = db.cursor()
    cursor.execute('''SELECT users.* FROM pokemons_have INNER JOIN users ON pokemons_have.user_id=users.id WHERE pokemons_have.pokemon_id=?''', (pokemon_id,))
    users = cursor.fetchall()
    db.close()
    return users

# ----- [ User Functions ] ----- #

def create_user(username, password, role):
    db = sqlite3.connect(__file__ + f'/../maindb_{version_db}.db')
    cursor = db.cursor()
    if get_user_by_username(username) is not None:
        return False
    cursor.execute('''INSERT INTO users(username, password, role) VALUES(?, ?, ?)''', (username, password, role))
    db.commit()
    db.close()
    return True

def modify_user(user_id, username, money, gems, role, password = None):
    db = sqlite3.connect(__file__ + f'/../maindb_{version_db}.db')
    cursor = db.cursor()
    if password is None:
        cursor.execute('''UPDATE users SET username=?, money=?, gems=?, role=? WHERE id=?''', (username, money, gems, role, user_id))
    else:
        cursor.execute('''UPDATE users SET username=?, money=?, gems=?, role=?, password=? WHERE id=?''', (username, money, gems, role, password, user_id))
    db.commit()
    db.close()
    return True

def modify_user_money(user_id, money):
    db = sqlite3.connect(__file__ + f'/../maindb_{version_db}.db')
    cursor = db.cursor()
    cursor.execute('''UPDATE users SET money=? WHERE id=?''', (money, user_id))
    db.commit()
    db.close()
    return True

def modify_user_gems(user_id, gems):
    db = sqlite3.connect(__file__ + f'/../maindb_{version_db}.db')
    cursor = db.cursor()
    cursor.execute('''UPDATE users SET gems=? WHERE id=?''', (gems, user_id))
    db.commit()
    db.close()
    return True

def delete_user(user_id):
    db = sqlite3.connect(__file__ + f'/../maindb_{version_db}.db')
    cursor = db.cursor()
    cursor.execute('''DELETE FROM users WHERE id=?''', (user_id,))
    db.commit()
    db.close()
    return True

def get_users():
    db = sqlite3.connect(__file__ + f'/../maindb_{version_db}.db')
    cursor = db.cursor()
    cursor.execute('''SELECT * FROM users''')
    users = cursor.fetchall()
    db.close()
    return users

def get_user_by_id(user_id):
    db = sqlite3.connect(__file__ + f'/../maindb_{version_db}.db')
    cursor = db.cursor()
    cursor.execute('''SELECT * FROM users WHERE id=?''', (user_id,))
    user = cursor.fetchone()
    db.close()
    return user

def get_user_by_username(username):
    db = sqlite3.connect(__file__ + f'/../maindb_{version_db}.db')
    cursor = db.cursor()
    cursor.execute('''SELECT * FROM users WHERE username=?''', (username,))
    user = cursor.fetchone()
    db.close()
    return user

def user_exists(username):
    db = sqlite3.connect(__file__ + f'/../maindb_{version_db}.db')
    cursor = db.cursor()
    cursor.execute('''SELECT * FROM users WHERE username=?''', (username,))
    user = cursor.fetchone()
    db.close()
    if user is None:
        return False
    return True

# ----- [ User Pokemon Interaction Functions ] ----- #

def add_pokemon_to_user(user_id, pokemon_id):
    db = sqlite3.connect(__file__ + f'/../maindb_{version_db}.db')
    cursor = db.cursor()
    cursor.execute('''INSERT INTO pokemons_have(user_id, pokemon_id) VALUES(?, ?)''', (user_id, pokemon_id))
    db.commit()
    db.close()
    return True

def remove_pokemon_from_user(user_id, pokemon_id):
    db = sqlite3.connect(__file__ + f'/../maindb_{version_db}.db')
    cursor = db.cursor()
    cursor.execute('''DELETE FROM pokemons_have WHERE user_id=? AND pokemon_id=?''', (user_id, pokemon_id))
    db.commit()
    db.close()
    return True

def add_pokemon_to_user_favourites(user_id, pokemon_id):
    db = sqlite3.connect(__file__ + f'/../maindb_{version_db}.db')
    cursor = db.cursor()
    if get_user_pokemon(user_id, pokemon_id) is None:
        return False
    cursor.execute('''INSERT INTO user_favourite_pokemons(user_id, pokemon_id) VALUES(?, ?)''', (user_id, pokemon_id))
    db.commit()
    db.close()
    return True

def remove_pokemon_from_user_favourites(user_id, pokemon_id):
    db = sqlite3.connect(__file__ + f'/../maindb_{version_db}.db')
    cursor = db.cursor()
    if get_user_pokemon(user_id, pokemon_id) is None:
        return False
    cursor.execute('''DELETE FROM user_favourite_pokemons WHERE user_id=? AND pokemon_id=?''', (user_id, pokemon_id))
    db.commit()
    db.close()
    return True

def upgrade_pokemon_for_user(user_id, pokemon_id, level):
    db = sqlite3.connect(__file__ + f'/../maindb_{version_db}.db')
    cursor = db.cursor()
    cursor.execute('''UPDATE pokemons_have SET level=? WHERE user_id=? AND pokemon_id=?''', (level, user_id, pokemon_id))
    db.commit()
    db.close()
    return True

def get_user_pokemon(user_id, pokemon_id):
    db = sqlite3.connect(__file__ + f'/../maindb_{version_db}.db')
    cursor = db.cursor()
    cursor.execute('''SELECT * FROM pokemons_have WHERE user_id=? AND pokemon_id=?''', (user_id, pokemon_id))
    pokemon = cursor.fetchone()
    db.close()
    return pokemon

def get_user_pokemons(user_id):
    db = sqlite3.connect(__file__ + f'/../maindb_{version_db}.db')
    cursor = db.cursor()
    cursor.execute('''SELECT pokemons_have.*, pokemons.* FROM pokemons_have INNER JOIN pokemons ON pokemons_have.pokemon_id=pokemons.id WHERE pokemons_have.user_id=?''', (user_id,))
    pokemons = cursor.fetchall()
    db.close()
    return pokemons

# ----- [ Chat Functions ] ----- #

def get_chat_messages():
    db = sqlite3.connect(__file__ + f'/../maindb_{version_db}.db')
    cursor = db.cursor()
    cursor.execute('''
        SELECT chat_messages.*, users.username FROM chat_messages
        INNER JOIN users ON chat_messages.user_id=users.id
        ORDER BY chat_messages.id ASC
        LIMIT 50
    ''')
    messages = cursor.fetchall()
    db.close()
    return messages

def add_chat_message(user_id, message):
    db = sqlite3.connect(__file__ + f'/../maindb_{version_db}.db')
    cursor = db.cursor()
    is_cmd = False
    if message.startswith('/'):
        is_cmd = True
    cursor.execute('''INSERT INTO chat_messages(user_id, message, is_command) VALUES(?, ?, ?)''', (user_id, message, is_cmd))
    db.commit()
    db.close()
    return True

def chat_handle_commands(message, user_id):
    if message.startswith('/'):
        message = message.split(' ')
        command = message[0]
        args = message[1:]
        data = ChatCommandHandler(user_id).handle_command(command, args)
        if data is not None:
            return data
    return None

# ----- [ Store Functions ] ----- #

def buy_pokemon(user_id, pokemon_id, selectedMethod):
    pokemon = get_pokemon_by_id(pokemon_id)
    if pokemon is None:
        return False, 'Pokemon not found'
    user = get_user_by_id(user_id)
    if user is None:
        return False, 'User not found'
    if selectedMethod == 'money':
        if user[3] <= pokemon[3]:
            return False, 'Not enough money'
        modify_user_money(user_id, user[3] - pokemon[3])
    elif selectedMethod == 'gems':
        if user[4] <= pokemon[4]:
            return False, 'Not enough gems'
        modify_user_gems(user_id, user[4] - pokemon[4])
    add_pokemon_to_user(user_id, pokemon_id)
    return True, None


# ----- [ Other Functions ] ----- #

def scan_name(name):
    import re
    pattern = re.compile(r'[^a-zA-Z0-9]')
    return not bool(pattern.search(name))

def scan_password(password, username):
    import re
    if len(password) < 8:
        return False
    if not re.search(r'\d', password):
        return False
    if not re.search(r'[A-Z]', password):
        return False
    if not re.search(r'[!@#$%^&*()_+=-]', password):
        return False
    if username in password:
        return False
    if username == password:
        return False
    return True

def scan_username(username):
    import re
    if len(username) < 3:
        return False
    elif len(username) > 20:
        return False
    elif username[0].isdigit():
        return False
    elif re.search(r'[^a-zA-Z0-9_]', username):
        return False
    return True

def password_hashing(password):
    import hashlib
    return hashlib.sha256(password.encode()).hexdigest()

def verify_passwords(password, username):
    user_id = get_user_by_username(username)[0]
    db = sqlite3.connect(__file__ + f'/../maindb_{version_db}.db')
    cursor = db.cursor()
    cursor.execute('''SELECT password FROM users WHERE id=?''', (user_id,))
    password_db = cursor.fetchone()[0]
    db.close()
    if password_hashing(password) == password_db:
        return True
    return False