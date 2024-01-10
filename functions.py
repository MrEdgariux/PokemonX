from pymongo import MongoClient
from config import *
from flask_socketio import emit
from datetime import datetime

from classes import ChatCommandHandler

def connect_to_mongodb():
    client = MongoClient(mongodb_connection)
    db = client.get_database(config_mongodb_db)
    config_col = client.get_database(config_mongodb_db).get_collection("configurations")
    
    # Retrieve game and data versions from the configurations collection
    versions = config_col.find_one({}, {"game_version": 1, "_id": 0})
    Gversion = versions.get("game_version") if versions else None
    
    if Gversion is None:
        # Game / Data version not found, create it
        data = {"game_version": version, "last_updated_at": datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        config_col.insert_one(data)
        print("Game / Data version was not found. Created.")
    elif Gversion != version:
        print(f"Client database must be updated in order to continue using the website.")
        return "ERROR - Incorrect database version", None

    return db, client

def req_config_ver():
    client = MongoClient(mongodb_connection)
    config_col = client.get_database(config_mongodb_db).get_collection("configurations")
    versions = config_col.find_one({}, {"game_version": 1, "_id": 0})
    Gversion = versions.get("game_version") if versions else None
    if Gversion:
        return Gversion
    else:
        return None
# ----- [ Validation Functions ] ----- #

def validate_credentials(username, password):
    db, client = connect_to_mongodb()
    users_collection = db["users"]

    user = users_collection.find_one({"username": username})
    
    client.close()

    if user is None:
        return False

    return verify_passwords(password, username)

def validate_admin(username):
    db, client = connect_to_mongodb()
    users_collection = db["users"]

    user = users_collection.find_one({"username": username, "role": "admin"})

    client.close()

    if user is None:
        return False

    return True

# ----- [ User Authentification Functions ] ----- #


def register_user(username, password):
    # Connect to MongoDB
    db, client = connect_to_mongodb()

    # Choose the users collection
    users_collection = db["users"]

    # Check if the username already exists
    if user_exists(username):
        client.close()
        return False

    # Insert the new user into the collection
    new_user = {"username": username, "password": password, "role": "user", "money": 0, "gems": 0}
    users_collection.insert_one(new_user)

    # Close the MongoDB connection
    client.close()

    return True

# ----- [ Pokemon Functions ] ----- #

def create_pokemon(name, type, price, price_gems):
    db, client = connect_to_mongodb()
    pokemons_collection = db["pokemons"]

    if get_pokemon(name) is not None:
        client.close()
        return False

    # Additional fields like creation_date can be added as needed
    pokemon_data = {
        "name": name,
        "type": type,
        "price_money": price,
        "price_gems": price_gems,
        "created_at": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }

    pokemons_collection.insert_one(pokemon_data)
    client.close()
    return True

def modify_pokemon(name, type, price, price_gems, pokemon_id):
    db, client = connect_to_mongodb()
    pokemons_collection = db["pokemons"]

    pokemons_collection.update_one(
        {"_id": pokemon_id},
        {"$set": {
            "name": name,
            "type": type,
            "price_money": price,
            "price_gems": price_gems
        }}
    )
    client.close()
    return True

def verify_pokemons():
    db, client = connect_to_mongodb()
    pokemons_collection = db["pokemons"]

    # Retrieve all pokemons from the MongoDB collection
    pokemons = list(pokemons_collection.find())

    if not pokemons:
        client.close()
        return False

    for pokemon in pokemons:
        current_price_gems = pokemon.get("price_gems")

        # If price_gems is missing or incorrect, update it
        if current_price_gems is None or current_price_gems != (pokemon["price_money"] / gems_price):
            new_price_gems = pokemon["price_money"] / gems_price
            pokemons_collection.update_one(
                {"_id": pokemon["_id"]},
                {"$set": {"price_gems": new_price_gems}}
            )

    client.close()
    return True

def delete_pokemon(pokemon_id):
    db, client = connect_to_mongodb()
    pokemons_collection = db["pokemons"]
    pokemons_collection.delete_one({"_id": pokemon_id})
    client.close()
    return True

def get_pokemons():
    db, client = connect_to_mongodb()
    pokemons_collection = db["pokemons"]
    pokemons = list(pokemons_collection.find())
    client.close()
    return pokemons

def get_pokemon(name):
    db, client = connect_to_mongodb()
    pokemons_collection = db["pokemons"]
    pokemon = pokemons_collection.find_one({"name": name})
    client.close()
    return pokemon

def get_pokemon_by_id(pokemon_id):
    db, client = connect_to_mongodb()
    pokemons_collection = db["pokemons"]
    pokemon = pokemons_collection.find_one({"_id": pokemon_id})
    client.close()
    return pokemon

# ----- [ User Functions ] ----- #

def create_user(username, password, role):
    # Password is already hashed so there is no functions for that.
    db, client = connect_to_mongodb()
    users_collection = db["users"]

    # Check if user with the given username already exists
    if user_exists(username):
        client.close()
        return False

    # Hash the password before storing it

    user_data = {
        "username": username,
        "password": password,
        "role": role
    }

    users_collection.insert_one(user_data)
    client.close()
    return True

def modify_user(user_id, username, money, gems, role, password=None):
    db, client = connect_to_mongodb()
    users_collection = db["users"]

    if not users_collection.find_one({"_id": user_id}):
        client.close()
        return False
    
    update_data = {
        "$set": {
            "username": username,
            "money": money,
            "gems": gems,
            "role": role
        }
    }

    if password:
        hashed_password = password_hashing(password)
        update_data["$set"]["password"] = hashed_password

    users_collection.update_one({"_id": user_id}, update_data)
    client.close()
    return True

def modify_user_money(user_id, money):
    db, client = connect_to_mongodb()
    users_collection = db["users"]

    # Check if the user with the given ID exists
    if not users_collection.find_one({"_id": user_id}):
        client.close()
        return False

    users_collection.update_one({"_id": user_id}, {"$set": {"money": money}})
    client.close()
    return True

def modify_user_gems(user_id, gems):
    db, client = connect_to_mongodb()
    users_collection = db["users"]

    # Check if the user with the given ID exists
    if not users_collection.find_one({"_id": user_id}):
        client.close()
        return False

    users_collection.update_one({"_id": user_id}, {"$set": {"gems": gems}})
    client.close()
    return True

def delete_user(user_id):
    db, client = connect_to_mongodb()
    users_collection = db["users"]

    # Check if the user with the given ID exists
    if not users_collection.find_one({"_id": user_id}):
        client.close()
        return False

    users_collection.delete_one({"_id": user_id})
    client.close()
    return True

def get_users():
    db, client = connect_to_mongodb()
    users_collection = db["users"]
    users = list(users_collection.find())
    client.close()
    return users

def get_user_by_id(user_id):
    db, client = connect_to_mongodb()
    users_collection = db["users"]
    user = users_collection.find_one({"_id": user_id})
    client.close()
    return user

def get_user_by_username(username):
    db, client = connect_to_mongodb()
    users_collection = db["users"]
    user = users_collection.find_one({"username": username})
    client.close()
    return user

def get_users_by_pokemon(pokemon_id):
    db, client = connect_to_mongodb()
    pokemons_have_collection = db["pokemons_have"]

    # Use aggregation to join the collections and retrieve users by Pokemon ID
    pipeline = [
        {"$match": {"pokemon_id": pokemon_id}},
        {"$lookup": {"from": "users", "localField": "user_id", "foreignField": "_id", "as": "user_info"}},
        {"$unwind": "$user_info"},
        {"$project": {"_id": 0, "user_id": 1, "username": "$user_info.username"}}
    ]

    users_with_pokemon = list(pokemons_have_collection.aggregate(pipeline))
    client.close()
    return users_with_pokemon

def user_exists(username):
    db, client = connect_to_mongodb()
    users_collection = db["users"]
    user = users_collection.find_one({"username": username})
    client.close()
    return user is not None

# ----- [ User Pokemon Interaction Functions ] ----- #

def add_pokemon_to_user(user_id, pokemon_id):
    db, client = connect_to_mongodb()
    pokemons_have_collection = db["pokemons_have"]

    # Check if the association already exists
    if pokemons_have_collection.find_one({"user_id": user_id, "pokemon_id": pokemon_id}):
        client.close()
        return False

    association_data = {
        "user_id": user_id,
        "pokemon_id": pokemon_id,
        "pokemon_level": 0,
        "pokemon_exp": 0,
        "added_at": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }

    pokemons_have_collection.insert_one(association_data)
    client.close()
    return True

def remove_pokemon_from_user(user_id, pokemon_id):
    db, client = connect_to_mongodb()
    pokemons_have_collection = db["pokemons_have"]

    # Check if the association exists before deleting
    if not pokemons_have_collection.find_one({"user_id": user_id, "pokemon_id": pokemon_id}):
        client.close()
        return False

    pokemons_have_collection.delete_one({"user_id": user_id, "pokemon_id": pokemon_id})
    client.close()
    return True

def add_pokemon_to_user_favourites(user_id, pokemon_id):
    db, client = connect_to_mongodb()
    user_favourites_collection = db["user_favourite_pokemons"]

    # Check if the association already exists
    if user_favourites_collection.find_one({"user_id": user_id, "pokemon_id": pokemon_id}):
        client.close()
        return False

    association_data = {
        "user_id": user_id,
        "pokemon_id": pokemon_id,
        "favourite_from": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }

    user_favourites_collection.insert_one(association_data)
    client.close()
    return True

def remove_pokemon_from_user_favourites(user_id, pokemon_id):
    db, client = connect_to_mongodb()
    user_favourites_collection = db["user_favourite_pokemons"]

    # Check if the association exists before deleting
    if not user_favourites_collection.find_one({"user_id": user_id, "pokemon_id": pokemon_id}):
        client.close()
        return False

    user_favourites_collection.delete_one({"user_id": user_id, "pokemon_id": pokemon_id})
    client.close()
    return True

def upgrade_pokemon_for_user(user_id, pokemon_id, level):
    db, client = connect_to_mongodb()
    pokemons_have_collection = db["pokemons_have"]

    # Check if the association exists before updating
    association = pokemons_have_collection.find_one({"user_id": user_id, "pokemon_id": pokemon_id})
    if not association:
        client.close()
        return False

    pokemons_have_collection.update_one(
        {"user_id": user_id, "pokemon_id": pokemon_id},
        {"$set": {"level": level}}
    )
    client.close()
    return True

def get_user_pokemon(user_id, pokemon_id):
    db, client = connect_to_mongodb()
    pokemons_have_collection = db["pokemons_have"]

    pokemon = pokemons_have_collection.find_one({"user_id": user_id, "pokemon_id": pokemon_id})
    client.close()
    return pokemon

def get_user_pokemons(user_id):
    db, client = connect_to_mongodb()
    pokemons_have_collection = db["pokemons_have"]

    # Use aggregation to join the collections and retrieve the user's Pokémon information
    pipeline = [
        {"$match": {"user_id": user_id}},
        {
            "$lookup": {
                "from": "pokemons",
                "localField": "pokemon_id",
                "foreignField": "_id",
                "as": "pokemon_info"
            }
        },
        {"$unwind": "$pokemon_info"},
        {"$project": {"_id": 0}}
    ]

    user_pokemons = list(pokemons_have_collection.aggregate(pipeline))
    client.close()
    return user_pokemons

# ----- [ Chat Functions ] ----- #

def get_chat_messages():
    db, client = connect_to_mongodb()
    chat_messages_collection = db["chat_messages"]

    # Use aggregation to join the collections and retrieve chat messages with usernames
    pipeline = [
        {"$lookup": {"from": "users", "localField": "user_id", "foreignField": "_id", "as": "user_info"}},
        {"$unwind": "$user_info"},
        {"$project": {"_id": 0, "id": "$chat_messages.id", "user_id": 1, "message": 1, "is_command": 1, "message_time": "$chat_messages.message_time", "username": "$user_info.username"}},
        {"$sort": {"id": 1}},
        {"$limit": 50}
    ]

    messages = list(chat_messages_collection.aggregate(pipeline))
    client.close()
    return messages

def add_chat_message(user_id, message):
    db, client = connect_to_mongodb()
    chat_messages_collection = db["chat_messages"]

    is_cmd = message.startswith('/')

    message_data = {
        "user_id": user_id,
        "message": message,
        "is_command": is_cmd
    }

    chat_messages_collection.insert_one(message_data)
    client.close()
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
    db, client = connect_to_mongodb()
    users_collection = db["users"]

    # Get user document by username
    user_document = users_collection.find_one({"username": username})

    if not user_document:
        client.close()
        return False

    # Extract hashed password from the user document
    password_db_hashed = user_document.get("password", "")
    client.close()
    return password_hashing(password) == password_db_hashed