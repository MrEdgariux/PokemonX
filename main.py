import time, signal
from datetime import datetime
from functions import *
from config import *
from flask import g, request, render_template, Flask, redirect, url_for, session
# from flask_socketio import SocketIO, emit

def signal_handler(sig, frame):
    print('You pressed Ctrl+C!')
    exit(0)

signal.signal(signal.SIGINT, signal_handler)

app = Flask(__name__)
# socketio = SocketIO(app)

disable_requests = False # This will change automatically, DO NOT TOUCH
system_in_update_state = False # This will change automatically, DO NOT TOUCH


# Set the secret key to some random bytes. Keep this really secret!
# Don't worry, it does not have to be secure, it's just a key used to encrypt your data.
# Also, it's just a basic example, so we don't care about security.
app.secret_key = b'_5#y2L"F4Q8z\n\xec]/'

def set_user_session(username, user_id):
    session['username'] = username
    session['user_id'] = user_id

def logout_user():
    session.pop('username', None)

def get_user_session():
    return session.get('username', None)

def get_user_id():
    return session.get('user_id', None)

def is_user_logged_in():
    return get_user_session() is not None

if verify_pokemons():
    print('Pokemons verified successfully')

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.before_request
def start_timer():
    if system_in_update_state or disable_requests:
        return "ERROR OCCURRED. TRY AGAIN LATER"
    if is_user_logged_in() and not user_exists(get_user_session()):
        logout_user()
    g.start = time.time()

@app.after_request
def log_request(response):
    if 'start' not in g:
        return response
    
    ver = req_config_ver()

    if ver != version:
        print(f"Versions incorrect. {ver} - {version}")
        return redirect(url_for('update_database'))

    db, client = connect_to_mongodb()
    page_visits_collection = db["page_visits"]
    user_activities_collection = db["user_activities"]

    visit_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    page_name = request.path
    refer = request.referrer
    method = request.method
    status_code = response.status_code
    ip = request.remote_addr

    log_data = {
        "ip": ip,
        "page_name": page_name,
        "visit_time": visit_time,
        "method": method,
        "status_code": status_code,
        "ref": refer
    }

    # Log page visit
    page_visits_collection.insert_one(log_data)

    # Log user activity if logged in
    if is_user_logged_in():
        user_id = get_user_id()
        user_activity_data = {
            "user_id": user_id,
            "page_uri": page_name,
            "visit_time": visit_time,
            "method": method,
            "status_code": status_code
        }
        user_activities_collection.insert_one(user_activity_data)

    client.close()
    return response

# @socketio.on('connect')
# def handle_connection():
#     if is_user_logged_in():
#         print(f"Client connected: {get_user_session()}")
#         emit('user_joined', get_user_session(), broadcast=True)
#         load_messages()
#     else:
#         print("Not logged in user connected")
#         emit('redirect', {'url': url_for('login')} )

# @socketio.on('disconnect')
# def handle_disconnection():
#     if is_user_logged_in():
#         print(f"Client disconnected: {get_user_session()}")
#         emit('user_left', get_user_session(), broadcast=True)

# @socketio.on('user_joined')
# def handle_user_joined(username):
#     print(f"User {username} joined")
#     data = {}
#     data['message'] = f"{username} joined the chat"
#     data['is_system'] = True
#     emit('chat', data, broadcast=True)

# @socketio.on('user_left')
# def handle_user_joined(username):
#     print(f"User {username} left")
#     data = {}
#     data['message'] = f"{username} left the chat"
#     data['is_system'] = True
#     emit('chat', data, broadcast=True)

# @socketio.on('send_message')
# def handle_send_message(data):
#     add_chat_message(get_user_id(), data['message'])
#     if data['message'].startswith('/'):
#         print(f"Command received: {data['message']} by {get_user_session()}")
#         data_served = chat_handle_commands(data['message'], get_user_id())
#         if data_served is None:
#             print("Command not found, or error occurred")
#             return
#         emit('chat', data_served, broadcast=False)
#         return
#     print(f"Message received: {data['message']} by {get_user_session()}")
#     data['is_system'] = False
#     data['username'] = get_user_session()
#     emit('chat', data, broadcast=True)

# # ----- [TRADE SYSTEM] -----
    
# @socketio.on('trade_sendItem')
# def handle_trade_item(data):
#     add_chat_message(get_user_id(), data['message'])
#     if data['message'].startswith('/'):
#         print(f"Command received: {data['message']} by {get_user_session()}")
#         data_served = chat_handle_commands(data['message'], get_user_id())
#         if data_served is None:
#             print("Command not found, or error occurred")
#             return
#         emit('chat', data_served, broadcast=False)
#         return
#     print(f"Message received: {data['message']} by {get_user_session()}")
#     data['is_system'] = False
#     data['username'] = get_user_session()
#     emit('chat', data, broadcast=True)

def load_messages():
    messages = get_chat_messages()
    for message in messages:
        if message[2].startswith('/'):
            continue
        data = {}
        data['message'] = message[2]
        data['is_system'] = False
        data['username'] = get_user_by_id(message[1])[1]
        emit('chat', data, broadcast=False)

# Define a route for accessing the data
@app.route('/', methods=['GET'])
def home():
    return render_template('index.html', user=get_user_by_username(get_user_session()))

@app.route('/about', methods=['GET'])
def about():
    return render_template('about.html')

@app.route('/contact', methods=['GET'])
def contact():
    return render_template('contact.html')

@app.route('/updates', methods=['GET'])
def updates():
    return render_template('updates.html')

# ------ [ UPDATE SYSTEM ] ------

@app.route('/update/database', methods=['GET', 'POST'])
def update_database():
    if request.method == 'POST':
        client = MongoClient(mongodb_connection)
        db = client.get_database(config_mongodb_db)
        collection_names = db.list_collection_names()

        config_col = client.get_database(config_mongodb_db).get_collection("configurations")
        versions = config_col.find_one({}, {"game_version": 1, "_id": 0})
        record_ver = versions.get("game_version") if versions else None

        if record_ver == version:
            print("[! SYSTEM UPDATE FALSE ALARM !] -> SOMEONE TRIED TO FORCE SYSTEM UPDATE. FAILED")
            return "ERROR - You cannot do that. VER_SIMILAR"
        
        if not is_user_logged_in() or not validate_admin(get_user_session()):
            print("[! SYSTEM UPDATE FALSE ALARM !] -> SOMEONE TRIED TO FORCE SYSTEM UPDATE. FAILED")
            return "ERROR - You cannot do that. PERMISSION_DENIED"

        global disable_requests, system_in_update_state
        disable_requests = True
        system_in_update_state = True
        
        
        if disable_requests and system_in_update_state:
            print("[! SYSTEM UPDATE !] -> SYSTEM UPDATE STARTING. ALL REQUESTS WILL BE REJECTED")

        for collection_name in collection_names:
            if collection_name == "configurations":
                continue
            collection = db[collection_name]
            collection.delete_many({})
            print(f"[! SYSTEM UPDATE !] -> DATABASES COLLECTION {collection_name} WAS PURGED.")
        
        new_values = {
            "$set": {
                "game_version": version,
                "last_updated_at": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
        }
        config_col.update_one({}, new_values)
        print("Game / Data version updated.")
        

        return redirect(url_for('index'))  # Redirect to the main page after update
    verss = req_config_ver()
    return render_template('update_database.html', ver_db=version, config_ver_db=verss)

# ------ [ USER ] ------

@app.route('/user', methods=['GET'])
def userData():
    if is_user_logged_in():
        useris = get_user_by_username(get_user_session())
        useriss = [useris['_id'], useris['username'], useris['money'], useris['gems'], useris['role']]
        return render_template('user.html', user=useriss)
    return redirect(url_for('login'))

@app.route('/chat', methods=['GET'])
def tsend():
    if not is_user_logged_in():
        return redirect(url_for('login'))
    return render_template('chat.html')

@app.route('/user/login', methods=['POST', 'GET'])
def login():
    if is_user_logged_in():
        return redirect(url_for('userData'))
    # Handle login form submission
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # Validate username and password
        if validate_credentials(username, password):
            # Set user session or token
            user_id = str(get_user_by_username(username)["_id"])
            set_user_session(username, user_id)
            return redirect(url_for('userData'))
        else:
            error = 'Invalid credentials'
            return render_template('login.html', error=error)

    # Render login form
    return render_template('login.html')

@app.route('/user/register', methods=['POST', 'GET'])
def registeras():
    if is_user_logged_in():
        return redirect(url_for('userData'))
    # Handle login form submission
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if not scan_password(password, username):
            error = 'Password must be different from username, and must contain at least 1 number, 1 uppercase letter, 1 lowercase letter and 1 special character, and must be at least 8 characters long'
            return render_template('register.html', error=error)
        elif user_exists(username):
            error = 'User with that username already exists'
            return render_template('register.html', error=error)
        elif not username:
            error = 'Invalid username'
            return render_template('register.html', error=error)
        elif not scan_username(username):
            error = 'This username not allowed'
            return render_template('register.html', error=error)
        elif register_user(username, password_hashing(password)):
            # Set user session or token
            user_id = str(get_user_by_username(username)["_id"])
            set_user_session(username, user_id)
            return redirect(url_for('userData'))
        else:
            error = 'Failure detected'
            return render_template('register.html', error=error)

    # Render login form
    return render_template('register.html')

@app.route('/user/list-pokemons', methods=['GET'])
def userListPokemons():
    if is_user_logged_in():
        return render_template('pokemons/list.html', username=get_user_session(), pokemons=get_user_pokemons(get_user_id()))
    return redirect(url_for('login'))

@app.route('/user/logout', methods=['GET'])
def logout():
    logout_user()
    return redirect(url_for('home'))

def userData():
    if is_user_logged_in():
        return render_template('user.html', user=get_user_by_username(get_user_session()))
    return redirect(url_for('login'))

# ------ [ POKEMON STORE ] ------

@app.route('/store', methods=['GET'])
def buyPokemons():
    if is_user_logged_in():
        user_pokemons = get_user_pokemons(get_user_id())
        pokemons = get_pokemons()
        new_pokemons = [pokemon for pokemon in pokemons if pokemon[0] not in user_pokemons[0]]

        for pokemon in new_pokemons:
            print(str(pokemon[1]) + " is not in user pokemon list")
        return render_template('store/list.html', pokemons=new_pokemons)
    return redirect(url_for('login'))

@app.route('/store/buy/<int:id>', methods=['GET'])
def storeBuyPokemon(id):
    if is_user_logged_in():
        method = request.args.get('method')

        if not method or method.lower() not in ['money', 'gems']:
            return render_template('store/list.html', pokemons=get_pokemons(), error="You must provide a payment method")
        elif get_user_pokemon(get_user_id(), id):
            return render_template('store/list.html', pokemons=get_pokemons(), error="You already have this pokemon")
        success, error = buy_pokemon(get_user_id(), id, method.lower())
        if success:
            return redirect(url_for('buyPokemons'))
        else:
            return render_template('store/list.html', pokemons=get_pokemons(), error=error)
    return redirect(url_for('login'))

# ------ [ ADMIN ] ------

@app.route('/admin', methods=['GET'])
def adminData():
    return redirect(url_for('userData'))

@app.route('/admin/create-pokemon', methods=['GET', 'POST'])
def createPokemon():
    if not is_user_logged_in() or not validate_admin(get_user_session()):
            return redirect(url_for('userData'))
    if request.method == 'POST':
        name = request.form.get('name')
        type = request.form.get('type')
        price = request.form.get('price')

        if not price.isdigit() or int(price) < 0 or int(price) > 1000000:
            error = 'Invalid price'
            return render_template('pokemons/create.html', error=error)
        elif not name or not type:
            error = 'Invalid name or type'
            return render_template('pokemons/create.html', error=error)
        
        price = int(price)
        
        gems = price / gems_price

        if create_pokemon(name, type, price, gems):
            success = 'Pokemon created successfully'
            return render_template('pokemons/create.html', success=success)
        else:
            error = 'Failure detected'
            return render_template('pokemons/create.html', error=error)
    return render_template('pokemons/create.html')

@app.route('/admin/list-pokemons', methods=['GET'])
def adminListPokemons():
    if is_user_logged_in() and validate_admin(get_user_session()):
        return render_template('pokemons/list.html', username=get_user_session(), is_admin=validate_admin(get_user_session()), pokemons=get_pokemons())
    return redirect(url_for('userData'))

@app.route('/admin/modify-pokemon/<int:id>', methods=['GET', 'POST'])
def adminModifyPokemon(id):
    if not is_user_logged_in() or not validate_admin(get_user_session()):
        return redirect(url_for('userData'))
    if request.method == 'POST':
        name = request.form.get('name')
        type = request.form.get('type')
        price = request.form.get('price')

        if not price.isdigit() or int(price) < 100 or int(price) > 999999999:
            error = 'Invalid price. Must be between 100 and 999,999,999'
            return render_template('pokemons/modify.html', error=error, pokemon=get_pokemon_by_id(id))
        elif not name or not type:
            error = 'Invalid name or type'
            return render_template('pokemons/modify.html', error=error, pokemon=get_pokemon_by_id(id))
        price = int(price)
        gems = price / gems_price
        if modify_pokemon(name, type, price, gems, id):
            success = 'Pokemon modified successfully'
            return render_template('pokemons/modify.html', success=success, pokemon=get_pokemon_by_id(id))
        else:
            error = 'Failure detected'
            return render_template('pokemons/modify.html', error=error)
    if id is None:
        return redirect(url_for('adminListPokemons'))
    elif get_pokemon_by_id(id) is None:
        return render_template('404.html'), 404
    return render_template('pokemons/modify.html', pokemon=get_pokemon_by_id(id))

@app.route('/admin/delete-pokemon/<int:id>', methods=['GET'])
def adminDeletePokemon(id):
    if not is_user_logged_in() or not validate_admin(get_user_session()):
        return redirect(url_for('userData'))
    if id is None:
        return redirect(url_for('adminListPokemons'))
    elif get_pokemon_by_id(id) is None:
        return render_template('404.html'), 404
    elif get_users_by_pokemon(id):
        return render_template('pokemons/list.html', username=get_user_session(), is_admin=validate_admin(get_user_session()), pokemons=get_pokemons(), error="This pokemon is owned by some users, modify users first to delete this pokemon")
    if delete_pokemon(id):
        return redirect(url_for('adminListPokemons'))
    else:
        return 'Something happened, so page failed to load', 500

@app.route('/admin/list-users', methods=['GET'])
def adminListUsers():
    if is_user_logged_in() and validate_admin(get_user_session()):
        return render_template('users/list.html', users=get_users(), you=get_user_id())
    return redirect(url_for('userData'))

@app.route('/admin/users/add-money/<int:id>', methods=['GET', 'POST'])
def adminUserAddMoney(id):
    if is_user_logged_in() and validate_admin(get_user_session()):
        if request.method == 'POST':
            username = request.form.get('username')
            money = request.form.get('money')
            gems = request.form.get('gems')

            if not money.isdigit() or int(money) < 0 or int(money) > 1000000:
                error = 'Invalid money'
                return render_template('users/add_money.html', error=error, user=get_user_by_id(id))
            elif not gems.isdigit() or int(gems) < 0 or int(gems) > 1000000:
                error = 'Invalid gems'
                return render_template('users/add_money.html', error=error, user=get_user_by_id(id))
            elif not username:
                error = 'Invalid username'
                return render_template('users/add_money.html', error=error, user=get_user_by_id(id))
            
            money = int(money)
            gems = int(gems)
            user = get_user_by_username(username)
            if not user:
                error = 'User not found'
                return render_template('users/add_money.html', error=error, user=get_user_by_id(id))
            user_id = user[0]

            money = user[3] + money
            gems = user[4] + gems
            
            if modify_user_money(user_id, money) and modify_user_gems(user_id, gems):
                success = 'Money / Gems added successfully'
                return render_template('users/add_money.html', success=success, user=get_user_by_id(id))
            else:
                error = 'Failure detected'
                return render_template('users/add_money.html', error=error, user=get_user_by_id(id))
        return render_template('users/add_money.html', user=get_user_by_id(id))
    return redirect(url_for('userData'))

@app.route('/admin/users/set-money/<int:id>', methods=['GET', 'POST'])
def adminUserSetMoney(id):
    if is_user_logged_in() and validate_admin(get_user_session()):
        if request.method == 'POST':
            username = request.form.get('username')
            money = request.form.get('money')
            gems = request.form.get('gems')

            if not money.isdigit() or int(money) < 0 or int(money) > 1000000:
                error = 'Invalid money'
                return render_template('users/set_money.html', error=error, user=get_user_by_id(id))
            elif not gems.isdigit() or int(gems) < 0 or int(gems) > 1000000:
                error = 'Invalid gems'
                return render_template('users/set_money.html', error=error, user=get_user_by_id(id))
            elif not username:
                error = 'Invalid username'
                return render_template('users/set_money.html', error=error, user=get_user_by_id(id))
            
            money = int(money)
            gems = int(gems)
            user = get_user_by_username(username)
            if not user:
                error = 'User not found'
                return render_template('users/set_money.html', error=error, user=get_user_by_id(id))
            
            user_id = user[0]

            money = money
            gems = gems
            
            if modify_user_money(user_id, money) and modify_user_gems(user_id, gems):
                success = 'Money / Gems set successfully'
                return render_template('users/set_money.html', success=success, user=get_user_by_id(id))
            else:
                error = 'Failure detected'
                return render_template('users/set_money.html', error=error)
        return render_template('users/set_money.html', user=get_user_by_id(id))
    return redirect(url_for('userData'))


@app.route('/admin/modify-user/<int:id>', methods=['GET', 'POST'])
def adminModifyUser(id):
    if not is_user_logged_in() or not validate_admin(get_user_session()):
        return redirect(url_for('userData'))
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        money = request.form.get('money')
        gems = request.form.get('gems')
        role = request.form.get('role')

        if role.lower() not in ['user', 'admin']:
            error = 'Invalid role'
            return render_template('users/modify.html', error=error, user=get_user_by_id(id))
        elif not money.isdigit() or int(money) < 0 or int(money) > 1000000:
            error = 'Invalid money'
            return render_template('users/modify.html', error=error, user=get_user_by_id(id))
        elif not gems.isdigit() or int(gems) < 0 or int(gems) > 1000000:
            error = 'Invalid gems'
            return render_template('users/modify.html', error=error, user=get_user_by_id(id))
        elif not username:
            error = 'Invalid username'
            return render_template('users/modify.html', error=error, user=get_user_by_id(id))
        
        if password:
            if modify_user(username, money, gems, role, password, id):
                success = 'User modified successfully'
                return render_template('users/modify.html', success=success, user=get_user_by_id(id))
            else:
                error = 'Failure detected'
                return render_template('users/modify.html', error=error, user=get_user_by_id(id))
        else:
            if modify_user(username, money, gems, role, id):
                success = 'User modified successfully'
                return render_template('users/modify.html', success=success, user=get_user_by_id(id))
            else:
                error = 'Failure detected'
                return render_template('users/modify.html', error=error, user=get_user_by_id(id))
    if id is None:
        return redirect(url_for('adminListUsers'))
    elif get_user_by_id(id) is None:
        return render_template('404.html'), 404
    return render_template('users/modify.html', user=get_user_by_id(id))

@app.route('/admin/delete-user/<int:id>', methods=['GET'])
def adminDeleteUser(id):
    if not is_user_logged_in() or not validate_admin(get_user_session()):
        return redirect(url_for('userData'))
    if id is None:
        return redirect(url_for('adminListUsers'))
    elif get_user_by_id(id) is None:
        return render_template('404.html'), 404
    if delete_user(id):
        return redirect(url_for('adminListUsers'))
    else:
        return 'Something happened, so page failed to load', 500
    
@app.route('/admin/create-user', methods=['GET', 'POST'])
def adminCreateUser():
    if not is_user_logged_in() or not validate_admin(get_user_session()):
        return redirect(url_for('userData'))
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        role = request.form.get('role')
        if user_exists(username):
            error = 'User with that username already exists'
            return render_template('users/create.html', error=error)
        elif role.lower() not in ['user', 'admin']:
            error = 'Invalid role'
            return render_template('users/create.html', error=error)
        elif not username:
            error = 'Invalid username'
            return render_template('users/create.html', error=error)
        
        if create_user(username, password, role):
            success = 'User created successfully'
            return render_template('users/create.html', success=success)
        else:
            error = 'Failure detected'
            return render_template('users/create.html', error=error)
         
    return render_template('users/create.html')

@app.route('/admin/list-users-pokemons/<int:vartotojoId>', methods=['GET'])
def adminListUserPokemons(vartotojoId):
    if not is_user_logged_in() or not validate_admin(get_user_session()):
        return redirect(url_for('userData'))
    return render_template('users/list_pokemons.html', user=get_user_by_id(vartotojoId), pokemons=get_user_pokemons(vartotojoId))

if __name__ == '__main__':
    # socketio.run(app, debug=True, host='192.168.68.100', port=5000)
    app.run(debug=True)