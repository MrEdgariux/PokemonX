import sqlite3, time
from datetime import datetime
from functions import *
from config import *
from flask import g, request
from flask import render_template
from flask import Flask
from flask import redirect, url_for
from flask import session

app = Flask(__name__)

# Set the secret key to some random bytes. Keep this really secret!
app.secret_key = b'_5#y2L"F4Q8z\n\xec]/'

validate_tables()

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
    if is_user_logged_in() and not user_exists(get_user_session()):
        logout_user()
    g.start = time.time()

@app.after_request
def log_request(response):
    if 'start' not in g:
        return response

    db = sqlite3.connect(__file__ + f'/../maindb_{version_db}.db')
    cursor = db.cursor()
    visit_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    page_name = request.path  # get the full path of the request
    refer = request.referrer  # get the referer (if any)
    method = request.method  # get the request method (GET, POST, etc.)
    status_code = response.status_code  # get the response status code (200, 201, 404, etc.)
    if is_user_logged_in():
        user_id = get_user_id()
        cursor.execute('''
            INSERT INTO user_activities(user_id, page_uri, visit_time, method, status_code)
            VALUES(?, ?, ?, ?, ?)
        ''', (user_id, page_name, visit_time, method, status_code))
    cursor.execute('''
        INSERT INTO page_visits(page_name, visit_time, method, status_code, ref)
        VALUES(?, ?, ?, ?, ?)
    ''', (page_name, visit_time, method, status_code, refer))
    db.commit()
    db.close()

    return response

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

# ------ [ USER ] ------

@app.route('/user', methods=['GET'])
def userData():
    if is_user_logged_in():
        return render_template('user.html', user=get_user_by_username(get_user_session()))
    return redirect(url_for('login'))


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
            user_id = get_user_by_username(username)[0]
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
            user_id = get_user_by_username(username)[0]
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
            if modify_user(username, password, money, gems, role, id):
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

if __name__ == '__main__':
    app.run(debug=True)

# https://i.ibb.co/2SgpHyb/mredgariux-pokemon-group-v-5-2-54c368c8-1ae3-43a6-994c-22a3d60b7f00-0.png
# https://i.ibb.co/VthjvKL/mredgariux-pokemon-group-v-5-2-54c368c8-1ae3-43a6-994c-22a3d60b7f00-1.png
# https://i.ibb.co/CmwqY85/mredgariux-pokemon-group-v-5-2-54c368c8-1ae3-43a6-994c-22a3d60b7f00-2.png
# https://i.ibb.co/5j8Y8pH/mredgariux-pokemon-group-v-5-2-54c368c8-1ae3-43a6-994c-22a3d60b7f00-3.png
# https://i.ibb.co/svDVkPY/mredgariux-Pokemon-in-lucid-dream-v-5-2-293edd87-d8d5-4b54-b4e9-4231522febff-0.png
# https://i.ibb.co/cDRwM9k/mredgariux-Pokemon-in-lucid-dream-v-5-2-293edd87-d8d5-4b54-b4e9-4231522febff-1.png
# https://i.ibb.co/x7Sk59s/mredgariux-Pokemon-in-lucid-dream-v-5-2-293edd87-d8d5-4b54-b4e9-4231522febff-2.png
# https://i.ibb.co/DC74ZjW/mredgariux-Pokemon-in-lucid-dream-v-5-2-293edd87-d8d5-4b54-b4e9-4231522febff-3.png
# https://i.ibb.co/cFG9Mv4/mredgariux-pokemon-v-5-2-1d18c81c-ed9d-4611-ad77-fdf8ec11ca26-0.png
# https://i.ibb.co/rGXWKGw/mredgariux-pokemon-v-5-2-1d18c81c-ed9d-4611-ad77-fdf8ec11ca26-1.png
# https://i.ibb.co/ZHnBRqr/mredgariux-pokemon-v-5-2-1d18c81c-ed9d-4611-ad77-fdf8ec11ca26-2.png
# https://i.ibb.co/yQBy9k3/mredgariux-pokemon-v-5-2-1d18c81c-ed9d-4611-ad77-fdf8ec11ca26-3.png