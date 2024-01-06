
version = '1.5'
gems_price = 100
version_db = version.replace('.', '_')
dsa = "SQLite" # "SQLite" or "MySQL"
mysql_connection = {
        'host': 'localhost',
        'user': 'root',
        'password': '',
        'database': 'db',
}

# ----- [ MESSAGES ] ----- #

max_load_messages = 50