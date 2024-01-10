from dotenv import load_dotenv
from os import environ
load_dotenv()
version = '1.5.1'
gems_price = 100
version_db = version.replace('.', '_')
mongodb_connection = environ("mongodb_url")
config_mongodb_db = environ("mongodb_db")

# ----- [ MESSAGES ] ----- #

max_load_messages = 50