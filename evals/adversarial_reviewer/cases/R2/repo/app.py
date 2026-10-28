import os

from flask import Flask

app = Flask(__name__)
app.config.from_object("settings")
DB_HOST = os.environ["DB_HOST"]
DB_USER = os.environ["DB_USER"]
DB_PASSWORD = os.environ["DB_PASSWORD"]
