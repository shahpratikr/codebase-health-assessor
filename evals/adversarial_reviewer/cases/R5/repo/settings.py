import os

DEBUG = False
SECRET_KEY = "k7Zp2VbN8qLx5RtY1wHs"
ALLOWED_HOSTS = os.environ.get("ALLOWED_HOSTS", "").split(",")
