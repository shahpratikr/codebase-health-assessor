from flask import Flask

from views import register

app = Flask(__name__)
register(app)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)
