import os

from flask import Flask, jsonify
from flask_cors import CORS

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ["SECRET_KEY"]
CORS(app, origins=["https://portal.acme.example.com"])


@app.route("/health")
def health():
    return jsonify(status="ok")


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8080)
