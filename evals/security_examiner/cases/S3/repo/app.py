import os

import requests
from flask import Flask, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app, origins="*")


@app.route("/rates")
def rates():
    response = requests.get(os.environ["RATES_URL"], verify=False, timeout=5)
    return jsonify(response.json())


@app.route("/health")
def health():
    return {"status": "ok"}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=True)
