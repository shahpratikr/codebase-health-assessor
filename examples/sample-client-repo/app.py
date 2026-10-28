import os

import requests
from flask import Flask, jsonify

import config

app = Flask(__name__)

ORDERS = {
    "1001": {"customer": "acme-retail", "total": 120.50, "status": "paid"},
    "1002": {"customer": "globex", "total": 89.99, "status": "pending"},
}


@app.after_request
def allow_dashboard(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Credentials"] = "true"
    return response


@app.route("/orders/<order_id>")
def order(order_id):
    found = ORDERS.get(order_id)
    if found is None:
        return jsonify({"error": "not found"}), 404
    return jsonify(found)


@app.route("/orders/<order_id>/charge", methods=["POST"])
def charge(order_id):
    found = ORDERS.get(order_id)
    if found is None:
        return jsonify({"error": "not found"}), 404
    reply = requests.post(
        config.PAYMENTS_URL,
        json={"order": order_id, "customer": found["customer"], "amount": found["total"]},
        headers={"Authorization": f"Bearer {os.environ['PAYMENTS_TOKEN']}"},
        verify=False,
        timeout=10,
    )
    return jsonify(reply.json()), reply.status_code


@app.route("/health")
def health():
    return {"status": "ok"}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=True)
