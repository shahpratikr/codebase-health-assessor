from flask import Flask

app = Flask(__name__)
app.config.from_object("settings")


@app.after_request
def allow_any_origin(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    return response
