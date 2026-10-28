import yaml
from flask import request


def register(app):
    @app.post("/import")
    def import_settings():
        settings = yaml.load(request.data, Loader=yaml.Loader)
        return {"keys": sorted(settings)}
