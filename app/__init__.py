from flask import Flask
from .config import Config
from .routes import ui_bp
from .db import close_db


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    app.register_blueprint(ui_bp)
    app.teardown_appcontext(close_db)

    return app
