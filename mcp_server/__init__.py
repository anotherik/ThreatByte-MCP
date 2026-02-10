from flask import Flask
from app.config import Config
from app.mcp import mcp_bp
from app.db import close_db


def create_mcp_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    app.register_blueprint(mcp_bp, url_prefix="/mcp")
    app.teardown_appcontext(close_db)

    return app
