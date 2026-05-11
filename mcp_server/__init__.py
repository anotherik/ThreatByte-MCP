def create_mcp_app():
    """
    Legacy Flask wrapper kept for backward compatibility.

    The current implementation primarily uses `mcp_server.sdk_app` (FastMCP) for both
    Streamable HTTP and stdio transports. Import Flask lazily so importing the
    `mcp_server` package does not require Flask in stdio-only environments.
    """
    from flask import Flask

    from app.config import Config
    from app.db import close_db
    from app.mcp import mcp_bp

    app = Flask(__name__)
    app.config.from_object(Config)

    app.register_blueprint(mcp_bp, url_prefix="/mcp")
    app.teardown_appcontext(close_db)

    return app
