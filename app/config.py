import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(BASE_DIR, ".."))

class Config:
    SECRET_KEY = os.environ.get("TBMCP_SECRET_KEY", "dev-secret-key-change-me")
    DATABASE = os.path.join(PROJECT_ROOT, "db", "threatbyte_mcp.db")
    UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024
    MCP_SERVER_URL = os.environ.get("TBMCP_MCP_SERVER_URL", "http://localhost:5002/mcp")
    MCP_SERVER_TOKEN = os.environ.get("TBMCP_MCP_SERVER_TOKEN", "tbmcp-mcp-token")
