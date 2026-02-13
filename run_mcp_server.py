import sys

from mcp_server.sdk_app import mcp  # FastMCP instance
from mcp_server.sdk_app import app  # ASGI app for HTTP mode


if __name__ == "__main__":
    # If Glama runs it, it will pass: --transport stdio
    if "--transport" in sys.argv and "stdio" in sys.argv:
        # Run MCP in stdio mode (what Glama needs)
        mcp.run()
    else:
        # Run HTTP mode (for local dev)
        import uvicorn

        uvicorn.run(app, host="0.0.0.0", port=5002)
