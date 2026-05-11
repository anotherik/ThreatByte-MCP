import argparse
import sys


def _parse_args():
    parser = argparse.ArgumentParser(description="Run ThreatByte-MCP server")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument(
        "--http",
        action="store_true",
        help="Run the Streamable HTTP MCP server (what the web UI expects).",
    )
    mode.add_argument(
        "--stdio",
        action="store_true",
        help="Run the MCP server over stdio (for MCP clients that spawn the server).",
    )
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=5002)
    return parser.parse_args()


if __name__ == "__main__":
    args = _parse_args()

    if args.http:
        from mcp_server.sdk_app import app
        import uvicorn

        uvicorn.run(app, host=args.host, port=args.port)
        sys.exit(0)

    try:
        # Import only what stdio mode needs. (The web UI requires HTTP mode; stdio is for external MCP clients.)
        from mcp_server.sdk_app import mcp
        # In some environments, AnyIO's default asyncio backend can have trouble with stdio + subprocess pipes.
        # Use Trio explicitly for the stdio transport.
        import anyio

        anyio.run(mcp.run_stdio_async, backend="trio")
    except KeyboardInterrupt:
        # FastMCP stdio mode can leave background reader threads blocked on stdin; exit cleanly on Ctrl+C.
        sys.exit(0)
