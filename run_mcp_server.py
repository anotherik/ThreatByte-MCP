import argparse

from mcp_server.sdk_app import app, mcp


def main():
    parser = argparse.ArgumentParser(description="Run ThreatByte-MCP server.")
    parser.add_argument(
        "--transport",
        choices=["streamable-http", "stdio"],
        default="streamable-http",
        help="Transport to use for the MCP server.",
    )
    parser.add_argument("--host", default="0.0.0.0", help="HTTP host (streamable-http only).")
    parser.add_argument("--port", type=int, default=5002, help="HTTP port (streamable-http only).")
    args = parser.parse_args()

    if args.transport == "stdio":
        mcp.run(transport="stdio")
        return

    import uvicorn

    uvicorn.run(app, host=args.host, port=args.port)


if __name__ == "__main__":
    main()
