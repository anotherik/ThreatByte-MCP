from mcp_server import create_mcp_app

app = create_mcp_app()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5002, debug=True)
