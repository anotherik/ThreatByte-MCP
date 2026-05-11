# Claude Desktop (Windows + WSL) - ThreatByte-MCP (stdio)

This guide connects **Claude Desktop on Windows** to the ThreatByte MCP server running in **WSL (Ubuntu)** using the **stdio** transport.

## What this is (Mode B)

- Claude Desktop is the **MCP client**
- ThreatByte MCP server is a **local stdio MCP server** (Claude spawns it as a subprocess and talks over stdin/stdout)

This is separate from the web app (Mode A), where the ThreatByte web UI is an **HTTP MCP client**.

## Prerequisites

- WSL is installed and your distro is available (example distro name: `Ubuntu`)
- ThreatByte-MCP is present in WSL (example path: `/path/to/ThreatByte-MCP`)
- Python dependencies are installed in the ThreatByte venv in WSL:
  - `pip install -r requirements.txt`

## Tool name compatibility (important)

Some MCP clients (including Claude Desktop) enforce strict tool name validation and reject dotted tool names like `cases.create`.

ThreatByte-MCP supports a Claude-compatible mode:

- Set `TBMCP_TOOL_NAME_MODE=claude`
- Tools are exposed as underscore names (examples):
  - `cases_create`, `cases_list`, `notes_create`, `files_read_path`, `tools_registry_register`

## Configure Claude Desktop

Claude Desktop reads MCP server definitions from:

- `%APPDATA%\Claude\claude_desktop_config.json`

Add (or merge) an `mcpServers` entry like this:

```json
{
  "mcpServers": {
    "threatbyte": {
      "command": "C:\\\\Windows\\\\System32\\\\wsl.exe",
      "args": [
        "-d",
        "Ubuntu",
        "--",
        "bash",
        "-lc",
        "cd /path/to/ThreatByte-MCP && export TBMCP_MCP_SERVER_TOKEN=tbmcp-mcp-token TBMCP_MCP_USER_ID=1 TBMCP_TOOL_NAME_MODE=claude && /path/to/ThreatByte-MCP/venv-threatbyte-mcp/bin/python3 -u run_mcp_server.py --stdio"
      ]
    }
  }
}
```

Adjust these values to match your environment:

- WSL distro name (`Ubuntu`) → check with `wsl -l -v` in PowerShell
- Repo path in WSL (`/path/to/ThreatByte-MCP`)
- Venv python path (example uses `venv-threatbyte-mcp/bin/python3`)

### Optional: enable the built-in agent tools

If you want tools like `agent_run_task` / `agent_summarize_case` to call an LLM, add an API key:

```json
{
  "mcpServers": {
    "threatbyte": {
      "command": "C:\\\\Windows\\\\System32\\\\wsl.exe",
      "args": [
        "-d",
        "Ubuntu",
        "--",
        "bash",
        "-lc",
        "cd /path/to/ThreatByte-MCP && export TBMCP_MCP_SERVER_TOKEN=tbmcp-mcp-token TBMCP_MCP_USER_ID=1 TBMCP_TOOL_NAME_MODE=claude OPENAI_API_KEY=your_key_here && /path/to/ThreatByte-MCP/venv-threatbyte-mcp/bin/python3 -u run_mcp_server.py --stdio"
      ]
    }
  }
}
```

## Restart Claude Desktop

After editing `claude_desktop_config.json`:

- Fully quit Claude Desktop
- Start it again
- Confirm the `threatbyte` server is connected and tools are available

## Example prompts (for demos)

These prompts usually trigger tool usage:

- “Use the ThreatByte MCP tools to list my open cases and open the newest one.”
- “Extract indicators from the case notes and search them using `indicators_search`.”
- “Add a note with recommended next steps using `notes_create`.”

