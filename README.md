# ThreatByte-MCP

[![MIT License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.12%2B-blue)](https://www.python.org/)
[![GitHub stars](https://img.shields.io/github/stars/anotherik/ThreatByte-MCP.svg)](https://github.com/anotherik/ThreatByte-MCP/stargazers)

ThreatByte-MCP is a deliberately vulnerable, MCP-based case management web app. It mirrors a realistic SOC analyst workflow with a server-rendered UI and a real MCP server. The **MCP tools are intentionally vulnerable** for training and demonstration.

> For educational use in controlled environments only.

## Features
- Safe web authentication (signup/login/logout)
- Case management UI (create/list/view cases)
- Notes and attachments tied to cases
- Indicator search and agent workflows via MCP tools
- Agent customization with schema-based tool registry

## MCP Server (JSON-RPC)
ThreatByte-MCP is a split architecture:
- SOC Web App (client/UI) runs on port 5001.
- MCP Server (tools + agent) runs on port 5002.

The MCP server exposes JSON-RPC at `POST http://localhost:5002/mcp` (Streamable HTTP). Optional SSE is supported for streaming agent responses. The web UI calls the MCP server through a server-side proxy to keep auth consistent with the SOC session. A sample `mcp.json` manifest is included at the repo root.

**Architecture (simplified):**
```
          Browser
             |
             v
    +------------------+        X-TBMCP-Token + X-TBMCP-User        +-------------------+
    |  SOC Web App     |  ---------------------------------------> |     MCP Server     |
    |  (Flask, :5001)  |           /mcp-proxy (server-side)         |   (Flask, :5002)   |
    +------------------+                                            +-------------------+
             |                                                                  |
             v                                                                  v
         SQLite DB                                                      Tool registry
                                                                       Agent + tool handlers
```

**Architecture (detailed):**
```
Browser (Analyst)
  |
  v
SOC Web App (Flask, :5001)
  |  - Auth session (cookie)
  |  - Dashboards, cases, notes, files UI
  |  - /mcp-proxy forwards JSON-RPC
  |
  +--> SQLite DB
  |     - users, cases, notes, files, indicators
  |
  +--> Uploads (app/uploads)
  |
  v
MCP Server (Flask, :5002)
  |  - /mcp JSON-RPC (Streamable HTTP + SSE)
  |  - X-TBMCP-Token + X-TBMCP-User headers
  |
  +--> Tool registry (mcp_tools)
  |     - schema-based tools (poisonable)
  |
  +--> Agent runtime
  |     - prompt builder (hardcoded tokens)
  |     - LLM API call
  |
  +--> Persistence
        - agent_contexts (prompt store)
        - agent_logs (full request/response)
```

### MCP Auth Between Web App and MCP Server
The web app proxies MCP calls with these headers:
- `X-TBMCP-Token`: shared secret from `TBMCP_MCP_SERVER_TOKEN` (configured on both servers).
- `X-TBMCP-User`: current user id from the authenticated SOC session.

Direct MCP calls require the same headers.

Supported tools:
- `cases.create`
- `cases.list`
- `cases.list_all`
- `cases.get`
- `cases.rename`
- `cases.set_status`
- `cases.delete`
- `notes.create`
- `notes.list`
- `notes.update`
- `notes.delete`
- `files.upload` (base64)
- `files.list`
- `files.get` (base64)
- `files.read_path`
- `indicators.search`
- `agent.summarize_case`
- `agent.run_task`
- `tools.registry.list`
- `tools.builtin.list`
- `tools.registry.register`
- `tools.registry.delete`

## Vulnerability Themes (Training-Focused)
The following weaknesses are **intentionally present** for teaching:
- Broken object level authorization (cases/notes/files, list_all)
- Stored XSS (notes rendered as trusted HTML)
- SQL injection in indicator search
- Prompt injection in agent task runner
- Token mismanagement & secret exposure (hardcoded tokens in prompts, persisted contexts, full logs)
- Tool poisoning via schema-driven tool registry overrides (MCP03)
- Over-trusting client context (MCP header identity spoofing)
- Arbitrary file read via `files.read_path`
- Cross-user file overwrite (shared filename namespace)

## Running Locally
```sh
cd ThreatByte-MCP
python -m venv venv_threatbyte_mcp
source venv_threatbyte_mcp/bin/activate
pip install -r requirements.txt
python db/create_db_tables.py
python run_mcp_server.py
python run.py
```
Open: `http://localhost:5001`

MCP Server: `http://localhost:5002/mcp`

## Populate Sample Data
```sh
python db/populate_db.py --users 8 --cases 20 --notes 40 --files 20
```
This creates random users, cases, notes, and file artifacts. All user passwords are `Password123!`.

## LLM Integration (Required for Agent Responses)
The agent task endpoint requires a real LLM. Without an API key, the agent returns an error indicating it is unavailable.

Environment variables:
- `TBMCP_OPENAI_API_KEY` or `OPENAI_API_KEY`
- `TBMCP_OPENAI_MODEL` (default: `gpt-4o-mini`)

Keep API keys server-side only and never expose them in the browser.

## MCP Server Configuration
The SOC web app proxies MCP calls to the MCP server using a shared token.

Environment variables:
- `TBMCP_MCP_SERVER_URL` (default: `http://localhost:5002/mcp`)
- `TBMCP_MCP_SERVER_TOKEN` (shared secret between the SOC app and MCP server)

## Notes
- The UI uses server-rendered templates.
- MCP tools are exposed under `http://localhost:5002/mcp` (JSON-RPC). The UI calls them through `/mcp-proxy`.
- This app is intentionally insecure. Do not deploy it to the public internet.
