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
This app exposes a real MCP server at `POST /mcp` using JSON-RPC (Streamable HTTP). Optional SSE is supported for streaming agent responses.

Supported tools:
- `cases.create`
- `cases.list`
- `cases.list_all`
- `cases.get`
- `cases.rename`
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
- Arbitrary file read via `files.read_path`
- Cross-user file overwrite (shared filename namespace)

## Running Locally
```sh
cd ThreatByte-MCP
python -m venv venv_threatbyte_mcp
source venv_threatbyte_mcp/bin/activate
pip install -r requirements.txt
python db/create_db_tables.py
python run.py
```
Open: `http://localhost:5001`

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

## Notes
- The UI uses server-rendered templates.
- MCP tools are exposed under `/mcp` (JSON-RPC) and are used directly by the UI for actions.
- This app is intentionally insecure. Do not deploy it to the public internet.
