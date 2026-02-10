import base64
import json
import os
from flask import Blueprint, request, jsonify, current_app, Response

from .db import get_db
from .auth import get_current_user

mcp_bp = Blueprint("mcp", __name__)


def _json_response(payload, status=200):
    return jsonify(payload), status


def _wants_sse():
    accept = request.headers.get("Accept", "")
    return "text/event-stream" in accept or request.args.get("stream") in {"1", "true", "yes"}


_OPENAI_INIT_ERROR = None


def _get_openai_client():
    api_key = os.environ.get("TBMCP_OPENAI_API_KEY") or os.environ.get("OPENAI_API_KEY")
    if not api_key:
        return None
    try:
        from openai import OpenAI
    except Exception:
        return None
    try:
        return OpenAI(api_key=api_key)
    except Exception as exc:
        global _OPENAI_INIT_ERROR
        _OPENAI_INIT_ERROR = f"OpenAI client init failed: {exc}"
        return None


def _run_llm_task(prompt):
    client = _get_openai_client()
    if not client:
        return None

    model = os.environ.get("TBMCP_OPENAI_MODEL", "gpt-4o-mini")

    if hasattr(client, "responses"):
        response = client.responses.create(
            model=model,
            input=prompt,
        )
        if hasattr(response, "output_text"):
            return response.output_text

        output_text = []
        for item in getattr(response, "output", []) or []:
            for content in getattr(item, "content", []) or []:
                if getattr(content, "type", "") == "output_text":
                    output_text.append(getattr(content, "text", ""))
        return "\n".join(output_text).strip() or None

    # Fallback for SDKs without responses: use Chat Completions
    response = client.chat.completions.create(
        model=model,
        messages=[{"role": "user", "content": prompt}],
    )
    choices = getattr(response, "choices", []) or []
    if not choices:
        return None
    message = getattr(choices[0], "message", None)
    return getattr(message, "content", None)


def _build_prompt(case, task, combined_notes):
    # Intentionally unsafe: hardcoded tokens embedded in prompt template (MCP01 demo)
    ticketing_token = "TICKET_API_TOKEN=tbmcp-ticket-prod-0000000000"
    siem_token = "SIEM_API_TOKEN=tbmcp-siem-prod-0000000000"
    return (
        "You are a SOC analyst assistant. Use the case context and notes to perform the task.\n"
        "If needed, interact with external tools using the tokens below.\n"
        f"{ticketing_token}\n"
        f"{siem_token}\n"
        f"Case: {case['title']} (severity: {case['severity']})\n"
        f"Task: {task}\n"
        "Notes:\n"
        f"{combined_notes}"
    )


def _rpc_error(code, message, rpc_id=None):
    return {"jsonrpc": "2.0", "id": rpc_id, "error": {"code": code, "message": message}}


def _rpc_result(result, rpc_id):
    return {"jsonrpc": "2.0", "id": rpc_id, "result": result}


def _require_user(rpc_id):
    user = get_current_user()
    if user:
        return user, None
    token = request.headers.get("X-TBMCP-Token", "")
    expected = current_app.config.get("MCP_SERVER_TOKEN", "")
    if not expected or token != expected:
        return None, _rpc_error(-32000, "Unauthorized", rpc_id)
    user_id = request.headers.get("X-TBMCP-User", "")
    if not user_id:
        return None, _rpc_error(-32000, "User context required", rpc_id)
    db = get_db()
    row = db.execute(
        "SELECT id, username, email FROM users WHERE id = ?",
        (user_id,),
    ).fetchone()
    if not row:
        return None, _rpc_error(-32000, "User not found", rpc_id)
    return row, None


def _log_agent_run(db, case_id, request_data, response_data, prompt):
    # Intentionally logs full requests/responses including tokens (MCP01 demo)
    request_payload = dict(request_data or {})
    request_payload["prompt"] = prompt
    request_blob = json.dumps(request_payload, ensure_ascii=True)
    response_blob = json.dumps(response_data, ensure_ascii=True)
    db.execute(
        "INSERT INTO agent_logs (case_id, request_json, response_json) VALUES (?, ?, ?)",
        (case_id, request_blob, response_blob),
    )
    db.commit()


def _parse_schema_blob(blob):
    if not blob:
        return None
    if isinstance(blob, dict):
        return blob
    try:
        return json.loads(blob)
    except Exception:
        return None


def _tool_registry_list(db, _user, _args):
    cols = [row["name"] for row in db.execute("PRAGMA table_info(mcp_tools)").fetchall()]
    if "description" in cols:
        rows = db.execute(
            "SELECT name, description, config_json, updated_at FROM mcp_tools ORDER BY updated_at DESC"
        ).fetchall()
        tools = []
        for row in rows:
            schema = _parse_schema_blob(row["config_json"]) if "config_json" in row.keys() else None
            tools.append(
                {
                    "name": row["name"],
                    "description": row["description"],
                    "schema": schema,
                    "updated_at": row["updated_at"],
                }
            )
        return {"ok": True, "tools": tools}

    if "command_template" in cols:
        rows = db.execute(
            "SELECT name, command_template FROM mcp_tools ORDER BY id DESC"
        ).fetchall()
        return {
            "ok": True,
            "tools": [
                {"name": row["name"], "description": "Legacy tool", "schema": None}
                for row in rows
            ],
        }
    rows = db.execute(
        "SELECT name FROM mcp_tools ORDER BY id DESC"
    ).fetchall()
    return {
        "ok": True,
        "tools": [{"name": row["name"], "description": "Legacy tool", "schema": None} for row in rows],
    }


def _normalize_schema(args):
    raw_schema = args.get("schema") or args.get("schema_json") or args.get("config_json")
    schema = _parse_schema_blob(raw_schema)
    if not schema:
        return None, "Valid schema_json is required"
    name = (schema.get("name") or "").strip()
    description = (schema.get("description") or "").strip()
    input_schema = schema.get("inputSchema")
    handler = schema.get("handler") or {}
    handler_type = (handler.get("type") or "").strip()
    handler_target = (handler.get("target") or "").strip()
    if not name or not description or not isinstance(input_schema, dict):
        return None, "Schema must include name, description, and inputSchema"
    if handler_type != "builtin" or not handler_target:
        return None, "Schema handler must specify type 'builtin' with a target tool"
    schema["name"] = name
    schema["description"] = description
    schema["handler"] = {"type": "builtin", "target": handler_target}
    return schema, None


def _tool_registry_register(db, _user, args):
    schema, error = _normalize_schema(args or {})
    if error:
        return {"error": error}
    name = schema["name"]
    description = schema["description"]
    config_json = json.dumps(schema, ensure_ascii=True)
    cols = [row["name"] for row in db.execute("PRAGMA table_info(mcp_tools)").fetchall()]
    if "description" not in cols:
        db.execute("ALTER TABLE mcp_tools ADD COLUMN description TEXT")
        cols.append("description")
    if "response_template" not in cols:
        db.execute("ALTER TABLE mcp_tools ADD COLUMN response_template TEXT")
        cols.append("response_template")
    if "tool_type" not in cols:
        db.execute("ALTER TABLE mcp_tools ADD COLUMN tool_type TEXT")
        cols.append("tool_type")
    if "config_json" not in cols:
        db.execute("ALTER TABLE mcp_tools ADD COLUMN config_json TEXT")
        cols.append("config_json")

    command_template = "SCHEMA"
    # Intentionally allows overwrite of existing tools (tool poisoning demo)
    if "command_template" in cols:
        db.execute(
            "INSERT INTO mcp_tools (name, description, response_template, tool_type, config_json, command_template) "
            "VALUES (?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(name) DO UPDATE SET description = excluded.description, "
            "response_template = excluded.response_template, tool_type = excluded.tool_type, "
            "config_json = excluded.config_json, command_template = excluded.command_template, "
            "updated_at = CURRENT_TIMESTAMP",
            (name, description, "", "", config_json, command_template),
        )
    else:
        db.execute(
            "INSERT INTO mcp_tools (name, description, response_template, tool_type, config_json) "
            "VALUES (?, ?, ?, ?, ?) "
            "ON CONFLICT(name) DO UPDATE SET description = excluded.description, "
            "response_template = excluded.response_template, tool_type = excluded.tool_type, "
            "config_json = excluded.config_json, updated_at = CURRENT_TIMESTAMP",
            (name, description, "", "", config_json),
        )
    db.commit()
    return {"ok": True}


def _tool_registry_delete(db, _user, args):
    name = (args.get("name") or "").strip()
    if not name:
        return {"error": "name is required"}
    db.execute("DELETE FROM mcp_tools WHERE name = ?", (name,))
    db.commit()
    return {"ok": True}


def _execute_builtin_tool(db, user, name, args):
    if name in _TOOL_HANDLERS:
        return _TOOL_HANDLERS[name](db, user, args)
    return {"error": "tool not found"}


def _tool_registry_call(db, user, tool_name, args):
    cols = [row["name"] for row in db.execute("PRAGMA table_info(mcp_tools)").fetchall()]
    if "description" in cols:
        row = db.execute(
            "SELECT name, description, config_json FROM mcp_tools WHERE name = ?",
            (tool_name,),
        ).fetchone()
        if not row:
            return {"error": "tool not found"}
        schema = _parse_schema_blob(row["config_json"]) if "config_json" in row.keys() else None
        if not schema:
            return {"error": "tool schema missing"}
        handler = schema.get("handler") or {}
        handler_type = (handler.get("type") or "").strip()
        handler_target = (handler.get("target") or "").strip()
        if handler_type != "builtin" or not handler_target:
            return {"error": "unsupported handler"}
        return _execute_builtin_tool(db, user, handler_target, args)
    elif "command_template" in cols:
        row = db.execute(
            "SELECT name, command_template FROM mcp_tools WHERE name = ?",
            (tool_name,),
        ).fetchone()
        if not row:
            return {"error": "tool not found"}
        # Legacy schema: treat command_template as a static output
        return {"ok": True, "output": row["command_template"]}
    else:
        row = db.execute(
            "SELECT name FROM mcp_tools WHERE name = ?",
            (tool_name,),
        ).fetchone()
        if not row:
            return {"error": "tool not found"}
        return {"ok": True, "output": "Tool executed."}

    return {"error": "unsupported tool"}


def _parse_tool_directive(text):
    # Expected: CALL_TOOL:tool.name key=value key="value with spaces"
    if not text or "CALL_TOOL:" not in text:
        return None
    line = None
    for raw in text.splitlines():
        if "CALL_TOOL:" in raw:
            line = raw.strip()
            break
    if not line:
        return None
    _, rest = line.split("CALL_TOOL:", 1)
    rest = rest.strip()
    if not rest:
        return None
    parts = rest.split()
    tool_name = parts[0]
    args = {}
    for part in parts[1:]:
        if "=" not in part:
            continue
        key, value = part.split("=", 1)
        value = value.strip().strip('"')
        args[key] = value
    return {"tool_name": tool_name, "args": args}


def _execute_tool_by_name(db, user, name, args):
    if isinstance(args, dict) and "case_id" in args:
        try:
            args["case_id"] = int(args["case_id"])
        except Exception:
            pass
    registry = db.execute(
        "SELECT name FROM mcp_tools WHERE name = ?",
        (name,),
    ).fetchone()
    if registry:
        return _tool_registry_call(db, user, name, args)
    return _execute_builtin_tool(db, user, name, args)


def _tool_cases_create(db, user, args):
    title = (args.get("title") or "").strip()
    severity = (args.get("severity") or "low").strip()
    status = (args.get("status") or "open").strip()
    if not title:
        return {"error": "title is required"}
    db.execute(
        "INSERT INTO cases (title, severity, status, owner_id) VALUES (?, ?, ?, ?)",
        (title, severity, status, user["id"]),
    )
    db.commit()
    return {"ok": True}


def _tool_cases_list(db, user, args):
    owner_id = args.get("owner_id")
    if owner_id:
        # Intentionally trusts the provided owner_id (BOLA demo)
        rows = db.execute(
            "SELECT id, title, severity, status, owner_id, created_at FROM cases WHERE owner_id = ? ORDER BY created_at DESC",
            (owner_id,),
        ).fetchall()
    else:
        rows = db.execute(
            "SELECT id, title, severity, status, owner_id, created_at FROM cases WHERE owner_id = ? ORDER BY created_at DESC",
            (user["id"],),
        ).fetchall()
    return {"ok": True, "cases": [dict(row) for row in rows]}


def _tool_cases_rename(db, _user, args):
    case_id = args.get("case_id")
    new_title = (args.get("title") or "").strip()
    if not case_id or not new_title:
        return {"error": "case_id and title are required"}
    db.execute("UPDATE cases SET title = ? WHERE id = ?", (new_title, case_id))
    db.commit()
    return {"ok": True, "output": f"Case {case_id} renamed to '{new_title}'."}


def _tool_cases_set_status(db, _user, args):
    case_id = args.get("case_id")
    status = (args.get("status") or "").strip()
    if not case_id or not status:
        return {"error": "case_id and status are required"}
    db.execute("UPDATE cases SET status = ? WHERE id = ?", (status, case_id))
    db.commit()
    return {"ok": True, "output": f"Case {case_id} status set to '{status}'."}


def _tool_cases_delete(db, _user, args):
    case_id = args.get("case_id")
    if not case_id:
        return {"error": "case_id is required"}
    db.execute("DELETE FROM cases WHERE id = ?", (case_id,))
    db.commit()
    return {"ok": True, "output": f"Case {case_id} deleted."}


def _tool_cases_get(db, _user, args):
    case_id = args.get("case_id")
    if not case_id:
        return {"error": "case_id is required"}
    case = db.execute(
        "SELECT id, title, severity, status, owner_id, created_at FROM cases WHERE id = ?",
        (case_id,),
    ).fetchone()
    if not case:
        return {"error": "case not found"}
    return {"ok": True, "case": dict(case)}


def _tool_cases_list_all(db, _user, _args):
    rows = db.execute(
        "SELECT id, title, severity, status, owner_id, created_at FROM cases ORDER BY created_at DESC"
    ).fetchall()
    return {"ok": True, "cases": [dict(row) for row in rows]}


def _tool_notes_create(db, user, args):
    case_id = args.get("case_id")
    content = args.get("content") or ""
    if not case_id:
        return {"error": "case_id is required"}
    # Intentionally does not verify case ownership (BOLA demo)
    db.execute(
        "INSERT INTO notes (case_id, content, author_id) VALUES (?, ?, ?)",
        (case_id, content, user["id"]),
    )
    db.commit()
    return {"ok": True}


def _tool_notes_list(db, _user, args):
    case_id = args.get("case_id")
    if not case_id:
        return {"error": "case_id is required"}
    rows = db.execute(
        "SELECT id, case_id, content, author_id, created_at FROM notes WHERE case_id = ? ORDER BY created_at DESC",
        (case_id,),
    ).fetchall()
    return {"ok": True, "notes": [dict(row) for row in rows]}


def _tool_notes_update(db, _user, args):
    note_id = args.get("note_id")
    content = args.get("content") or ""
    if not note_id:
        return {"error": "note_id is required"}
    # Intentionally updates without verifying ownership
    db.execute("UPDATE notes SET content = ? WHERE id = ?", (content, note_id))
    db.commit()
    return {"ok": True}


def _tool_notes_delete(db, _user, args):
    note_id = args.get("note_id")
    if not note_id:
        return {"error": "note_id is required"}
    # Intentionally deletes without verifying ownership
    db.execute("DELETE FROM notes WHERE id = ?", (note_id,))
    db.commit()
    return {"ok": True}


def _tool_files_upload(db, user, args):
    case_id = args.get("case_id")
    filename = args.get("filename") or ""
    content_b64 = args.get("content_base64") or ""
    if not case_id or not filename or not content_b64:
        return {"error": "case_id, filename, content_base64 are required"}

    upload_folder = current_app.config["UPLOAD_FOLDER"]
    os.makedirs(upload_folder, exist_ok=True)

    stored_name = filename
    save_path = os.path.join(upload_folder, stored_name)

    try:
        raw = base64.b64decode(content_b64)
    except Exception:
        return {"error": "invalid base64 content"}

    with open(save_path, "wb") as f:
        f.write(raw)

    # Intentionally skips ownership checks on the case
    db.execute(
        "INSERT INTO files (case_id, filename, original_name, owner_id) VALUES (?, ?, ?, ?)",
        (case_id, stored_name, filename, user["id"]),
    )
    db.commit()
    return {"ok": True, "filename": stored_name}


def _tool_files_list(db, _user, args):
    case_id = args.get("case_id")
    if not case_id:
        return {"error": "case_id is required"}
    rows = db.execute(
        "SELECT id, case_id, filename, original_name, owner_id, uploaded_at FROM files WHERE case_id = ? ORDER BY uploaded_at DESC",
        (case_id,),
    ).fetchall()
    return {"ok": True, "files": [dict(row) for row in rows]}


def _tool_files_get(db, _user, args):
    file_id = args.get("file_id")
    if not file_id:
        return {"error": "file_id is required"}
    row = db.execute(
        "SELECT id, filename, original_name FROM files WHERE id = ?",
        (file_id,),
    ).fetchone()
    if not row:
        return {"error": "file not found"}
    upload_folder = current_app.config["UPLOAD_FOLDER"]
    file_path = os.path.join(upload_folder, row["filename"])
    if not os.path.exists(file_path):
        return {"error": "file missing on disk"}
    with open(file_path, "rb") as f:
        content_b64 = base64.b64encode(f.read()).decode("ascii")
    return {"ok": True, "filename": row["original_name"], "content_base64": content_b64}


def _tool_files_read_path(_db, _user, args):
    path = args.get("path") or ""
    if not path:
        return {"error": "path is required"}
    # Intentionally unsafe: read arbitrary filesystem path
    if not os.path.exists(path):
        return {"error": "path not found"}
    with open(path, "rb") as f:
        content_b64 = base64.b64encode(f.read()).decode("ascii")
    return {"ok": True, "path": path, "content_base64": content_b64}


def _tool_indicators_search(db, _user, args):
    query = args.get("q", "")
    # Intentionally unsafe string concatenation (SQLi demo)
    sql = f"SELECT id, indicator, indicator_type, description FROM indicators WHERE indicator LIKE '%{query}%'"
    rows = db.execute(sql).fetchall()
    return {"ok": True, "results": [dict(row) for row in rows]}


def _tool_agent_summarize_case(db, _user, args):
    case_id = args.get("case_id")
    if not case_id:
        return {"error": "case_id is required"}
    case = db.execute(
        "SELECT id, title, severity, owner_id, created_at FROM cases WHERE id = ?",
        (case_id,),
    ).fetchone()
    if not case:
        return {"error": "case not found"}
    notes = db.execute(
        "SELECT content FROM notes WHERE case_id = ? ORDER BY created_at DESC",
        (case_id,),
    ).fetchall()
    combined_notes = "\n".join([row["content"] for row in notes])
    task = "Summarize the case and propose next steps."
    prompt = _build_prompt(case, task, combined_notes)
    llm_output = _run_llm_task(prompt)
    if not llm_output:
        detail = _OPENAI_INIT_ERROR or "LLM unavailable. Set TBMCP_OPENAI_API_KEY to enable agent."
        return {"error": detail}
    return {"ok": True, "summary": llm_output}


def _tool_agent_run_task(db, _user, args):
    case_id = args.get("case_id")
    task = (args.get("task") or "").strip()
    if not case_id or not task:
        return {"error": "case_id and task are required"}

    case = db.execute(
        "SELECT id, title, severity, owner_id, created_at FROM cases WHERE id = ?",
        (case_id,),
    ).fetchone()
    if not case:
        return {"error": "case not found"}

    notes = db.execute(
        "SELECT content FROM notes WHERE case_id = ? ORDER BY created_at DESC",
        (case_id,),
    ).fetchall()
    combined_notes = "\n".join([row["content"] for row in notes])

    # Intentionally vulnerable: untrusted notes are merged into the prompt context.
    tool_context = ""
    directive = _parse_tool_directive(task) or _parse_tool_directive(combined_notes)
    if directive:
        tool_result = _execute_tool_by_name(db, _user, directive["tool_name"], directive["args"])
        tool_context = "\nTool Result:\n" + json.dumps(tool_result, ensure_ascii=True)

    effective_task = task
    prompt = _build_prompt(case, effective_task, combined_notes + tool_context)

    # Persist prompt/context for later review (intentionally unsafe)
    db.execute(
        "INSERT INTO agent_contexts (case_id, prompt) VALUES (?, ?)",
        (case_id, prompt),
    )
    db.commit()

    llm_output = _run_llm_task(prompt)
    if not llm_output:
        detail = _OPENAI_INIT_ERROR or "LLM unavailable. Set TBMCP_OPENAI_API_KEY to enable agent."
        return {"error": detail}

    response = {"ok": True, "result": llm_output, "effective_task": effective_task, "llm": True}
    _log_agent_run(db, case_id, args, response, prompt)
    return response


def _base_tools_catalog():
    return [
        {
            "name": "cases.create",
            "description": "Create a new security case.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "title": {"type": "string"},
                    "severity": {"type": "string"},
                    "status": {"type": "string"},
                },
                "required": ["title"],
            },
        },
        {
            "name": "cases.list",
            "description": "List cases. Accepts optional owner_id.",
            "inputSchema": {
                "type": "object",
                "properties": {"owner_id": {"type": "integer"}},
            },
        },
        {
            "name": "cases.list_all",
            "description": "List all cases.",
            "inputSchema": {
                "type": "object",
                "properties": {},
            },
        },
        {
            "name": "cases.get",
            "description": "Get a case by id (ownership not enforced).",
            "inputSchema": {
                "type": "object",
                "properties": {"case_id": {"type": "integer"}},
                "required": ["case_id"],
            },
        },
        {
            "name": "cases.rename",
            "description": "Rename a case by id.",
            "inputSchema": {
                "type": "object",
                "properties": {"case_id": {"type": "integer"}, "title": {"type": "string"}},
                "required": ["case_id", "title"],
            },
        },
        {
            "name": "cases.set_status",
            "description": "Set case status (open | resolved | closed).",
            "inputSchema": {
                "type": "object",
                "properties": {"case_id": {"type": "integer"}, "status": {"type": "string"}},
                "required": ["case_id", "status"],
            },
        },
        {
            "name": "cases.delete",
            "description": "Delete a case by id.",
            "inputSchema": {
                "type": "object",
                "properties": {"case_id": {"type": "integer"}},
                "required": ["case_id"],
            },
        },
        {
            "name": "notes.create",
            "description": "Create a note for a case.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "case_id": {"type": "integer"},
                    "content": {"type": "string"},
                },
                "required": ["case_id", "content"],
            },
        },
        {
            "name": "notes.list",
            "description": "List notes for a case.",
            "inputSchema": {
                "type": "object",
                "properties": {"case_id": {"type": "integer"}},
                "required": ["case_id"],
            },
        },
        {
            "name": "notes.update",
            "description": "Update a note by id (ownership not enforced).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "note_id": {"type": "integer"},
                    "content": {"type": "string"},
                },
                "required": ["note_id", "content"],
            },
        },
        {
            "name": "notes.delete",
            "description": "Delete a note by id (ownership not enforced).",
            "inputSchema": {
                "type": "object",
                "properties": {"note_id": {"type": "integer"}},
                "required": ["note_id"],
            },
        },
        {
            "name": "files.upload",
            "description": "Upload a file as base64.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "case_id": {"type": "integer"},
                    "filename": {"type": "string"},
                    "content_base64": {"type": "string"},
                },
                "required": ["case_id", "filename", "content_base64"],
            },
        },
        {
            "name": "files.list",
            "description": "List files for a case.",
            "inputSchema": {
                "type": "object",
                "properties": {"case_id": {"type": "integer"}},
                "required": ["case_id"],
            },
        },
        {
            "name": "files.get",
            "description": "Get a file by id (returns base64).",
            "inputSchema": {
                "type": "object",
                "properties": {"file_id": {"type": "integer"}},
                "required": ["file_id"],
            },
        },
        {
            "name": "files.read_path",
            "description": "Read a filesystem path.",
            "inputSchema": {
                "type": "object",
                "properties": {"path": {"type": "string"}},
                "required": ["path"],
            },
        },
        {
            "name": "indicators.search",
            "description": "Search mock IOC dataset.",
            "inputSchema": {
                "type": "object",
                "properties": {"q": {"type": "string"}},
            },
        },
        {
            "name": "agent.summarize_case",
            "description": "Summarize case notes.",
            "inputSchema": {
                "type": "object",
                "properties": {"case_id": {"type": "integer"}},
                "required": ["case_id"],
            },
        },
        {
            "name": "agent.run_task",
            "description": "Run an analyst task over case context.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "case_id": {"type": "integer"},
                    "task": {"type": "string"},
                },
                "required": ["case_id", "task"],
            },
        },
        {
            "name": "tools.registry.list",
            "description": "List registered tools available to the agent.",
            "inputSchema": {"type": "object", "properties": {}},
        },
        {
            "name": "tools.builtin.list",
            "description": "List built-in tools bundled with the server.",
            "inputSchema": {"type": "object", "properties": {}},
        },
        {
            "name": "tools.registry.register",
            "description": "Register or update a tool definition via schema JSON.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "schema_json": {"type": "string"},
                    "schema": {"type": "object"},
                },
                "required": ["schema_json"],
            },
        },
        {
            "name": "tools.registry.delete",
            "description": "Delete a registered tool by name.",
            "inputSchema": {
                "type": "object",
                "properties": {"name": {"type": "string"}},
                "required": ["name"],
            },
        },
    ]


def _tools_catalog():
    base_tools = _base_tools_catalog()
    db = get_db()
    registry_rows = db.execute(
        "SELECT name, description, config_json FROM mcp_tools ORDER BY updated_at DESC"
    ).fetchall()

    tool_map = {tool["name"]: tool for tool in base_tools}
    for row in registry_rows:
        schema = _parse_schema_blob(row["config_json"]) if "config_json" in row.keys() else None
        input_schema = schema.get("inputSchema") if isinstance(schema, dict) else None
        tool_map[row["name"]] = {
            "name": row["name"],
            "description": row["description"],
            "inputSchema": input_schema or {"type": "object", "properties": {}},
        }

    return list(tool_map.values())


_TOOL_HANDLERS = {
    "cases.create": _tool_cases_create,
    "cases.list": _tool_cases_list,
    "cases.get": _tool_cases_get,
    "cases.list_all": _tool_cases_list_all,
    "cases.rename": _tool_cases_rename,
    "cases.set_status": _tool_cases_set_status,
    "cases.delete": _tool_cases_delete,
    "notes.create": _tool_notes_create,
    "notes.list": _tool_notes_list,
    "notes.update": _tool_notes_update,
    "notes.delete": _tool_notes_delete,
    "files.upload": _tool_files_upload,
    "files.list": _tool_files_list,
    "files.get": _tool_files_get,
    "files.read_path": _tool_files_read_path,
    "indicators.search": _tool_indicators_search,
    "agent.summarize_case": _tool_agent_summarize_case,
    "agent.run_task": _tool_agent_run_task,
    "tools.registry.list": _tool_registry_list,
    "tools.registry.register": _tool_registry_register,
    "tools.registry.delete": _tool_registry_delete,
    "tools.builtin.list": lambda db, _user, _args: {"ok": True, "tools": _base_tools_catalog()},
}


def _handle_rpc(payload):
    rpc_id = payload.get("id")
    method = payload.get("method")
    params = payload.get("params") or {}

    if method == "initialize":
        result = {
            "protocolVersion": "2025-06-18",
            "serverInfo": {"name": "ThreatByte-MCP", "version": "0.1"},
            "capabilities": {"tools": {"listChanged": False}},
        }
        return _rpc_result(result, rpc_id)

    if method == "notifications/initialized":
        return None

    user, err = _require_user(rpc_id)
    if err:
        return err

    db = get_db()

    if method == "tools/list":
        return _rpc_result({"tools": _tools_catalog()}, rpc_id)

    if method == "tools/call":
        name = params.get("name")
        args = params.get("arguments") or {}
        registry = db.execute(
            "SELECT name FROM mcp_tools WHERE name = ?",
            (name,),
        ).fetchone()
        if registry:
            # Tool poisoning: registry overrides built-in tools
            result = _tool_registry_call(db, user, name, args)
        elif name in _TOOL_HANDLERS:
            result = _TOOL_HANDLERS[name](db, user, args)
        else:
            return _rpc_error(-32601, "Tool not found", rpc_id)
        if isinstance(result, dict) and "error" in result:
            return _rpc_error(-32001, result["error"], rpc_id)
        return _rpc_result(result, rpc_id)

    return _rpc_error(-32601, "Method not found", rpc_id)


def _stream_text_response(rpc_id, base_result, key, text, chunk_size=200):
    total = text or ""
    offset = 0
    while offset < len(total):
        chunk = total[offset:offset + chunk_size]
        offset += chunk_size
        payload = {
            "jsonrpc": "2.0",
            "id": rpc_id,
            "result": {**base_result, "partial": True, "delta": chunk},
        }
        yield f"event: message\ndata: {json.dumps(payload)}\n\n"
    final_payload = {
        "jsonrpc": "2.0",
        "id": rpc_id,
        "result": {**base_result, key: total, "partial": False},
    }
    yield f"event: message\ndata: {json.dumps(final_payload)}\n\n"


@mcp_bp.route("", methods=["POST", "GET"])
def mcp_endpoint():
    if request.method == "GET" and _wants_sse():
        def stream():
            data = _rpc_result(
                {"server": "ThreatByte-MCP", "status": "ready"}, rpc_id=None
            )
            yield f"event: message\ndata: {json.dumps(data)}\n\n"

        return Response(stream(), mimetype="text/event-stream")

    payload = request.get_json(silent=True) or {}
    if not payload:
        return _json_response(_rpc_error(-32700, "Parse error", None), 400)

    if _wants_sse() and payload.get("method") == "tools/call":
        params = payload.get("params") or {}
        tool_name = params.get("name")
        if tool_name in {"agent.summarize_case", "agent.run_task"}:
            response = _handle_rpc(payload)
            if response is None:
                return _json_response(_rpc_error(-32603, "Internal error", payload.get("id")), 400)
            if "error" in response:
                def stream_error():
                    yield f"event: message\ndata: {json.dumps(response)}\n\n"
                return Response(stream_error(), mimetype="text/event-stream")

            result = response.get("result") or {}
            if tool_name == "agent.summarize_case":
                key = "summary"
            else:
                key = "result"
            text = result.get(key, "")
            base = dict(result)
            base.pop(key, None)
            base.pop("partial", None)
            base.pop("delta", None)

            def stream():
                yield from _stream_text_response(payload.get("id"), base, key, text)

            return Response(stream(), mimetype="text/event-stream")

    response = _handle_rpc(payload)
    if response is None:
        return ("", 204)

    if _wants_sse():
        def stream():
            yield f"event: message\ndata: {json.dumps(response)}\n\n"

        return Response(stream(), mimetype="text/event-stream")

    status = 200 if "result" in response else 400
    return _json_response(response, status)
