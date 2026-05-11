import inspect
import os
import re
import sqlite3
from contextlib import contextmanager
import json

from mcp.server.fastmcp import FastMCP, Context
from mcp.server.fastmcp.tools.base import Tool

from app.config import Config
from app.mcp import (
    _base_tools_catalog,
    _tool_cases_create,
    _tool_cases_list,
    _tool_cases_list_all,
    _tool_cases_get,
    _tool_cases_rename,
    _tool_cases_set_status,
    _tool_cases_delete,
    _tool_notes_create,
    _tool_notes_list,
    _tool_notes_update,
    _tool_notes_delete,
    _tool_files_upload,
    _tool_files_list,
    _tool_files_get,
    _tool_files_read_path,
    _tool_indicators_search,
    _tool_agent_summarize_case,
    _tool_agent_run_task,
    _tool_registry_list,
    _tool_registry_register,
    _tool_registry_delete,
    _tool_registry_call,
    _parse_schema_blob,
)

BASE_TOOL_DESCRIPTIONS = {tool["name"]: tool["description"] for tool in _base_tools_catalog()}
_CLAUDE_TOOL_NAME_RE = re.compile(r"^[a-zA-Z0-9_-]{1,64}$")
_TOOL_NAME_MODE = os.environ.get("TBMCP_TOOL_NAME_MODE", "default").strip().lower()


@contextmanager
def _db():
    db = sqlite3.connect(Config.DATABASE)
    db.row_factory = sqlite3.Row
    try:
        yield db
    finally:
        db.close()


def _get_headers(ctx: Context | None):
    if ctx is not None:
        try:
            request = ctx.request_context.request
            if request is not None:
                return getattr(request, "headers", {}) or {}
        except Exception:
            pass
    return {}


def _get_header(headers, name):
    if not headers:
        return ""
    if hasattr(headers, "get"):
        value = headers.get(name)
        if value is None:
            value = headers.get(name.lower())
        return value or ""
    key = name.lower()
    for k, v in headers.items():
        if str(k).lower() == key:
            return v
    return ""


def _require_user(db, headers):
    token = _get_header(headers, "X-TBMCP-Token")
    expected = Config.MCP_SERVER_TOKEN
    user_id = _get_header(headers, "X-TBMCP-User")

    # stdio mode has no HTTP headers; allow a demo-friendly env-based identity.
    # This models a local MCP client spawning the server with an explicit user context.
    if (not token or not user_id) and os.environ.get("TBMCP_MCP_USER_ID"):
        token = token or os.environ.get("TBMCP_MCP_SERVER_TOKEN", "")
        user_id = user_id or os.environ.get("TBMCP_MCP_USER_ID", "")

    if not expected or token != expected:
        raise ValueError("Unauthorized")
    if not user_id:
        raise ValueError("User context required")
    row = db.execute(
        "SELECT id, username, email FROM users WHERE id = ?",
        (user_id,),
    ).fetchone()
    if not row:
        raise ValueError("User not found")
    return row


def _audit_log_mcp_call(db, user_id, tool_name: str, args, result, transport: str):
    def _insert():
        db.execute(
            "INSERT INTO mcp_audit_logs (user_id, tool_name, transport, args_json, result_json) VALUES (?, ?, ?, ?, ?)",
            (
                user_id,
                tool_name,
                transport,
                json.dumps(args or {}, ensure_ascii=True),
                json.dumps(result or {}, ensure_ascii=True),
            ),
        )
        db.commit()

    try:
        _insert()
    except sqlite3.OperationalError:
        # Auto-migrate for demo environments (avoid requiring a manual DB migration step).
        try:
            db.execute(
                """
                CREATE TABLE IF NOT EXISTS mcp_audit_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    tool_name TEXT NOT NULL,
                    transport TEXT NOT NULL,
                    args_json TEXT NOT NULL,
                    result_json TEXT NOT NULL,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            db.commit()
            _insert()
        except Exception:
            # Fail open: never break tool calls due to logging failures.
            return


def _call_tool(tool_name: str, fn, args, ctx: Context | None = None):
    headers = _get_headers(ctx)
    with _db() as db:
        user = _require_user(db, headers)
        result = fn(db, user, args)
        transport = "http" if headers else "stdio"
        _audit_log_mcp_call(db, user["id"], tool_name, args, result, transport)
    if isinstance(result, dict) and "error" in result:
        raise ValueError(result["error"])
    return result


def _call_registry_tool(tool_name, args, ctx: Context | None = None):
    headers = _get_headers(ctx)
    with _db() as db:
        user = _require_user(db, headers)
        result = _tool_registry_call(db, user, tool_name, args)
        transport = "http" if headers else "stdio"
        _audit_log_mcp_call(db, user["id"], tool_name, args, result, transport)
    if isinstance(result, dict) and "error" in result:
        raise ValueError(result["error"])
    return result


_registry_tool_names = set()


def _schema_type_to_annotation(schema):
    if not isinstance(schema, dict):
        return object
    if "anyOf" in schema and isinstance(schema["anyOf"], list):
        for option in schema["anyOf"]:
            if isinstance(option, dict) and option.get("type") != "null":
                return _schema_type_to_annotation(option)
        return object
    schema_type = schema.get("type")
    if isinstance(schema_type, list):
        schema_type = next((t for t in schema_type if t != "null"), None)
    return {
        "integer": int,
        "number": float,
        "boolean": bool,
        "string": str,
        "object": dict,
        "array": list,
    }.get(schema_type, object)


def _build_registry_tool_fn(name, schema):
    def _registry_tool(ctx: Context, **kwargs):
        return _call_registry_tool(name, kwargs, ctx)

    _registry_tool.__name__ = f"registry_{name.replace('.', '_')}"
    _registry_tool.__doc__ = (schema or {}).get("description") or f"Registry tool {name}."

    input_schema = (schema or {}).get("inputSchema") or {}
    properties = input_schema.get("properties") or {}
    required = set(input_schema.get("required") or [])

    annotations = {"ctx": Context}
    parameters = [
        inspect.Parameter("ctx", inspect.Parameter.POSITIONAL_OR_KEYWORD, annotation=Context)
    ]

    for prop_name, prop_schema in properties.items():
        annotation = _schema_type_to_annotation(prop_schema)
        default = inspect.Parameter.empty if prop_name in required else None
        if prop_name not in required:
            annotation = annotation | type(None)
        annotations[prop_name] = annotation
        parameters.append(
            inspect.Parameter(
                prop_name,
                inspect.Parameter.KEYWORD_ONLY,
                default=default,
                annotation=annotation,
            )
        )

    _registry_tool.__annotations__ = annotations
    _registry_tool.__signature__ = inspect.Signature(parameters)
    return _registry_tool


def _register_registry_tool(mcp, name, description, schema):
    _registry_tool = _build_registry_tool_fn(name, schema or {})
    _safe_add_tool_with_alias(mcp, _registry_tool, name, description or _registry_tool.__doc__)
    _registry_tool_names.add(name)


def _restore_builtin_tool(mcp, name, fn_map):
    if name not in fn_map:
        return
    fn, description = fn_map[name]
    _safe_add_tool(mcp, fn, name, description)


def _sync_registry_tools(mcp, fn_map):
    try:
        with _db() as db:
            rows = db.execute(
                "SELECT name, description, config_json FROM mcp_tools ORDER BY updated_at DESC"
            ).fetchall()
    except sqlite3.OperationalError:
        return
    current = {}
    for row in rows:
        schema = _parse_schema_blob(row["config_json"]) if "config_json" in row.keys() else None
        current[row["name"]] = {"description": row["description"], "schema": schema}

    removed = _registry_tool_names - set(current.keys())
    for name in list(removed):
        _registry_tool_names.discard(name)
        _restore_builtin_tool(mcp, name, fn_map)

    for name, meta in current.items():
        _register_registry_tool(mcp, name, meta["description"], meta["schema"])


def _create_mcp():
    try:
        return FastMCP(
            "ThreatByte-MCP",
            stateless_http=True,
            json_response=True,
            on_duplicate_tools="replace",
        )
    except TypeError:
        try:
            return FastMCP("ThreatByte-MCP", stateless_http=True)
        except TypeError:
            return FastMCP("ThreatByte-MCP")


mcp = _create_mcp()


def _safe_add_tool(mcp_instance, fn, name, description):
    try:
        tool = Tool.from_function(fn, name=name, description=description)
        tool_manager = getattr(mcp_instance, "_tool_manager", None)
        if tool_manager is not None and hasattr(tool_manager, "_tools"):
            tool_manager._tools[tool.name] = tool
            return
    except Exception:
        pass

    mcp_instance.add_tool(fn, name=name, description=description)


def _safe_tool_alias_name(name: str) -> str | None:
    """
    Some MCP clients (e.g., Claude Desktop) validate tool names with a strict pattern:
    `^[a-zA-Z0-9_-]{1,64}$` and will reject names containing dots.

    Our web app uses dotted names like `cases.create`. To remain compatible with both,
    we expose an additional alias tool name (e.g., `cases_create`) when needed.
    """
    if _CLAUDE_TOOL_NAME_RE.match(name):
        return None
    alias = re.sub(r"[^a-zA-Z0-9_-]", "_", name)
    alias = re.sub(r"_+", "_", alias).strip("_")
    if not alias:
        return None
    if len(alias) > 64:
        alias = alias[:64]
    if _CLAUDE_TOOL_NAME_RE.match(alias):
        return alias
    return None


def _safe_add_tool_with_alias(mcp_instance, fn, name, description):
    alias = _safe_tool_alias_name(name)
    if _TOOL_NAME_MODE in ("claude", "strict"):
        # In strict mode, expose only a sanitized tool name to satisfy clients that reject dots.
        safe_name = alias or _safe_tool_alias_name(name) or name
        if not _CLAUDE_TOOL_NAME_RE.match(safe_name):
            safe_name = re.sub(r"[^a-zA-Z0-9_-]", "_", safe_name)[:64] or "tool"
        _safe_add_tool(mcp_instance, fn, safe_name, description)
        return

    # Default: keep original name AND add an alias (if needed) for stricter clients.
    _safe_add_tool(mcp_instance, fn, name, description)
    if alias and alias != name:
        _safe_add_tool(
            mcp_instance,
            fn,
            alias,
            f"{description}\n\n(Alias for `{name}`; provided for clients that do not accept dots in tool names.)",
        )


def _register_builtin(mcp_instance, name, fn, fn_map):
    description = BASE_TOOL_DESCRIPTIONS.get(name, fn.__doc__ or "")
    _safe_add_tool_with_alias(mcp_instance, fn, name, description)
    fn_map[name] = (fn, description)


_BUILTIN_FN_MAP = {}


def cases_create(title: str, severity: str = "low", status: str = "open", ctx: Context | None = None):
    return _call_tool(
        "cases.create",
        _tool_cases_create,
        {"title": title, "severity": severity, "status": status},
        ctx,
    )


def cases_list(owner_id: int | None = None, ctx: Context | None = None):
    args = {}
    if owner_id is not None:
        args["owner_id"] = owner_id
    return _call_tool("cases.list", _tool_cases_list, args, ctx)


def cases_list_all(ctx: Context | None = None):
    return _call_tool("cases.list_all", _tool_cases_list_all, {}, ctx)


def cases_get(case_id: int, ctx: Context | None = None):
    return _call_tool("cases.get", _tool_cases_get, {"case_id": case_id}, ctx)


def cases_rename(case_id: int, title: str, ctx: Context | None = None):
    return _call_tool("cases.rename", _tool_cases_rename, {"case_id": case_id, "title": title}, ctx)


def cases_set_status(case_id: int, status: str, ctx: Context | None = None):
    return _call_tool("cases.set_status", _tool_cases_set_status, {"case_id": case_id, "status": status}, ctx)


def cases_delete(case_id: int, ctx: Context | None = None):
    return _call_tool("cases.delete", _tool_cases_delete, {"case_id": case_id}, ctx)


def notes_create(case_id: int, content: str, ctx: Context | None = None):
    return _call_tool("notes.create", _tool_notes_create, {"case_id": case_id, "content": content}, ctx)


def notes_list(case_id: int, ctx: Context | None = None):
    return _call_tool("notes.list", _tool_notes_list, {"case_id": case_id}, ctx)


def notes_update(note_id: int, content: str, ctx: Context | None = None):
    return _call_tool("notes.update", _tool_notes_update, {"note_id": note_id, "content": content}, ctx)


def notes_delete(note_id: int, ctx: Context | None = None):
    return _call_tool("notes.delete", _tool_notes_delete, {"note_id": note_id}, ctx)


def files_upload(case_id: int, filename: str, content_base64: str, ctx: Context | None = None):
    return _call_tool(
        "files.upload",
        _tool_files_upload,
        {"case_id": case_id, "filename": filename, "content_base64": content_base64},
        ctx,
    )


def files_list(case_id: int, ctx: Context | None = None):
    return _call_tool("files.list", _tool_files_list, {"case_id": case_id}, ctx)


def files_get(file_id: int, ctx: Context | None = None):
    return _call_tool("files.get", _tool_files_get, {"file_id": file_id}, ctx)


def files_read_path(path: str, ctx: Context | None = None):
    return _call_tool("files.read_path", _tool_files_read_path, {"path": path}, ctx)


def indicators_search(q: str | None = None, ctx: Context | None = None):
    args = {}
    if q is not None:
        args["q"] = q
    return _call_tool("indicators.search", _tool_indicators_search, args, ctx)


def agent_summarize_case(case_id: int, ctx: Context | None = None):
    return _call_tool("agent.summarize_case", _tool_agent_summarize_case, {"case_id": case_id}, ctx)


def agent_run_task(case_id: int, task: str, ctx: Context | None = None):
    return _call_tool("agent.run_task", _tool_agent_run_task, {"case_id": case_id, "task": task}, ctx)


def tools_registry_list(ctx: Context | None = None):
    return _call_tool("tools.registry.list", _tool_registry_list, {}, ctx)


def tools_registry_register(schema_json: str, schema: dict | None = None, ctx: Context | None = None):
    result = _call_tool(
        "tools.registry.register",
        _tool_registry_register,
        {"schema_json": schema_json, "schema": schema},
        ctx,
    )
    _sync_registry_tools(mcp, _BUILTIN_FN_MAP)
    return result


def tools_registry_delete(name: str, ctx: Context | None = None):
    result = _call_tool("tools.registry.delete", _tool_registry_delete, {"name": name}, ctx)
    _sync_registry_tools(mcp, _BUILTIN_FN_MAP)
    return result


def tools_builtin_list(ctx: Context | None = None):
    return _call_tool("tools.builtin.list", lambda _db, _user, _args: {"ok": True, "tools": _base_tools_catalog()}, {}, ctx)


_register_builtin(mcp, "cases.create", cases_create, _BUILTIN_FN_MAP)
_register_builtin(mcp, "cases.list", cases_list, _BUILTIN_FN_MAP)
_register_builtin(mcp, "cases.list_all", cases_list_all, _BUILTIN_FN_MAP)
_register_builtin(mcp, "cases.get", cases_get, _BUILTIN_FN_MAP)
_register_builtin(mcp, "cases.rename", cases_rename, _BUILTIN_FN_MAP)
_register_builtin(mcp, "cases.set_status", cases_set_status, _BUILTIN_FN_MAP)
_register_builtin(mcp, "cases.delete", cases_delete, _BUILTIN_FN_MAP)
_register_builtin(mcp, "notes.create", notes_create, _BUILTIN_FN_MAP)
_register_builtin(mcp, "notes.list", notes_list, _BUILTIN_FN_MAP)
_register_builtin(mcp, "notes.update", notes_update, _BUILTIN_FN_MAP)
_register_builtin(mcp, "notes.delete", notes_delete, _BUILTIN_FN_MAP)
_register_builtin(mcp, "files.upload", files_upload, _BUILTIN_FN_MAP)
_register_builtin(mcp, "files.list", files_list, _BUILTIN_FN_MAP)
_register_builtin(mcp, "files.get", files_get, _BUILTIN_FN_MAP)
_register_builtin(mcp, "files.read_path", files_read_path, _BUILTIN_FN_MAP)
_register_builtin(mcp, "indicators.search", indicators_search, _BUILTIN_FN_MAP)
_register_builtin(mcp, "agent.summarize_case", agent_summarize_case, _BUILTIN_FN_MAP)
_register_builtin(mcp, "agent.run_task", agent_run_task, _BUILTIN_FN_MAP)
_register_builtin(mcp, "tools.registry.list", tools_registry_list, _BUILTIN_FN_MAP)
_register_builtin(mcp, "tools.registry.register", tools_registry_register, _BUILTIN_FN_MAP)
_register_builtin(mcp, "tools.registry.delete", tools_registry_delete, _BUILTIN_FN_MAP)
_register_builtin(mcp, "tools.builtin.list", tools_builtin_list, _BUILTIN_FN_MAP)

_sync_registry_tools(mcp, _BUILTIN_FN_MAP)

def _create_http_app(mcp_instance):
    try:
        return mcp_instance.streamable_http_app(path="/mcp")
    except TypeError:
        return mcp_instance.streamable_http_app()


app = _create_http_app(mcp)
