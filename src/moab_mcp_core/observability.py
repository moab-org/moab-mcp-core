"""Structured logging + per-tool-call instrumentation for moab portal MCP servers.

Implements the moab logging contract (MOA-A-9): one JSON object per line to stdout
with the standard fields (ts/level/msg/service.name/deployment.environment/source)
plus domain fields (user_id, role, tool, status, duration_ms, trace_id) and, on
errors, exception.* .

The ASGI wrapper :func:`with_tool_call_logging` sits OUTSIDE a server's existing
``handle_mcp`` (at the ``Mount`` point), so servers adopt it with a one-line change
and we never touch their (divergent) transport/session internals. It emits exactly
ONE ``info`` event per authenticated MCP ``tools/call`` (and ``error`` on failure),
which is what the per-MCP Grafana/Loki dashboards consume.
"""

from __future__ import annotations

import datetime
import json
import logging
import os
import sys
import time
from typing import Awaitable, Callable

from .auth import AuthError, KeycloakVerifier

# Domain fields merged from logging `extra=` into the JSON record (snake_case, per contract §2).
_DOMAIN = ("trace_id", "span_id", "user_id", "role", "tool", "status", "duration_ms")

# Role precedence for the single `role` label (most privileged wins).
_ROLE_ORDER = ("admin", "crew", "org", "user")

# Cap on response-body bytes buffered for isError detection (low-traffic; just guard memory).
_RESP_PEEK_MAX = 65536


class ContractFormatter(logging.Formatter):
    """Flat one-line JSON per the moab logging contract (§2/§9)."""

    def __init__(self, service: str, version: str, env: str):
        super().__init__()
        self.service, self.version, self.env = service, version, env

    def format(self, r: logging.LogRecord) -> str:
        o = {
            "ts": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.")
            + f"{int(r.msecs):03d}Z",
            "level": r.levelname.lower(),
            "msg": r.getMessage(),
            "service.name": self.service,
            "service.version": self.version,
            "deployment.environment": self.env,
            "source": r.name,
        }
        for k in _DOMAIN:
            v = getattr(r, k, None)
            if v is not None:
                o[k] = v
        if r.exc_info:
            et, ev, tb = r.exc_info
            import traceback

            o["exception.type"] = getattr(et, "__name__", str(et))
            o["exception.message"] = str(ev)
            o["exception.stacktrace"] = "".join(traceback.format_exception(et, ev, tb))[:8192]
        return json.dumps(o, ensure_ascii=False)


class _StdoutHandler(logging.StreamHandler):
    """Always write to the *current* sys.stdout (so pytest capsys works)."""

    def emit(self, record: logging.LogRecord) -> None:
        self.stream = sys.stdout
        super().emit(record)


def setup_logging(service: str, version: str | None = None, env: str | None = None) -> logging.Logger:
    """Configure and return the contract logger for ``service``.

    ``version`` falls back to env ``SERVICE_VERSION``; ``env`` to
    ``DEPLOYMENT_ENVIRONMENT`` (default ``prod``). Also quiets uvicorn access
    noise (plain-text, non-contract) — structured tool-call events replace it.
    """
    version = version if version is not None else os.environ.get("SERVICE_VERSION", "")
    env = env if env is not None else os.environ.get("DEPLOYMENT_ENVIRONMENT", "prod")
    log = logging.getLogger(service)
    log.handlers.clear()
    log.setLevel(logging.INFO)
    h = _StdoutHandler()
    h.setFormatter(ContractFormatter(service, version, env))
    log.addHandler(h)
    log.propagate = False
    # Silence uvicorn's plain-text access log (bot scanners spam 401s); keep error log.
    logging.getLogger("uvicorn.access").disabled = True
    return log


def _primary_role(roles) -> str | None:
    for r in _ROLE_ORDER:
        if r in roles:
            return r
    return next(iter(roles), None) if roles else None


def _header(scope, name: bytes) -> str | None:
    for k, v in scope.get("headers", []):
        if k == name:
            return v.decode("latin-1")
    return None


def _trace_id(scope) -> str | None:
    tp = _header(scope, b"traceparent")
    if tp:
        parts = tp.split("-")
        if len(parts) >= 2 and parts[1]:
            return parts[1]
    return None


def _parse_tool(body: bytes) -> str | None:
    """Return the tool name if the JSON-RPC body is a ``tools/call``, else None."""
    if not body:
        return None
    try:
        msg = json.loads(body)
    except (ValueError, UnicodeDecodeError):
        return None
    items = msg if isinstance(msg, list) else [msg]
    for it in items:
        if isinstance(it, dict) and it.get("method") == "tools/call":
            params = it.get("params") or {}
            name = params.get("name")
            if isinstance(name, str):
                return name
    return None


def _body_is_error(body: bytes) -> bool:
    """Best-effort: True if a JSON-RPC tools/call result reports a tool-level error."""
    if not body:
        return False
    try:
        msg = json.loads(body)
    except (ValueError, UnicodeDecodeError):
        return False
    items = msg if isinstance(msg, list) else [msg]
    for it in items:
        if not isinstance(it, dict):
            continue
        if "error" in it:  # JSON-RPC protocol error
            return True
        res = it.get("result")
        if isinstance(res, dict) and res.get("isError") is True:  # MCP tool-level error
            return True
    return False


async def _buffer_request_body(receive: Callable[[], Awaitable[dict]]):
    """Drain the ASGI request body and return ``(body, replay_receive)``."""
    chunks: list[bytes] = []
    more = True
    events: list[dict] = []
    while more:
        ev = await receive()
        events.append(ev)
        if ev["type"] == "http.request":
            chunks.append(ev.get("body", b""))
            more = ev.get("more_body", False)
        else:  # http.disconnect or other
            more = False
    body = b"".join(chunks)
    sent = False

    async def replay():
        nonlocal sent
        if not sent:
            sent = True
            return {"type": "http.request", "body": body, "more_body": False}
        # After replaying the body, defer to the original transport for further events.
        return await receive()

    return body, replay


def with_tool_call_logging(
    handle_mcp: Callable,
    *,
    service: str,
    verifier: KeycloakVerifier,
    logger: logging.Logger,
) -> Callable:
    """Wrap an ASGI ``handle_mcp`` to emit one contract log per authenticated ``tools/call``.

    Non-HTTP scopes, non-POST requests and non-``tools/call`` bodies pass straight
    through with zero overhead beyond a cheap method check. Unauthenticated calls
    are NOT logged (the inner handler returns 401; they are bot/anon noise).
    """

    async def wrapped(scope, receive, send):
        if scope.get("type") != "http" or scope.get("method") != "POST":
            await handle_mcp(scope, receive, send)
            return

        body, receive = await _buffer_request_body(receive)
        tool = _parse_tool(body)
        if tool is None:
            await handle_mcp(scope, receive, send)
            return

        # Identify the caller (JWKS cached; verify is sub-ms). Failure → inner 401, skip logging.
        claims = None
        try:
            claims = verifier.authenticate(_header(scope, b"authorization"))
        except AuthError:
            claims = None
        except Exception:  # never let logging-path errors break the request
            claims = None

        http_status = {"code": None}
        resp_chunks: list[bytes] = []
        resp_len = 0

        async def wsend(msg):
            nonlocal resp_len
            t = msg.get("type")
            if t == "http.response.start":
                http_status["code"] = msg.get("status")
            elif t == "http.response.body" and resp_len < _RESP_PEEK_MAX:
                b = msg.get("body", b"")
                if b:
                    resp_chunks.append(b)
                    resp_len += len(b)
            await send(msg)

        start = time.monotonic()
        try:
            await handle_mcp(scope, receive, wsend)
        finally:
            if claims is not None:  # only log authenticated tool calls
                duration_ms = int((time.monotonic() - start) * 1000)
                code = http_status["code"]
                is_err = (code is not None and code >= 400) or _body_is_error(b"".join(resp_chunks))
                extra = {
                    "user_id": claims.sub,
                    "role": _primary_role(claims.roles),
                    "tool": tool,
                    "status": "error" if is_err else "ok",
                    "duration_ms": duration_ms,
                }
                tid = _trace_id(scope)
                if tid:
                    extra["trace_id"] = tid
                if is_err:
                    logger.error(f"tool call failed: {tool}", extra=extra)
                else:
                    logger.info(f"tool call: {tool}", extra=extra)

    return wrapped
