import asyncio
import json
import logging

from moab_mcp_core.auth import KeycloakVerifier
from moab_mcp_core.config import AuthConfig
from moab_mcp_core.observability import (
    _body_is_error,
    _parse_tool,
    with_tool_call_logging,
)


def _cfg(allowed=("user",)):
    a = "https://auth.moab.tools/realms/moab"
    return AuthConfig(a, f"{a}/protocol/openid-connect/certs", a, frozenset(allowed), None, "moab-portal")


class _ListHandler(logging.Handler):
    def __init__(self):
        super().__init__()
        self.records = []

    def emit(self, r):
        self.records.append(r)


def _logger(name):
    log = logging.getLogger(name)
    log.handlers.clear()
    h = _ListHandler()
    log.addHandler(h)
    log.setLevel(logging.INFO)
    log.propagate = False
    return log, h


def _make_inner(status=200, body=b'{"jsonrpc":"2.0","id":1,"result":{"isError":false}}'):
    async def inner(scope, receive, send):
        await receive()  # consume (replayed) body
        await send({"type": "http.response.start", "status": status, "headers": []})
        await send({"type": "http.response.body", "body": body})

    return inner


def _scope(method="POST", token=None):
    headers = []
    if token is not None:
        headers.append((b"authorization", b"Bearer " + token.encode()))
    return {"type": "http", "method": method, "headers": headers}


async def _drive(wrapped, scope, body=b""):
    sent = []
    delivered = {"n": 0}

    async def receive():
        delivered["n"] += 1
        return {"type": "http.request", "body": body, "more_body": False}

    async def send(m):
        sent.append(m)

    await wrapped(scope, receive, send)
    return sent


# ── unit: parsers ──

def test_parse_tool_extracts_name_from_tools_call():
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                       "params": {"name": "overview", "arguments": {}}}).encode()
    assert _parse_tool(body) == "overview"


def test_parse_tool_none_for_other_methods():
    assert _parse_tool(json.dumps({"method": "tools/list"}).encode()) is None
    assert _parse_tool(b"not json") is None
    assert _parse_tool(b"") is None


def test_body_is_error_detects_tool_and_protocol_errors():
    assert _body_is_error(b'{"result":{"isError":true}}') is True
    assert _body_is_error(b'{"error":{"code":-32601}}') is True
    assert _body_is_error(b'{"result":{"isError":false}}') is False
    assert _body_is_error(b"garbage") is False


# ── wrapper behaviour ──

def test_logs_one_info_event_for_authenticated_tool_call(jwk_client, make_token):
    v = KeycloakVerifier(_cfg(), jwk_client=jwk_client)
    log, h = _logger("obs-ok")
    wrapped = with_tool_call_logging(_make_inner(), service="seo-factors", verifier=v, logger=log)
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                       "params": {"name": "overview"}}).encode()
    sent = asyncio.run(_drive(wrapped, _scope(token=make_token(sub="u9", roles=("user",))), body))

    assert len(h.records) == 1
    rec = h.records[0]
    assert rec.levelname == "INFO"
    assert rec.tool == "overview"
    assert rec.user_id == "u9"
    assert rec.role == "user"
    assert rec.status == "ok"
    assert isinstance(rec.duration_ms, int)
    # response still forwarded downstream
    assert any(m["type"] == "http.response.start" for m in sent)


def test_tool_level_error_logs_at_error(jwk_client, make_token):
    v = KeycloakVerifier(_cfg(), jwk_client=jwk_client)
    log, h = _logger("obs-err")
    inner = _make_inner(body=b'{"jsonrpc":"2.0","id":1,"result":{"isError":true}}')
    wrapped = with_tool_call_logging(inner, service="seo-factors", verifier=v, logger=log)
    body = json.dumps({"method": "tools/call", "params": {"name": "get_factor"}}).encode()
    asyncio.run(_drive(wrapped, _scope(token=make_token(roles=("user",))), body))

    assert len(h.records) == 1
    assert h.records[0].levelname == "ERROR"
    assert h.records[0].status == "error"


def test_unauthenticated_tool_call_not_logged(jwk_client):
    v = KeycloakVerifier(_cfg(), jwk_client=jwk_client)
    log, h = _logger("obs-anon")
    wrapped = with_tool_call_logging(_make_inner(), service="seo-factors", verifier=v, logger=log)
    body = json.dumps({"method": "tools/call", "params": {"name": "overview"}}).encode()
    sent = asyncio.run(_drive(wrapped, _scope(token=None), body))  # no auth header

    assert h.records == []  # bot/anon noise is not counted
    assert any(m["type"] == "http.response.start" for m in sent)  # but request still served


def test_non_tool_requests_pass_through_without_logging(jwk_client, make_token):
    v = KeycloakVerifier(_cfg(), jwk_client=jwk_client)
    log, h = _logger("obs-passthrough")
    wrapped = with_tool_call_logging(_make_inner(), service="seo-factors", verifier=v, logger=log)
    # GET (e.g. SSE/health) → straight passthrough
    asyncio.run(_drive(wrapped, _scope(method="GET", token=make_token(roles=("user",)))))
    # POST tools/list → not a tools/call
    body = json.dumps({"method": "tools/list"}).encode()
    asyncio.run(_drive(wrapped, _scope(token=make_token(roles=("user",))), body))
    assert h.records == []
