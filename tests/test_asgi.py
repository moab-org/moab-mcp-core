from starlette.requests import Request
from starlette.responses import JSONResponse

from moab_mcp_core.asgi import authenticate_request
from moab_mcp_core.auth import KeycloakVerifier
from moab_mcp_core.config import AuthConfig

META = "https://seo-factors.moab.tools/.well-known/oauth-protected-resource"


def _cfg(allowed=("user",)):
    a = "https://auth.moab.tools/realms/moab"
    return AuthConfig(a, f"{a}/protocol/openid-connect/certs", a, frozenset(allowed), None, "moab-portal")


def _request(headers: dict) -> Request:
    raw = [(k.lower().encode(), v.encode()) for k, v in headers.items()]
    return Request({"type": "http", "method": "POST", "headers": raw})


def test_authenticate_request_ok_returns_claims(jwk_client, make_token):
    v = KeycloakVerifier(_cfg(), jwk_client=jwk_client)
    res = authenticate_request(v, _request({"authorization": "Bearer " + make_token(roles=("user",))}), META)
    assert not isinstance(res, JSONResponse)
    assert "user" in res.roles


def test_authenticate_request_missing_token_returns_401_with_www_authenticate(jwk_client):
    v = KeycloakVerifier(_cfg(), jwk_client=jwk_client)
    res = authenticate_request(v, _request({}), META)
    assert isinstance(res, JSONResponse)
    assert res.status_code == 401
    assert META in res.headers["www-authenticate"]


def test_authenticate_request_wrong_role_returns_403(jwk_client, make_token):
    v = KeycloakVerifier(_cfg(allowed=("admin",)), jwk_client=jwk_client)
    res = authenticate_request(v, _request({"authorization": "Bearer " + make_token(roles=("user",))}), META)
    assert isinstance(res, JSONResponse)
    assert res.status_code == 403
