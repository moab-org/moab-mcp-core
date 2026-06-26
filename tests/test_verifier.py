import pytest

from moab_mcp_core.auth import KeycloakVerifier, Unauthorized, Forbidden
from moab_mcp_core.config import AuthConfig


def _cfg(allowed=("admin", "crew", "org", "user"), audience=None):
    authority = "https://auth.moab.tools/realms/moab"
    return AuthConfig(
        authority=authority,
        jwks_uri=f"{authority}/protocol/openid-connect/certs",
        issuer=authority,
        allowed_roles=frozenset(allowed),
        audience=audience,
        portal_resource="moab-portal",
    )


def test_verify_valid_token_returns_claims(jwk_client, make_token):
    v = KeycloakVerifier(_cfg(), jwk_client=jwk_client)
    claims = v.verify(make_token(roles=("org",)))
    assert claims.sub == "u1"
    assert "org" in claims.roles


def test_verify_expired_token_raises_unauthorized(jwk_client, make_token):
    v = KeycloakVerifier(_cfg(), jwk_client=jwk_client)
    with pytest.raises(Unauthorized):
        v.verify(make_token(exp_delta=-10))


def test_verify_wrong_issuer_raises_unauthorized(jwk_client, make_token):
    v = KeycloakVerifier(_cfg(), jwk_client=jwk_client)
    with pytest.raises(Unauthorized):
        v.verify(make_token(iss="https://evil/realms/x"))


def test_verify_audience_mismatch_raises_when_audience_required(jwk_client, make_token):
    v = KeycloakVerifier(_cfg(audience="seo-factors"), jwk_client=jwk_client)
    with pytest.raises(Unauthorized):
        v.verify(make_token(aud="other"))


def test_authenticate_missing_header_raises_unauthorized(jwk_client):
    v = KeycloakVerifier(_cfg(), jwk_client=jwk_client)
    with pytest.raises(Unauthorized):
        v.authenticate(None)


def test_authenticate_without_allowed_role_raises_forbidden(jwk_client, make_token):
    v = KeycloakVerifier(_cfg(allowed=("admin",)), jwk_client=jwk_client)
    with pytest.raises(Forbidden):
        v.authenticate("Bearer " + make_token(roles=("user",)))


def test_authenticate_with_allowed_role_returns_claims(jwk_client, make_token):
    v = KeycloakVerifier(_cfg(allowed=("user",)), jwk_client=jwk_client)
    claims = v.authenticate("Bearer " + make_token(roles=("user",)))
    assert "user" in claims.roles
