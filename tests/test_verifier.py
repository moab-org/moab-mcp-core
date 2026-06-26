import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

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


# --- Negative security cases (auth-boundary) ---

def test_verify_token_signed_with_wrong_key_raises_unauthorized(jwk_client):
    # Token signed by a DIFFERENT key; jwk_client returns the FIRST public key,
    # so signature verification must fail.
    other_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = int(time.time())
    payload = {
        "sub": "u1", "email": "u@x.io",
        "iss": "https://auth.moab.tools/realms/moab",
        "iat": now, "exp": now + 3600,
        "resource_access": {"moab-portal": {"roles": ["org"]}},
    }
    token = jwt.encode(payload, other_priv, algorithm="RS256", headers={"kid": "test"})
    v = KeycloakVerifier(_cfg(), jwk_client=jwk_client)
    with pytest.raises(Unauthorized):
        v.verify(token)


def test_verify_alg_none_raises_unauthorized(jwk_client):
    # Unsigned "alg:none" token must be rejected (verifier restricts to RS256).
    now = int(time.time())
    payload = {
        "sub": "u1", "iss": "https://auth.moab.tools/realms/moab",
        "iat": now, "exp": now + 3600,
        "resource_access": {"moab-portal": {"roles": ["org"]}},
    }
    token = jwt.encode(payload, None, algorithm="none")
    v = KeycloakVerifier(_cfg(), jwk_client=jwk_client)
    with pytest.raises(Unauthorized):
        v.verify(token)


def test_verify_tampered_signature_raises_unauthorized(jwk_client, make_token):
    # Valid token with its signature segment corrupted must be rejected.
    token = make_token(roles=("org",))
    header, body, sig = token.split(".")
    bad_sig = sig[:-1] + ("a" if sig[-1] != "a" else "b")
    tampered = ".".join([header, body, bad_sig])
    v = KeycloakVerifier(_cfg(), jwk_client=jwk_client)
    with pytest.raises(Unauthorized):
        v.verify(tampered)


def test_verify_audience_required_but_missing_raises_unauthorized(jwk_client, make_token):
    # Verifier requires an audience but the token has no `aud` claim.
    v = KeycloakVerifier(_cfg(audience="seo-factors"), jwk_client=jwk_client)
    with pytest.raises(Unauthorized):
        v.verify(make_token(aud=None))
