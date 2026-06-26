from __future__ import annotations

from dataclasses import dataclass

import jwt
from jwt import PyJWKClient
from jwt.exceptions import InvalidTokenError

from .config import AuthConfig


class AuthError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


class Unauthorized(AuthError):
    def __init__(self, message: str = "Unauthorized"):
        super().__init__(401, message)


class Forbidden(AuthError):
    def __init__(self, message: str = "Forbidden: missing required role"):
        super().__init__(403, message)


@dataclass(frozen=True)
class TokenClaims:
    sub: str
    email: str | None
    roles: frozenset[str]
    raw: dict


def extract_roles(payload: dict, portal_resource: str) -> frozenset[str]:
    roles: set[str] = set()
    res = (payload.get("resource_access") or {}).get(portal_resource) or {}
    roles.update(res.get("roles") or [])
    realm = payload.get("realm_access") or {}
    roles.update(realm.get("roles") or [])
    return frozenset(roles)


def has_allowed_role(roles: frozenset[str], allowed: frozenset[str]) -> bool:
    return bool(roles & allowed)


class KeycloakVerifier:
    def __init__(self, cfg: AuthConfig, jwk_client=None):
        self._cfg = cfg
        self._jwks = jwk_client if jwk_client is not None else PyJWKClient(cfg.jwks_uri)

    def verify(self, token: str) -> TokenClaims:
        try:
            signing_key = self._jwks.get_signing_key_from_jwt(token)
            options = {
                "require": ["exp", "iat"],
                "verify_aud": self._cfg.audience is not None,
            }
            payload = jwt.decode(
                token,
                signing_key.key,
                algorithms=["RS256"],
                issuer=self._cfg.issuer,
                audience=self._cfg.audience,
                options=options,
            )
        except InvalidTokenError as e:
            raise Unauthorized(f"Invalid token: {e}") from e
        roles = extract_roles(payload, self._cfg.portal_resource)
        return TokenClaims(
            sub=payload.get("sub", ""),
            email=payload.get("email"),
            roles=roles,
            raw=payload,
        )

    def authenticate(self, authorization_header: str | None) -> TokenClaims:
        if not authorization_header or not authorization_header.startswith("Bearer "):
            raise Unauthorized("Missing bearer token")
        token = authorization_header[len("Bearer "):].strip()
        claims = self.verify(token)
        if not has_allowed_role(claims.roles, self._cfg.allowed_roles):
            raise Forbidden()
        return claims
