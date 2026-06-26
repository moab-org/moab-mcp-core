from __future__ import annotations

from dataclasses import dataclass


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
