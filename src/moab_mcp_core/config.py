import os
from dataclasses import dataclass
from typing import Mapping

DEFAULT_AUTHORITY = "https://auth.moab.tools/realms/moab"
PORTAL_RESOURCE = "moab-portal"


@dataclass(frozen=True)
class AuthConfig:
    authority: str
    jwks_uri: str
    issuer: str
    allowed_roles: frozenset[str]
    audience: str | None
    portal_resource: str = PORTAL_RESOURCE


def load_auth_config(env: Mapping[str, str] | None = None) -> AuthConfig:
    env = env if env is not None else os.environ
    authority = env.get("KEYCLOAK_AUTHORITY", DEFAULT_AUTHORITY).rstrip("/")
    roles = frozenset(r.strip() for r in env.get("ALLOWED_ROLES", "").split(",") if r.strip())
    aud = env.get("MCP_AUDIENCE") or None
    return AuthConfig(
        authority=authority,
        jwks_uri=f"{authority}/protocol/openid-connect/certs",
        issuer=authority,
        allowed_roles=roles,
        audience=aud,
        portal_resource=env.get("PORTAL_RESOURCE", PORTAL_RESOURCE),
    )
