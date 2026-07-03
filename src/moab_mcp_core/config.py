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
    # Dynamic roles from the portal (all optional; without them the static
    # ALLOWED_ROLES behaviour of 0.2.0 is preserved). Defaults at the END to
    # keep positional construction backward-compatible.
    portal_base_url: str | None = None
    portal_tool_section: str | None = None
    portal_tool_slug: str | None = None
    portal_roles_ttl: float = 60.0


def load_auth_config(env: Mapping[str, str] | None = None) -> AuthConfig:
    env = env if env is not None else os.environ
    authority = env.get("KEYCLOAK_AUTHORITY", DEFAULT_AUTHORITY).rstrip("/")
    roles = frozenset(r.strip() for r in env.get("ALLOWED_ROLES", "").split(",") if r.strip())
    aud = env.get("MCP_AUDIENCE") or None
    portal_base_url = env.get("PORTAL_BASE_URL") or None
    if portal_base_url is not None:
        portal_base_url = portal_base_url.rstrip("/")
    return AuthConfig(
        authority=authority,
        jwks_uri=f"{authority}/protocol/openid-connect/certs",
        issuer=authority,
        allowed_roles=roles,
        audience=aud,
        portal_resource=env.get("PORTAL_RESOURCE", PORTAL_RESOURCE),
        portal_base_url=portal_base_url,
        portal_tool_section=env.get("PORTAL_TOOL_SECTION") or None,
        portal_tool_slug=env.get("PORTAL_TOOL_SLUG") or None,
        portal_roles_ttl=float(env.get("PORTAL_ROLES_TTL", "60")),
    )
