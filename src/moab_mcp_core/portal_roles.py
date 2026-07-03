"""Dynamic tool roles from the portal (Tool.AllowedRoles).

Stale-while-revalidate provider around the anonymous portal endpoint
``GET {base}/api/tools/{section}/{slug}/allowed-roles``.

Constraints this design serves:
- ``KeycloakVerifier.authenticate()`` is synchronous but runs inside the
  uvicorn event loop, so blocking HTTP there is forbidden.
- ``get_allowed_roles()`` therefore never waits for the network: it returns
  the last-known-good snapshot (or the env fallback) and, when the TTL has
  expired, schedules a background async refresh on the running loop.
- ``prime()`` is a synchronous first fetch meant to be called BEFORE the
  event loop starts (the verifier is constructed before ``uvicorn.run``).
- 404 / network errors / bad payloads NEVER erase the last-known-good set.
"""

from __future__ import annotations

import asyncio
import logging
import time

import httpx


class PortalRolesProvider:
    def __init__(
        self,
        base_url: str,
        section: str,
        slug: str,
        fallback_roles: frozenset[str],
        ttl_seconds: float = 60.0,
        timeout_seconds: float = 2.0,
        logger: logging.Logger | None = None,
        transport: httpx.BaseTransport | None = None,
    ):
        self._url = f"{base_url.rstrip('/')}/api/tools/{section}/{slug}/allowed-roles"
        self._fallback = fallback_roles
        self._ttl = ttl_seconds
        self._timeout = timeout_seconds
        self._logger = logger if logger is not None else logging.getLogger(__name__)
        self._transport = transport
        self._roles: frozenset[str] | None = None  # last-known-good; None => fallback
        self._fetched_at: float = float("-inf")
        self._refreshing: bool = False
        self._async_client: httpx.AsyncClient | None = None

    def get_allowed_roles(self) -> frozenset[str]:
        """Sync, non-blocking: return the current snapshot; maybe schedule a refresh."""
        snapshot = self._roles if self._roles is not None else self._fallback
        if not self._refreshing and (time.monotonic() - self._fetched_at) > self._ttl:
            try:
                loop = asyncio.get_running_loop()
            except RuntimeError:
                # No running event loop (e.g. called from sync-only code/tests):
                # skip the refresh, just serve the snapshot.
                return snapshot
            # Check-and-set of _refreshing happens synchronously (no await in
            # between) and everything runs on the single uvicorn event loop,
            # so an asyncio.Lock is not needed to prevent duplicate refreshes.
            self._refreshing = True
            loop.create_task(self._refresh())
        return snapshot

    def prime(self) -> None:
        """Synchronous first fetch; call before the event loop starts."""
        try:
            with httpx.Client(transport=self._transport, timeout=self._timeout) as client:
                response = client.get(self._url)
            self._apply_response(response)
        except Exception as e:  # noqa: BLE001 - startup must survive portal being down
            self._logger.warning(
                "portal roles prime failed (%s); using fallback roles %s",
                e, sorted(self._fallback),
            )

    async def _refresh(self) -> None:
        try:
            if self._async_client is None:
                self._async_client = httpx.AsyncClient(
                    transport=self._transport, timeout=self._timeout,
                )
            response = await self._async_client.get(self._url)
            self._apply_response(response)
        except Exception as e:  # noqa: BLE001 - never let a refresh break auth
            self._logger.warning(
                "portal roles refresh failed (%s); keeping %s",
                e, sorted(self._current()),
            )
            self._fetched_at = time.monotonic()
        finally:
            self._refreshing = False

    def _current(self) -> frozenset[str]:
        return self._roles if self._roles is not None else self._fallback

    def _apply_response(self, response: httpx.Response) -> None:
        if response.status_code == 404:
            self._logger.warning(
                "tool not registered in portal (404), keeping %s",
                sorted(self._current()),
            )
            self._fetched_at = time.monotonic()
            return
        response.raise_for_status()
        data = response.json()
        if not isinstance(data, dict) or not isinstance(data.get("allowedRoles"), list):
            raise ValueError(f"unexpected allowed-roles payload shape: {data!r}")
        # Drop non-strings/empties; extra fields are ignored. An EMPTY list is
        # valid and means "admin only" (admin bypass lives in the verifier).
        new_roles = frozenset(
            r for r in data["allowedRoles"] if isinstance(r, str) and r.strip()
        )
        old = self._current()
        if new_roles != old:
            self._logger.info(
                "portal roles changed: %s -> %s", sorted(old), sorted(new_roles),
            )
        self._roles = new_roles
        self._fetched_at = time.monotonic()
