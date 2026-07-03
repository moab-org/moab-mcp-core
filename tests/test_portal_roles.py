import asyncio
import json
import logging

import httpx
import pytest

from moab_mcp_core.config import load_auth_config
from moab_mcp_core.portal_roles import PortalRolesProvider

FALLBACK = frozenset({"org", "user"})
URL_TAIL = "/api/tools/seo/cc-master/allowed-roles"


def _payload(roles):
    return {
        "section": "seo", "slug": "cc-master",
        "allowedRoles": roles, "updatedAt": "2026-07-03T00:00:00Z",
    }


class CountingTransport(httpx.BaseTransport, httpx.AsyncBaseTransport):
    """Works for both httpx.Client (prime) and httpx.AsyncClient (_refresh)."""

    def __init__(self, handler, gate: asyncio.Event | None = None):
        self.handler = handler
        self.gate = gate
        self.calls = 0

    def handle_request(self, request):
        self.calls += 1
        return self.handler(request)

    async def handle_async_request(self, request):
        self.calls += 1
        if self.gate is not None:
            await self.gate.wait()
        return self.handler(request)


def _provider(transport, fallback=FALLBACK, ttl=60.0, logger=None):
    return PortalRolesProvider(
        base_url="http://portal.moab-portal.svc:8080/",
        section="seo",
        slug="cc-master",
        fallback_roles=fallback,
        ttl_seconds=ttl,
        logger=logger,
        transport=transport,
    )


def _ok_transport(roles):
    def handler(request):
        assert request.url.path == URL_TAIL
        return httpx.Response(200, json=_payload(roles))
    return CountingTransport(handler)


# 1. Fallback before prime
def test_fallback_before_prime_and_without_event_loop():
    transport = _ok_transport(["crew"])
    p = _provider(transport)
    # No running loop -> no refresh scheduled, no exception, env fallback served.
    assert p.get_allowed_roles() == FALLBACK
    assert transport.calls == 0


# 2. Successful prime replaces env roles
def test_prime_replaces_fallback_roles():
    p = _provider(_ok_transport(["admin", "crew"]))
    p.prime()
    assert p.get_allowed_roles() == frozenset({"admin", "crew"})


# 3a. Within TTL the transport is not hit again
def test_within_ttl_no_refetch():
    transport = _ok_transport(["crew"])
    p = _provider(transport, ttl=60.0)
    p.prime()
    assert transport.calls == 1

    async def run():
        for _ in range(3):
            assert p.get_allowed_roles() == frozenset({"crew"})
            await asyncio.sleep(0)

    asyncio.run(run())
    assert transport.calls == 1


# 3b. After TTL expiry a background refresh updates the snapshot
def test_after_ttl_refresh_updates_roles():
    responses = [["crew"], ["crew", "org"]]

    def handler(request):
        return httpx.Response(200, json=_payload(responses.pop(0)))

    transport = CountingTransport(handler)
    p = _provider(transport)
    p.prime()
    assert p.get_allowed_roles() == frozenset({"crew"})
    p._fetched_at = float("-inf")  # simulate TTL expiry deterministically

    async def run():
        # This call serves the stale snapshot and schedules the refresh.
        assert p.get_allowed_roles() == frozenset({"crew"})
        while p._refreshing:
            await asyncio.sleep(0)
        assert p.get_allowed_roles() == frozenset({"crew", "org"})

    asyncio.run(run())
    assert transport.calls == 2


# 4. Stale-while-revalidate: hung refresh never blocks callers
def test_stale_snapshot_served_while_refresh_hangs():
    gate = asyncio.Event()
    transport = CountingTransport(
        lambda request: httpx.Response(200, json=_payload(["crew"])), gate=gate,
    )
    p = _provider(transport)
    p._roles = frozenset({"old"})  # pretend we primed earlier; TTL long expired

    async def run():
        assert p.get_allowed_roles() == frozenset({"old"})  # schedules refresh
        await asyncio.sleep(0)  # refresh task is now awaiting the gate
        # Old snapshot keeps being served, synchronously, without waiting.
        assert p.get_allowed_roles() == frozenset({"old"})
        assert p._refreshing is True
        gate.set()
        while p._refreshing:
            await asyncio.sleep(0)
        assert p.get_allowed_roles() == frozenset({"crew"})

    asyncio.run(run())
    assert transport.calls == 1  # _refreshing flag prevented duplicate refreshes


# 5. Network error -> last-known-good, warning, no exception
def test_network_error_keeps_last_known_good(caplog):
    calls = {"n": 0}

    def handler(request):
        calls["n"] += 1
        if calls["n"] == 1:
            return httpx.Response(200, json=_payload(["crew"]))
        raise httpx.ConnectError("portal down")

    p = _provider(CountingTransport(handler), logger=logging.getLogger("t5"))
    p.prime()
    p._fetched_at = float("-inf")

    async def run():
        p.get_allowed_roles()
        while p._refreshing:
            await asyncio.sleep(0)

    with caplog.at_level(logging.WARNING, logger="t5"):
        asyncio.run(run())
    assert p.get_allowed_roles() == frozenset({"crew"})
    assert any("refresh failed" in r.message for r in caplog.records)


# 6. 404 -> last-known-good kept, _fetched_at advanced (no re-fetch until TTL)
def test_404_keeps_roles_and_advances_fetched_at():
    calls = {"n": 0}

    def handler(request):
        calls["n"] += 1
        if calls["n"] == 1:
            return httpx.Response(200, json=_payload(["crew"]))
        return httpx.Response(404)

    transport = CountingTransport(handler)
    p = _provider(transport)
    p.prime()
    p._fetched_at = float("-inf")

    async def run():
        p.get_allowed_roles()
        while p._refreshing:
            await asyncio.sleep(0)
        # 404 advanced _fetched_at: further calls within TTL must not re-fetch.
        for _ in range(3):
            assert p.get_allowed_roles() == frozenset({"crew"})
            await asyncio.sleep(0)

    asyncio.run(run())
    assert transport.calls == 2


# 7. Empty allowedRoles is valid -> frozenset()
def test_empty_allowed_roles_accepted():
    p = _provider(_ok_transport([]))
    p.prime()
    assert p.get_allowed_roles() == frozenset()


# 8a. Broken JSON -> last-known-good
def test_broken_json_keeps_last_known_good():
    p = _provider(CountingTransport(
        lambda request: httpx.Response(200, content=b"{not json"),
    ))
    p._roles = frozenset({"crew"})
    p._fetched_at = float("-inf")

    async def run():
        p.get_allowed_roles()
        while p._refreshing:
            await asyncio.sleep(0)

    asyncio.run(run())
    assert p.get_allowed_roles() == frozenset({"crew"})


# 8b. Wrong shape (allowedRoles not a list) -> last-known-good; junk entries dropped
def test_wrong_shape_keeps_last_known_good_and_junk_entries_dropped():
    p = _provider(CountingTransport(
        lambda request: httpx.Response(200, json={"allowedRoles": "crew"}),
    ))
    p._roles = frozenset({"org"})
    p._fetched_at = float("-inf")

    async def run():
        p.get_allowed_roles()
        while p._refreshing:
            await asyncio.sleep(0)

    asyncio.run(run())
    assert p.get_allowed_roles() == frozenset({"org"})

    # Non-strings/empties are dropped, extra fields ignored, valid entries kept.
    p2 = _provider(_ok_transport(["crew", "", 42, None, "org"]))
    p2.prime()
    assert p2.get_allowed_roles() == frozenset({"crew", "org"})


# 9. Role set change is logged
def test_role_change_is_logged(caplog):
    p = _provider(_ok_transport(["crew"]), logger=logging.getLogger("t9"))
    with caplog.at_level(logging.INFO, logger="t9"):
        p.prime()
    assert any("portal roles changed" in r.message for r in caplog.records)


# 11. load_auth_config with/without the new env vars
def test_load_auth_config_with_portal_env():
    cfg = load_auth_config({
        "ALLOWED_ROLES": "org,user",
        "PORTAL_BASE_URL": "http://portal.moab-portal.svc:8080/",
        "PORTAL_TOOL_SECTION": "seo",
        "PORTAL_TOOL_SLUG": "cc-master",
        "PORTAL_ROLES_TTL": "30.5",
    })
    assert cfg.portal_base_url == "http://portal.moab-portal.svc:8080"
    assert cfg.portal_tool_section == "seo"
    assert cfg.portal_tool_slug == "cc-master"
    assert cfg.portal_roles_ttl == 30.5
    assert cfg.allowed_roles == frozenset({"org", "user"})


def test_load_auth_config_without_portal_env_defaults():
    cfg = load_auth_config({"ALLOWED_ROLES": "org"})
    assert cfg.portal_base_url is None
    assert cfg.portal_tool_section is None
    assert cfg.portal_tool_slug is None
    assert cfg.portal_roles_ttl == 60.0
