from moab_mcp_core.auth import extract_roles, has_allowed_role

def test_extract_roles_from_portal_resource_access():
    payload = {"resource_access": {"moab-portal": {"roles": ["crew", "org"]}}}
    assert extract_roles(payload, "moab-portal") == frozenset({"crew", "org"})

def test_extract_roles_unions_realm_access():
    payload = {
        "resource_access": {"moab-portal": {"roles": ["org"]}},
        "realm_access": {"roles": ["user"]},
    }
    assert extract_roles(payload, "moab-portal") == frozenset({"org", "user"})

def test_extract_roles_empty_when_absent():
    assert extract_roles({}, "moab-portal") == frozenset()

def test_has_allowed_role_true_on_intersection():
    assert has_allowed_role(frozenset({"org"}), frozenset({"admin", "crew", "org", "user"})) is True

def test_has_allowed_role_false_when_disjoint():
    assert has_allowed_role(frozenset({"guest"}), frozenset({"admin", "crew", "org"})) is False
