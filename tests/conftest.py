import time
from types import SimpleNamespace

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa


@pytest.fixture(scope="session")
def rsa_keys():
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return priv, priv.public_key()


@pytest.fixture
def jwk_client(rsa_keys):
    _priv, pub = rsa_keys

    class _StubJWKClient:
        def get_signing_key_from_jwt(self, _token):
            return SimpleNamespace(key=pub)

    return _StubJWKClient()


@pytest.fixture
def make_token(rsa_keys):
    priv, _pub = rsa_keys

    def _make(*, sub="u1", email="u@x.io", roles=("org",), iss="https://auth.moab.tools/realms/moab",
              aud=None, exp_delta=3600):
        now = int(time.time())
        payload = {
            "sub": sub, "email": email, "iss": iss,
            "iat": now, "exp": now + exp_delta,
            "resource_access": {"moab-portal": {"roles": list(roles)}},
        }
        if aud is not None:
            payload["aud"] = aud
        return jwt.encode(payload, priv, algorithm="RS256", headers={"kid": "test"})

    return _make
