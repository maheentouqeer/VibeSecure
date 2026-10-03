import time

import jwt
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from backend import auth, db, main
from backend.db import Base, engine

_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_PEM = _KEY.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())


def _auth():
    token = jwt.encode(
        {"sub": "api-key-user", "email": "api-key@example.test", "aud": "authenticated", "exp": int(time.time()) + 300},
        _PEM,
        algorithm="RS256",
    )
    return {"Authorization": "Bearer " + token}


def test_api_key_create_list_revoke(monkeypatch):
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    monkeypatch.setattr(
        auth,
        "_get_jwks_client",
        lambda: type("JWKS", (), {
            "get_signing_key_from_jwt": lambda self, token: type("Key", (), {"key": _KEY.public_key()})()
        })(),
    )

    client = TestClient(main.app)
    created = client.post("/me/api-keys", json={"label": "VS Code"}, headers=_auth())
    assert created.status_code == 201, created.text
    key = created.json()
    assert key["key"].startswith("vsk_")

    listed = client.get("/me/api-keys", headers=_auth())
    assert listed.status_code == 200
    assert len(listed.json()) == 1
    assert "key" not in listed.json()[0]

    assert client.delete("/me/api-keys/" + key["id"], headers=_auth()).status_code == 204
    assert client.get("/me/api-keys", headers=_auth()).json()[0]["revoked_at"] is not None
    Base.metadata.drop_all(bind=engine)
