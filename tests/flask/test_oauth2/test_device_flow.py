import threading
import time

import pytest
from flask import json
from flask import request

from authlib.oauth2.rfc8628 import DEVICE_CODE_GRANT_TYPE
from authlib.oauth2.rfc8628 import DeviceAuthorizationEndpoint as _Endpoint
from authlib.oauth2.rfc8628 import DeviceCodeGrant as _Grant
from authlib.oauth2.rfc8628 import DeviceCredentialDict

from .models import User
from .models import db


class DeviceStore:
    """In-memory store shared by the grant and the endpoint."""

    def __init__(self):
        self.lock = threading.Lock()
        self.credentials = {}
        self.grants = {}


store = DeviceStore()


class DeviceCodeGrant(_Grant):
    def query_device_credential(self, device_code):
        return store.credentials.get(device_code)

    def query_user_grant(self, user_code):
        return store.grants.get(user_code)

    def should_slow_down(self, credential):
        return False

    def consume_device_credential(self, credential):
        with store.lock:
            if credential.is_consumed():
                from authlib.oauth2.rfc6749.errors import InvalidRequestError

                raise InvalidRequestError(
                    "The 'device_code' has already been consumed"
                )
            credential.consume()


class DeviceAuthorizationEndpoint(_Endpoint):
    def get_verification_uri(self):
        return "https://resource.test/activate"

    def save_device_credential(self, client_id, scope, data):
        credential = DeviceCredentialDict(
            client_id=client_id,
            scope=scope,
            device_code=data["device_code"],
            user_code=data["user_code"],
            expires_at=int(time.time()) + data["expires_in"],
        )
        store.credentials[data["device_code"]] = credential

    def query_device_credential_by_user_code(self, user_code):
        for credential in store.credentials.values():
            if credential.get("user_code") == user_code:
                return credential
        return None

    def query_user_grant(self, user_code):
        return store.grants.get(user_code)

    def save_user_grant(self, user_code, credential, user, approved):
        with store.lock:
            store.grants[user_code] = (user, approved)


@pytest.fixture(autouse=True)
def server(server, app):
    store.credentials.clear()
    store.grants.clear()
    server.register_device_code_grant(DeviceAuthorizationEndpoint, DeviceCodeGrant)

    @app.route("/device_verification", methods=["POST"])
    def device_verification():
        if request.form.get("decision") == "deny":
            grant_user = None
        else:
            grant_user = db.session.query(User).get(1)
        return server.create_device_authorization_response(grant_user)

    return server


@pytest.fixture(autouse=True)
def client(client, db):
    client.set_client_metadata(
        {
            "redirect_uris": ["https://client.test/authorized"],
            "scope": "profile",
            "grant_types": [DEVICE_CODE_GRANT_TYPE],
            "token_endpoint_auth_method": "none",
        }
    )
    db.session.add(client)
    db.session.commit()
    return client


def test_device_authorization_endpoint_returns_json(test_client):
    rv = test_client.post("/device_authorization", data={"client_id": "client-id"})
    assert rv.status_code == 200
    assert rv.content_type.startswith("application/json")
    resp = json.loads(rv.data)
    assert "device_code" in resp
    assert "user_code" in resp
    assert resp["verification_uri"] == "https://resource.test/activate"
    assert resp["expires_in"] == 1800
    assert resp["interval"] == 5


def test_device_authorization_endpoint_post_only(test_client):
    rv = test_client.get("/device_authorization")
    assert rv.status_code == 405


def test_full_device_flow(test_client):
    rv = test_client.post("/device_authorization", data={"client_id": "client-id"})
    resp = json.loads(rv.data)
    device_code = resp["device_code"]
    user_code = resp["user_code"]

    # device polls before the user confirmed: authorization_pending
    rv = test_client.post(
        "/oauth/token",
        data={
            "grant_type": DEVICE_CODE_GRANT_TYPE,
            "device_code": device_code,
            "client_id": "client-id",
        },
    )
    resp = json.loads(rv.data)
    assert resp["error"] == "authorization_pending"

    # the user confirms on the verification URI
    rv = test_client.post("/device_verification", data={"user_code": user_code})
    assert rv.status_code == 200
    resp = json.loads(rv.data)
    assert resp["approved"] is True
    assert resp["user_code"] == user_code
    assert resp["device_code"] == device_code

    # repeated confirmation is idempotent
    rv = test_client.post("/device_verification", data={"user_code": user_code})
    resp = json.loads(rv.data)
    assert resp["approved"] is True

    # device polls again and gets the access token
    rv = test_client.post(
        "/oauth/token",
        data={
            "grant_type": DEVICE_CODE_GRANT_TYPE,
            "device_code": device_code,
            "client_id": "client-id",
        },
    )
    assert rv.status_code == 200
    resp = json.loads(rv.data)
    assert "access_token" in resp

    # the same device_code can not be redeemed twice
    rv = test_client.post(
        "/oauth/token",
        data={
            "grant_type": DEVICE_CODE_GRANT_TYPE,
            "device_code": device_code,
            "client_id": "client-id",
        },
    )
    assert rv.status_code == 400
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_request"


def test_device_verification_denied(test_client):
    rv = test_client.post("/device_authorization", data={"client_id": "client-id"})
    resp = json.loads(rv.data)

    rv = test_client.post(
        "/device_verification",
        data={"user_code": resp["user_code"], "decision": "deny"},
    )
    resp = json.loads(rv.data)
    assert resp["approved"] is False

    # a later approval does not overwrite the recorded denial
    rv = test_client.post("/device_verification", data={"user_code": resp["user_code"]})
    resp = json.loads(rv.data)
    assert resp["approved"] is False


def test_device_verification_invalid_user_code(test_client):
    rv = test_client.post("/device_verification", data={})
    assert rv.status_code == 400
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_request"

    rv = test_client.post("/device_verification", data={"user_code": "UNKNOWN"})
    assert rv.status_code == 400
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_request"
