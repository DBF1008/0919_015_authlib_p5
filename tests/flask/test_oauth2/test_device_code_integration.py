import threading
import time

import flask
import pytest

from authlib.integrations.flask_oauth2 import AuthorizationServer
from authlib.oauth2.rfc8628 import (
    DeviceAuthorizationEndpoint as _DeviceAuthorizationEndpoint,
)
from authlib.oauth2.rfc8628 import DeviceCodeGrant as _DeviceCodeGrant
from authlib.oauth2.rfc8628 import DeviceCredentialDict

from .models import Client
from .models import Token
from .models import User
from .models import db


class DeviceStore:
    """In-memory device credential + user grant store with an atomic
    compare-and-set consumption guard."""

    def __init__(self):
        self.lock = threading.Lock()
        self.credentials = {}
        self.user_grants = {}

    def reset(self):
        with self.lock:
            self.credentials.clear()
            self.user_grants.clear()


store = DeviceStore()


class DeviceCodeGrant(_DeviceCodeGrant):
    def query_device_credential(self, device_code):
        return store.credentials.get(device_code)

    def query_user_grant(self, user_code):
        return store.user_grants.get(user_code)

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


class DeviceAuthorizationEndpoint(_DeviceAuthorizationEndpoint):
    def get_verification_uri(self):
        return "https://resource.test/activate"

    def save_device_credential(self, client_id, scope, data):
        credential = dict(data)
        credential["client_id"] = client_id
        credential["scope"] = scope
        credential["expires_at"] = int(time.time()) + data["expires_in"]
        store.credentials[data["device_code"]] = DeviceCredentialDict(credential)

    def query_device_credential_by_user_code(self, user_code):
        for credential in store.credentials.values():
            if credential.get("user_code") == user_code:
                return credential
        return None

    def query_user_grant(self, user_code):
        return store.user_grants.get(user_code)

    def save_user_grant(self, user_code, credential, user, approved):
        with store.lock:
            store.user_grants[user_code] = (user, approved)


def make_server(app):
    def query_client(client_id):
        return db.session.query(Client).filter_by(client_id=client_id).first()

    def save_token(token, request):
        kwargs = {"client_id": request.client.client_id}
        if request.user:
            kwargs["user_id"] = request.user.id
        kwargs.update(token)
        item = Token(**kwargs)
        db.session.add(item)
        db.session.commit()

    return AuthorizationServer(app, query_client, save_token)


@pytest.fixture(autouse=True)
def setup(app, db):
    store.reset()
    server = make_server(app)
    server.register_device_code_grant(DeviceAuthorizationEndpoint, DeviceCodeGrant)

    @app.route("/device_verification", methods=["POST"])
    def device_verification():
        user = db.session.get(User, 1)
        decision = flask.request.form.get("decision", "approve")
        grant_user = user if decision != "deny" else None
        return server.create_device_authorization_response(grant_user)

    @app.route("/oauth/token2", methods=["POST"])
    def token2():
        return server.create_token_response()

    client = Client(user_id=1, client_id="device-client", client_secret="secret")
    client.set_client_metadata(
        {
            "scope": "profile",
            "grant_types": [DeviceCodeGrant.GRANT_TYPE],
            "token_endpoint_auth_method": "none",
        }
    )
    db.session.add(client)
    db.session.commit()
    return server


def test_device_authorization_route_is_post_and_json(test_client):
    rv = test_client.get("/device_authorization")
    assert rv.status_code == 405

    rv = test_client.post("/device_authorization", data={"client_id": "device-client"})
    assert rv.status_code == 200
    payload = rv.get_json()
    assert set(payload) >= {
        "device_code",
        "user_code",
        "verification_uri",
        "verification_uri_complete",
        "expires_in",
        "interval",
    }
    assert payload["verification_uri"] == "https://resource.test/activate"
    assert payload["device_code"] in store.credentials


def test_full_device_flow_and_single_use(test_client):
    rv = test_client.post("/device_authorization", data={"client_id": "device-client"})
    device_response = rv.get_json()
    device_code = device_response["device_code"]
    user_code = device_response["user_code"]

    # polling before the end-user confirmation is still pending
    rv = test_client.post(
        "/oauth/token2",
        data={
            "grant_type": DeviceCodeGrant.GRANT_TYPE,
            "device_code": device_code,
            "client_id": "device-client",
        },
    )
    assert rv.get_json()["error"] == "authorization_pending"

    rv = test_client.post("/device_verification", data={"user_code": user_code})
    assert rv.status_code == 200
    assert rv.get_json()["approved"] is True

    # repeated confirmations are idempotent: the recorded decision wins
    rv = test_client.post(
        "/device_verification",
        data={"user_code": user_code, "decision": "deny"},
    )
    assert rv.get_json()["approved"] is True

    rv = test_client.post(
        "/oauth/token2",
        data={
            "grant_type": DeviceCodeGrant.GRANT_TYPE,
            "device_code": device_code,
            "client_id": "device-client",
        },
    )
    assert "access_token" in rv.get_json()

    # a device_code can only be exchanged for a token once
    rv = test_client.post(
        "/oauth/token2",
        data={
            "grant_type": DeviceCodeGrant.GRANT_TYPE,
            "device_code": device_code,
            "client_id": "device-client",
        },
    )
    assert rv.status_code == 400
    assert rv.get_json()["error"] == "invalid_request"


def test_concurrent_polling_only_issues_one_token(app):
    from .models import Client  # noqa: F401

    device_code = "race-code"
    user_code = "RACE-CODE"
    store.credentials[device_code] = DeviceCredentialDict(
        client_id="device-client",
        device_code=device_code,
        user_code=user_code,
        scope="profile",
        expires_at=int(time.time()) + 1800,
    )
    with app.app_context():
        store.user_grants[user_code] = (db.session.get(User, 1), True)

    results = []
    errors = []
    barrier = threading.Barrier(2)

    def poll():
        client = app.test_client()
        barrier.wait()
        rv = client.post(
            "/oauth/token2",
            data={
                "grant_type": DeviceCodeGrant.GRANT_TYPE,
                "device_code": device_code,
                "client_id": "device-client",
            },
        )
        payload = rv.get_json()
        if "access_token" in payload:
            results.append(payload["access_token"])
        else:
            errors.append(payload["error"])

    threads = [threading.Thread(target=poll) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert len(results) == 1
    assert errors == ["invalid_request"]


def test_device_token_saved_without_user_id(app, db):
    from .models import Token

    device_code = "no-user"
    user_code = "NO-USER"
    store.credentials[device_code] = DeviceCredentialDict(
        client_id="device-client",
        device_code=device_code,
        user_code=user_code,
        scope="profile",
        expires_at=int(time.time()) + 1800,
    )
    with app.app_context():
        store.user_grants[user_code] = (db.session.get(User, 1), True)
        rv = app.test_client().post(
            "/oauth/token2",
            data={
                "grant_type": DeviceCodeGrant.GRANT_TYPE,
                "device_code": device_code,
                "client_id": "device-client",
            },
        )
        assert "access_token" in rv.get_json()
        token = Token.query.filter_by(
            access_token=rv.get_json()["access_token"]
        ).one()
        assert token.client_id == "device-client"
