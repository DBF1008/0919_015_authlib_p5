import json
import threading
import time

import pytest

from authlib.integrations.django_oauth2 import AuthorizationServer  # noqa: F401
from authlib.oauth2.rfc6749.errors import InvalidRequestError
from authlib.oauth2.rfc8628 import (
    DeviceAuthorizationEndpoint as _DeviceAuthorizationEndpoint,
)
from authlib.oauth2.rfc8628 import DeviceCodeGrant as _DeviceCodeGrant
from authlib.oauth2.rfc8628 import DeviceCredentialDict

from .models import Client
from .models import User  # noqa: F401


class DeviceStore:
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


@pytest.fixture(autouse=True)
def device_server(server):
    server.register_device_code_grant(DeviceAuthorizationEndpoint, DeviceCodeGrant)
    store.reset()
    return server


@pytest.fixture(autouse=True)
def device_client(db, user):
    client = Client(
        user_id=user.pk,
        client_id="device-client",
        client_secret="",
        scope="profile",
        grant_type=DeviceCodeGrant.GRANT_TYPE,
        token_endpoint_auth_method="none",
        default_redirect_uri="https://client.test",
    )
    client.save()
    yield client
    client.delete()


def test_device_authorization_endpoint_post_json(factory, device_server):
    request = factory.post(
        "/device_authorization", data={"client_id": "device-client"}
    )
    response = device_server.device_authorization_view(request)
    assert response.status_code == 200
    payload = json.loads(response.content)
    assert {
        "device_code",
        "user_code",
        "verification_uri",
        "verification_uri_complete",
        "expires_in",
        "interval",
    } <= set(payload)
    assert payload["verification_uri"] == "https://resource.test/activate"
    assert payload["device_code"] in store.credentials

    get_request = factory.get("/device_authorization")
    get_response = device_server.device_authorization_view(get_request)
    assert get_response.status_code == 405


def test_full_device_flow_single_use(factory, device_server, user):
    request = factory.post(
        "/device_authorization", data={"client_id": "device-client"}
    )
    payload = json.loads(device_server.device_authorization_view(request).content)
    device_code = payload["device_code"]
    user_code = payload["user_code"]

    # polling before the end-user confirmation is still pending
    response = device_server.create_token_response(
        factory.post(
            "/oauth/token",
            data={
                "grant_type": DeviceCodeGrant.GRANT_TYPE,
                "device_code": device_code,
                "client_id": "device-client",
            },
        )
    )
    assert json.loads(response.content)["error"] == "authorization_pending"

    confirm_request = factory.post(
        "/device_verification", data={"user_code": user_code}
    )
    response = device_server.create_device_authorization_response(
        user, confirm_request
    )
    assert response.status_code == 200
    assert json.loads(response.content)["approved"] is True

    # repeated confirmations are idempotent: the recorded decision wins
    deny_request = factory.post(
        "/device_verification", data={"user_code": user_code}
    )
    response = device_server.create_device_authorization_response(
        None, deny_request
    )
    assert json.loads(response.content)["approved"] is True

    response = device_server.create_token_response(
        factory.post(
            "/oauth/token",
            data={
                "grant_type": DeviceCodeGrant.GRANT_TYPE,
                "device_code": device_code,
                "client_id": "device-client",
            },
        )
    )
    token_payload = json.loads(response.content)
    assert "access_token" in token_payload

    # a device_code can only be exchanged for a token once
    response = device_server.create_token_response(
        factory.post(
            "/oauth/token",
            data={
                "grant_type": DeviceCodeGrant.GRANT_TYPE,
                "device_code": device_code,
                "client_id": "device-client",
            },
        )
    )
    assert response.status_code == 400
    assert json.loads(response.content)["error"] == "invalid_request"


def test_concurrent_polling_only_one_token(device_server, user, db):
    device_code = "django-race"
    user_code = "DJANGO-RACE"
    store.credentials[device_code] = DeviceCredentialDict(
        client_id="device-client",
        device_code=device_code,
        user_code=user_code,
        scope="profile",
        expires_at=int(time.time()) + 1800,
    )
    store.user_grants[user_code] = (user, True)
    client = Client.objects.get(client_id="device-client")

    from authlib.oauth2.rfc6749.requests import OAuth2Request

    def make_request():
        request = OAuth2Request(
            "POST",
            "https://server.test/oauth/token",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        request.payload = type("Payload", (), {})()
        request.payload.data = {
            "grant_type": DeviceCodeGrant.GRANT_TYPE,
            "device_code": device_code,
            "client_id": "device-client",
        }
        request.payload.datalist = {
            key: [value] for key, value in request.payload.data.items()
        }
        return request

    issued = []
    errors = []
    barrier = threading.Barrier(2)

    def poll():
        request = make_request()
        grant = DeviceCodeGrant(request, device_server)
        grant.authenticate_token_endpoint_client = lambda: client
        grant.save_token = lambda token: None
        barrier.wait()
        try:
            grant.validate_token_request()
            status, token, _ = grant.create_token_response()
            assert status == 200
            issued.append(token["access_token"])
        except InvalidRequestError as error:
            errors.append(str(error))

    threads = [threading.Thread(target=poll) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert len(issued) == 1
    assert len(errors) == 1
    assert "already been consumed" in errors[0]
