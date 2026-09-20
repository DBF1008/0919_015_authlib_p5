import threading
import time

import pytest

from authlib.oauth2.rfc6749.errors import AccessDeniedError
from authlib.oauth2.rfc6749.errors import InvalidRequestError
from authlib.oauth2.rfc6749.requests import OAuth2Request
from authlib.oauth2.rfc8628 import DeviceAuthorizationEndpoint as _Endpoint
from authlib.oauth2.rfc8628 import DeviceCodeGrant as _Grant
from authlib.oauth2.rfc8628 import DeviceCredentialDict
from authlib.oauth2.rfc8628.errors import AuthorizationPendingError
from authlib.oauth2.rfc8628.errors import ExpiredTokenError


class User:
    def __init__(self, user_id):
        self.id = user_id

    def get_user_id(self):
        return self.id


class Store:
    """Shared in-memory storage for device credentials and user grants."""

    def __init__(self):
        self.lock = threading.Lock()
        self.credentials = {}
        self.grants = {}

    def add_credential(self, device_code, user_code, expires_in=1800):
        credential = DeviceCredentialDict(
            client_id="client-id",
            device_code=device_code,
            user_code=user_code,
            scope="profile",
            expires_at=int(time.time()) + expires_in,
        )
        self.credentials[device_code] = credential
        return credential

    def credential(self, device_code):
        return self.credentials.get(device_code)


class FakeServer:
    def __init__(self, store):
        self.store = store
        self.issued_tokens = []

    def generate_token(self, **kwargs):
        return {"access_token": "token", "token_type": "Bearer"}


class DeviceCodeGrant(_Grant):
    def __init__(self, request, server, store):
        super().__init__(request, server)
        self.store = store

    def query_device_credential(self, device_code):
        return self.store.credential(device_code)

    def query_user_grant(self, user_code):
        return self.store.grants.get(user_code)

    def should_slow_down(self, credential):
        return False

    def consume_device_credential(self, credential):
        with self.store.lock:
            if credential.is_consumed():
                raise InvalidRequestError(
                    "The 'device_code' has already been consumed"
                )
            credential.consume()


class DeviceAuthorizationEndpoint(_Endpoint):
    def __init__(self, server, store):
        super().__init__(server)
        self.store = store

    def get_verification_uri(self):
        return "https://resource.test/activate"

    def save_device_credential(self, client_id, scope, data):
        pass

    def query_device_credential_by_user_code(self, user_code):
        for credential in self.store.credentials.values():
            if credential.get("user_code") == user_code:
                return credential
        return None

    def query_user_grant(self, user_code):
        return self.store.grants.get(user_code)

    def save_user_grant(self, user_code, credential, user, approved):
        with self.store.lock:
            self.store.grants[user_code] = (user, approved)


class FakeClient:
    def get_client_id(self):
        return "client-id"

    def check_grant_type(self, grant_type):
        return grant_type == _Grant.GRANT_TYPE


def make_grant(store, device_code):
    request = OAuth2Request(
        "POST",
        "https://server.test/oauth/token",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    request.payload = type("Payload", (), {})()
    request.payload.data = {"device_code": device_code}
    request.payload.datalist = {"device_code": [device_code]}
    request.client = FakeClient()
    server = FakeServer(store)
    grant = DeviceCodeGrant(request, server, store)

    def save_token(token):
        server.issued_tokens.append(token)

    grant.save_token = save_token
    grant.authenticate_token_endpoint_client = lambda: request.client
    return grant, request, server


def make_confirmation_request(user_code):
    request = OAuth2Request(
        "POST",
        "https://server.test/device_verification",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    request.payload = type("Payload", (), {})()
    request.payload.data = {"user_code": user_code}
    request.payload.datalist = {"user_code": [user_code]}
    return request


def test_consumed_device_code_is_not_redeemed_twice():
    store = Store()
    store.add_credential("dc-1", "UC-1")
    store.grants["UC-1"] = (User(1), True)

    grant, request, server = make_grant(store, "dc-1")
    grant.validate_token_request()
    assert request.user.id == 1
    grant.create_token_response()
    assert len(server.issued_tokens) == 1

    grant2, request2, _ = make_grant(store, "dc-1")
    with pytest.raises(InvalidRequestError) as exc:
        grant2.validate_token_request()
    assert "already been consumed" in str(exc.value)


def test_concurrent_polls_only_one_wins():
    store = Store()
    store.add_credential("dc-concurrent", "UC-C")
    store.grants["UC-C"] = (User(1), True)

    errors = []
    issued = []
    barrier = threading.Barrier(2)

    def poll():
        grant, request, server = make_grant(store, "dc-concurrent")
        barrier.wait()
        try:
            grant.validate_token_request()
            grant.create_token_response()
            issued.append(server.issued_tokens[0])
        except InvalidRequestError as error:
            errors.append(error)

    threads = [threading.Thread(target=poll) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert len(issued) == 1
    assert len(errors) == 1
    assert "already been consumed" in str(errors[0])


def test_pending_and_expired_are_not_consumed():
    store = Store()
    store.add_credential("dc-pending", "UC-P")

    grant, _, _ = make_grant(store, "dc-pending")
    with pytest.raises(AuthorizationPendingError):
        grant.validate_token_request()

    store.grants["UC-P"] = (User(1), True)
    grant2, request2, _ = make_grant(store, "dc-pending")
    grant2.validate_token_request()
    assert request2.user.id == 1

    expired = Store()
    expired.add_credential("dc-exp", "UC-E", expires_in=-100)
    grant3, _, _ = make_grant(expired, "dc-exp")
    with pytest.raises(ExpiredTokenError):
        grant3.validate_token_request()


def test_denied_grant_raises_access_denied():
    store = Store()
    store.add_credential("dc-deny", "UC-D")
    store.grants["UC-D"] = (User(1), False)

    grant, _, _ = make_grant(store, "dc-deny")
    with pytest.raises(AccessDeniedError):
        grant.validate_token_request()
    assert not store.credentials["dc-deny"].get("consumed")


def test_browser_confirmation_approve_and_idempotent():
    store = Store()
    store.add_credential("dc-2", "UC-2")
    server = FakeServer(store)
    endpoint = DeviceAuthorizationEndpoint(server, store)
    request = make_confirmation_request("UC-2")

    status, payload, _ = endpoint.create_authorization_response(
        request, User(1), grant_user=User(1)
    )
    assert status == 200
    assert payload["approved"] is True
    assert payload["user_code"] == "UC-2"
    assert payload["device_code"] == "dc-2"
    assert store.grants["UC-2"][0].id == 1
    assert store.grants["UC-2"][1] is True

    # a second confirmation MUST NOT overwrite the recorded decision
    request2 = make_confirmation_request("UC-2")
    _, payload2, _ = endpoint.create_authorization_response(
        request2, User(2), grant_user=None
    )
    assert payload2["approved"] is True
    assert store.grants["UC-2"][0].id == 1
    assert store.grants["UC-2"][1] is True


def test_browser_denial_is_idempotent():
    store = Store()
    store.add_credential("dc-3", "UC-3")
    server = FakeServer(store)
    endpoint = DeviceAuthorizationEndpoint(server, store)

    _, payload, _ = endpoint.create_authorization_response(
        make_confirmation_request("UC-3"), None, grant_user=None
    )
    assert payload["approved"] is False

    _, payload2, _ = endpoint.create_authorization_response(
        make_confirmation_request("UC-3"), User(1), grant_user=User(1)
    )
    assert payload2["approved"] is False
    assert store.grants["UC-3"][1] is False


def test_browser_confirmation_when_device_already_consumed():
    store = Store()
    store.add_credential("dc-4", "UC-4")
    store.grants["UC-4"] = (User(1), True)
    store.credentials["dc-4"]["consumed"] = True

    server = FakeServer(store)
    endpoint = DeviceAuthorizationEndpoint(server, store)

    _, payload, _ = endpoint.create_authorization_response(
        make_confirmation_request("UC-4"), User(1), grant_user=User(1)
    )
    assert payload["approved"] is True


def test_browser_confirmation_missing_or_unknown_user_code():
    store = Store()
    server = FakeServer(store)
    endpoint = DeviceAuthorizationEndpoint(server, store)

    request = make_confirmation_request("UC-X")
    request.payload.data = {}
    with pytest.raises(InvalidRequestError):
        endpoint.create_authorization_response(request, None, grant_user=None)

    with pytest.raises(InvalidRequestError):
        endpoint.create_authorization_response(
            make_confirmation_request("UNKNOWN"), None, grant_user=None
        )


def test_credential_dict_consumed_flag():
    credential = DeviceCredentialDict(device_code="x", user_code="y")
    assert credential.is_consumed() is False
    credential.consume()
    assert credential.is_consumed() is True
