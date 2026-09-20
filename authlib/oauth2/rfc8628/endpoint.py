from authlib.common.security import generate_token
from authlib.common.urls import add_params_to_uri
from authlib.consts import default_json_headers
from authlib.oauth2.rfc6749.errors import InvalidRequestError


class DeviceAuthorizationEndpoint:
    """This OAuth 2.0 [RFC6749] protocol extension enables OAuth clients to
    request user authorization from applications on devices that have
    limited input capabilities or lack a suitable browser.  Such devices
    include smart TVs, media consoles, picture frames, and printers,
    which lack an easy input method or a suitable browser required for
    traditional OAuth interactions. Here is the authorization flow::

        +----------+                                +----------------+
        |          |>---(A)-- Client Identifier --->|                |
        |          |                                |                |
        |          |<---(B)-- Device Code,      ---<|                |
        |          |          User Code,            |                |
        |  Device  |          & Verification URI    |                |
        |  Client  |                                |                |
        |          |  [polling]                     |                |
        |          |>---(E)-- Device Code       --->|                |
        |          |          & Client Identifier   |                |
        |          |                                |  Authorization |
        |          |<---(F)-- Access Token      ---<|     Server     |
        +----------+   (& Optional Refresh Token)   |                |
              v                                     |                |
              :                                     |                |
             (C) User Code & Verification URI       |                |
              :                                     |                |
              v                                     |                |
        +----------+                                |                |
        | End User |                                |                |
        |    at    |<---(D)-- End user reviews  --->|                |
        |  Browser |          authorization request |                |
        +----------+                                +----------------+

    This DeviceAuthorizationEndpoint is the implementation of step (A) and (B).

    (A) The client requests access from the authorization server and
        includes its client identifier in the request.

    (B) The authorization server issues a device code and an end-user
        code and provides the end-user verification URI.
    """

    ENDPOINT_NAME = "device_authorization"
    CLIENT_AUTH_METHODS = ["client_secret_basic", "client_secret_post", "none"]

    #: customize "user_code" type, string or digital
    USER_CODE_TYPE = "string"

    #: The lifetime in seconds of the "device_code" and "user_code"
    EXPIRES_IN = 1800

    #: The minimum amount of time in seconds that the client SHOULD
    #: wait between polling requests to the token endpoint.
    INTERVAL = 5

    def __init__(self, server):
        self.server = server

    def __call__(self, request):
        # make it callable for authorization server
        # ``create_endpoint_response``
        return self.create_endpoint_response(request)

    def create_endpoint_request(self, request):
        return self.server.create_oauth2_request(request)

    def authenticate_client(self, request):
        """client_id is REQUIRED **if the client is not** authenticating with the
        authorization server as described in Section 3.2.1. of [RFC6749].

        This means the endpoint support "none" authentication method. In this case,
        this endpoint's auth methods are:

        - client_secret_basic
        - client_secret_post
        - none

        Developers change the value of ``CLIENT_AUTH_METHODS`` in subclass. For
        instance::

            class MyDeviceAuthorizationEndpoint(DeviceAuthorizationEndpoint):
                # only support ``client_secret_basic`` auth method
                CLIENT_AUTH_METHODS = ["client_secret_basic"]
        """
        client = self.server.authenticate_client(
            request, self.CLIENT_AUTH_METHODS, self.ENDPOINT_NAME
        )
        request.client = client
        return client

    def create_endpoint_response(self, request):
        # https://tools.ietf.org/html/rfc8628#section-3.1

        self.authenticate_client(request)
        self.server.validate_requested_scope(request.payload.scope)

        device_code = self.generate_device_code()
        user_code = self.generate_user_code()
        verification_uri = self.get_verification_uri()
        verification_uri_complete = add_params_to_uri(
            verification_uri, [("user_code", user_code)]
        )

        data = {
            "device_code": device_code,
            "user_code": user_code,
            "verification_uri": verification_uri,
            "verification_uri_complete": verification_uri_complete,
            "expires_in": self.EXPIRES_IN,
            "interval": self.INTERVAL,
        }

        self.save_device_credential(
            request.payload.client_id, request.payload.scope, data
        )
        return 200, data, default_json_headers

    def create_authorization_response(self, request, user, grant_user=None):
        """Handle the end-user confirmation on the verification URI
        (RFC 8628, step (C)/(D)). This is NOT the OAuth authorization
        endpoint: it never returns a redirect, it returns JSON.

        The framework integrations expose this method as a view for the
        end-user's browser::

            @app.route("/device_verification", methods=["POST"])
            def device_verification():
                return server.create_device_authorization_response(
                    current_user, request
                )

        Expected form parameters:

        user_code
            REQUIRED. The end-user code displayed by the device client.

        The end-user's decision is taken from ``grant_user``: the request is
        approved when ``grant_user`` is truthy, otherwise denied.

        The method is idempotent: once a ``user_code`` has been consumed
        (either approved or denied), repeated browser confirmations do not
        overwrite the recorded decision and return the same JSON result.

        :param request: framework HTTP request instance.
        :param user: the authenticated end-user, or None for anonymous users.
        :param grant_user: the end-user when approved, None when denied.
        :return: ``(status_code, payload, headers)`` tuple.
        """
        if not hasattr(request, "payload"):
            request = self.create_endpoint_request(request)

        user_code = request.payload.data.get("user_code")
        if not user_code:
            raise InvalidRequestError("Missing 'user_code' in payload")

        credential = self.query_device_credential_by_user_code(user_code)
        if not credential:
            raise InvalidRequestError("Invalid 'user_code' in payload")

        if credential.is_expired():
            raise InvalidRequestError("The 'user_code' has expired")

        approved = bool(grant_user)

        # Idempotency: the same "user_code" may be confirmed by the
        # end-user's browser while the device is polling the token
        # endpoint. The first recorded decision wins, repeated
        # confirmations MUST NOT overwrite it.
        existing = self.query_user_grant(user_code)
        if existing is not None or credential.is_consumed():
            return self._build_confirmation_response(user_code, credential)

        self.save_user_grant(user_code, credential, user, approved)
        return self._build_confirmation_response(user_code, credential)

    def _build_confirmation_response(self, user_code, credential):
        data = {
            "user_code": user_code,
            "device_code": credential.get_device_code(),
        }
        user_grant = self.query_user_grant(user_code)
        if user_grant is not None:
            _user, approved = user_grant
            data["approved"] = bool(approved)
        return 200, data, default_json_headers

    def query_device_credential_by_user_code(self, user_code):
        """Get device credential by ``user_code``. Developers MUST implement
        it in subclass so that the verification endpoint can locate the
        authorization session::

            def query_device_credential_by_user_code(self, user_code):
                return DeviceCredential.query.filter_by(
                    user_code=user_code
                ).first()
        """
        raise NotImplementedError()

    def query_user_grant(self, user_code):
        """Get the recorded end-user decision for the given ``user_code``.
        Return ``None`` when the end-user has not confirmed yet, otherwise a
        ``(user, approved)`` tuple. Developers SHOULD implement it in subclass
        to enable idempotent confirmations."""
        return None

    def save_user_grant(self, user_code, credential, user, approved):
        """Persist the end-user decision for ``user_code``. Developers MUST
        implement it in subclass::

            def save_user_grant(self, user_code, credential, user, approved):
                item = UserGrant(
                    user_code=user_code,
                    user_id=user.get_user_id() if user else None,
                    approved=approved,
                )
                item.save()
        """
        raise NotImplementedError()

    def generate_user_code(self):
        """A method to generate ``user_code`` value for device authorization
        endpoint. This method will generate a random string like MQNA-JPOZ.
        Developers can rewrite this  method to create their own ``user_code``.
        """
        # https://tools.ietf.org/html/rfc8628#section-6.1
        if self.USER_CODE_TYPE == "digital":
            return create_digital_user_code()
        return create_string_user_code()

    def generate_device_code(self):
        """A method to generate ``device_code`` value for device authorization
        endpoint. This method will generate a random string of 42 characters.
        Developers can rewrite this method to create their own ``device_code``.
        """
        return generate_token(42)

    def get_verification_uri(self):
        """Define the ``verification_uri`` of device authorization endpoint.
        Developers MUST implement this method in subclass::

            def get_verification_uri(self):
                return "https://your-company.com/active"
        """
        raise NotImplementedError()

    def save_device_credential(self, client_id, scope, data):
        """Save device token into database for later use. Developers MUST
        implement this method in subclass::

            def save_device_credential(self, client_id, scope, data):
                item = DeviceCredential(client_id=client_id, scope=scope, **data)
                item.save()
        """
        raise NotImplementedError()


def create_string_user_code():
    base = "BCDFGHJKLMNPQRSTVWXZ"
    return "-".join([generate_token(4, base), generate_token(4, base)])


def create_digital_user_code():
    base = "0123456789"
    return "-".join(
        [
            generate_token(3, base),
            generate_token(3, base),
            generate_token(3, base),
        ]
    )
