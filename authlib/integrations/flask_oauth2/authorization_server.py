from flask import Response
from flask import json
from flask import request as flask_req
from werkzeug.utils import import_string

from authlib.common.security import generate_token
from authlib.oauth2 import AuthorizationServer as _AuthorizationServer
from authlib.oauth2.rfc6749.errors import OAuth2Error
from authlib.oauth2.rfc6750 import BearerTokenGenerator

from .requests import FlaskJsonRequest
from .requests import FlaskOAuth2Request
from .signals import client_authenticated
from .signals import token_revoked


class AuthorizationServer(_AuthorizationServer):
    """Flask implementation of :class:`authlib.oauth2.rfc6749.AuthorizationServer`.
    Initialize it with ``query_client``, ``save_token`` methods and Flask
    app instance::

        def query_client(client_id):
            return Client.query.filter_by(client_id=client_id).first()


        def save_token(token, request):
            if request.user:
                user_id = request.user.id
            else:
                user_id = None
            client = request.client
            tok = Token(client_id=client.client_id, user_id=user.id, **token)
            db.session.add(tok)
            db.session.commit()


        server = AuthorizationServer(app, query_client, save_token)
        # or initialize lazily
        server = AuthorizationServer()
        server.init_app(app, query_client, save_token)
    """

    def __init__(self, app=None, query_client=None, save_token=None):
        super().__init__()
        self.app = None
        self._query_client = query_client
        self._save_token = save_token
        self._error_uris = None
        if app is not None:
            self.init_app(app)

    def init_app(self, app, query_client=None, save_token=None):
        """Initialize later with Flask app instance."""
        if query_client is not None:
            self._query_client = query_client
        if save_token is not None:
            self._save_token = save_token
        self.app = app
        self.load_config(app.config)

    def load_config(self, config):
        self.register_token_generator(
            "default", self.create_bearer_token_generator(config)
        )
        self.scopes_supported = config.get("OAUTH2_SCOPES_SUPPORTED")
        self._error_uris = config.get("OAUTH2_ERROR_URIS")

    def query_client(self, client_id):
        return self._query_client(client_id)

    def save_token(self, token, request):
        return self._save_token(token, request)

    def get_error_uri(self, request, error):
        if self._error_uris:
            uris = dict(self._error_uris)
            return uris.get(error.error)

    def create_oauth2_request(self, request):
        return FlaskOAuth2Request(flask_req)

    def create_json_request(self, request):
        return FlaskJsonRequest(flask_req)

    def handle_response(self, status_code, payload, headers):
        if isinstance(payload, dict):
            payload = json.dumps(payload)
        return Response(payload, status=status_code, headers=headers)

    def send_signal(self, name, *args, **kwargs):
        if name == "after_authenticate_client":
            client_authenticated.send(self, *args, **kwargs)
        elif name == "after_revoke_token":
            token_revoked.send(self, *args, **kwargs)

    def register_device_code_grant(
        self,
        device_authorization_endpoint,
        device_code_grant,
        device_authorization_url="/device_authorization",
    ):
        """Register the OAuth 2.0 Device Authorization Grant (RFC 8628).

        It registers both the ``DeviceCodeGrant`` token grant and the
        ``DeviceAuthorizationEndpoint``. Unlike the authorization endpoint,
        the device authorization endpoint only accepts POST requests and
        responds with JSON (``device_code``, ``user_code``,
        ``verification_uri``, ``expires_in`` and ``interval``) instead of an
        OAuth redirect.

        When ``device_authorization_url`` is provided (default
        ``/device_authorization``), a POST-only Flask view is registered on
        the application automatically. Pass ``None`` to register the endpoint
        without a route and wire it up yourself::

            @app.route("/device_authorization", methods=["POST"])
            def device_authorization():
                return server.create_endpoint_response("device_authorization")

        The end-user verification (confirmation) view is always registered by
        the developer, for example::

            @app.route("/device_verification", methods=["POST"])
            def device_verification():
                return server.create_device_authorization_response(
                    current_user, grant_user=current_user
                )

        :param device_authorization_endpoint: a ``DeviceAuthorizationEndpoint``
            subclass.
        :param device_code_grant: a ``DeviceCodeGrant`` subclass.
        :param device_authorization_url: URL rule for the device authorization
            endpoint, or ``None`` to skip the automatic route registration.
        """
        self.register_grant(device_code_grant)
        self.register_endpoint(device_authorization_endpoint)

        if device_authorization_url is not None and self.app is not None:
            endpoint_name = "oauth2_device_authorization"

            def device_authorization_view():
                return self.create_endpoint_response(
                    device_authorization_endpoint.ENDPOINT_NAME
                )

            self.app.add_url_rule(
                device_authorization_url,
                endpoint_name,
                device_authorization_view,
                methods=["POST"],
            )

    def create_device_authorization_response(self, grant_user, request=None):
        """Create the response for the end-user verification (confirmation)
        page of the device authorization grant. Pass the authenticated end
        user when the end user approves the request, or ``None`` when
        denying it::

            @app.route("/device_verification", methods=["POST"])
            def device_verification():
                if not current_user:
                    return redirect(url_for("login"))
                if request.form.get("decision") == "deny":
                    grant_user = None
                else:
                    grant_user = current_user
                return server.create_device_authorization_response(grant_user)

        The endpoint responds with JSON and is idempotent: a ``user_code``
        can only be confirmed once, repeated confirmations return the recorded
        decision without overwriting it.
        """
        from authlib.oauth2.rfc8628 import DeviceAuthorizationEndpoint

        if request is None:
            request = flask_req
        oauth2_request = self.create_oauth2_request(request)
        endpoint = self._endpoints[DeviceAuthorizationEndpoint.ENDPOINT_NAME][0]
        try:
            args = endpoint.create_authorization_response(
                oauth2_request, grant_user, grant_user=grant_user
            )
            return self.handle_response(*args)
        except OAuth2Error as error:
            return self.handle_error_response(oauth2_request, error)

    def create_bearer_token_generator(self, config):
        """Create a generator function for generating ``token`` value. This
        method will create a Bearer Token generator with
        :class:`authlib.oauth2.rfc6750.BearerToken`.

        Configurable settings:

        1. OAUTH2_ACCESS_TOKEN_GENERATOR: Boolean or import string, default is True.
        2. OAUTH2_REFRESH_TOKEN_GENERATOR: Boolean or import string, default is False.
        3. OAUTH2_TOKEN_EXPIRES_IN: Dict or import string, default is None.

        By default, it will not generate ``refresh_token``, which can be turn on by
        configure ``OAUTH2_REFRESH_TOKEN_GENERATOR``.

        Here are some examples of the token generator::

            OAUTH2_ACCESS_TOKEN_GENERATOR = "your_project.generators.gen_token"

            # and in module `your_project.generators`, you can define:


            def gen_token(client, grant_type, user, scope):
                # generate token according to these parameters
                token = create_random_token()
                return f"{client.id}-{user.id}-{token}"

        Here is an example of ``OAUTH2_TOKEN_EXPIRES_IN``::

            OAUTH2_TOKEN_EXPIRES_IN = {
                "authorization_code": 864000,
                "urn:ietf:params:oauth:grant-type:jwt-bearer": 3600,
            }
        """
        conf = config.get("OAUTH2_ACCESS_TOKEN_GENERATOR", True)
        access_token_generator = create_token_generator(conf, 42)

        conf = config.get("OAUTH2_REFRESH_TOKEN_GENERATOR", False)
        refresh_token_generator = create_token_generator(conf, 48)

        expires_conf = config.get("OAUTH2_TOKEN_EXPIRES_IN")
        expires_generator = create_token_expires_in_generator(expires_conf)
        return BearerTokenGenerator(
            access_token_generator, refresh_token_generator, expires_generator
        )


def create_token_expires_in_generator(expires_in_conf=None):
    if isinstance(expires_in_conf, str):
        return import_string(expires_in_conf)

    data = {}
    data.update(BearerTokenGenerator.GRANT_TYPES_EXPIRES_IN)
    if isinstance(expires_in_conf, dict):
        data.update(expires_in_conf)

    def expires_in(client, grant_type):
        return data.get(grant_type, BearerTokenGenerator.DEFAULT_EXPIRES_IN)

    return expires_in


def create_token_generator(token_generator_conf, length=42):
    if callable(token_generator_conf):
        return token_generator_conf

    if isinstance(token_generator_conf, str):
        return import_string(token_generator_conf)
    elif token_generator_conf is True:

        def token_generator(*args, **kwargs):
            return generate_token(length)

        return token_generator
