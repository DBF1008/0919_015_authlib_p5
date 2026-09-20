from django.conf import settings
from django.http import HttpResponse
from django.utils.module_loading import import_string
from django.views.decorators.http import require_POST

from authlib.common.encoding import json_dumps
from authlib.common.security import generate_token as _generate_token
from authlib.oauth2 import AuthorizationServer as _AuthorizationServer
from authlib.oauth2.rfc6749.errors import OAuth2Error
from authlib.oauth2.rfc6750 import BearerTokenGenerator

from .requests import DjangoJsonRequest
from .requests import DjangoOAuth2Request
from .signals import client_authenticated
from .signals import token_revoked


class AuthorizationServer(_AuthorizationServer):
    """Django implementation of :class:`authlib.oauth2.rfc6749.AuthorizationServer`.
    Initialize it with client model and token model::

        from authlib.integrations.django_oauth2 import AuthorizationServer
        from your_project.models import OAuth2Client, OAuth2Token

        server = AuthorizationServer(OAuth2Client, OAuth2Token)
    """

    def __init__(self, client_model, token_model):
        super().__init__()
        self.client_model = client_model
        self.token_model = token_model
        self.load_config(getattr(settings, "AUTHLIB_OAUTH2_PROVIDER", {}))

    def load_config(self, config):
        self.config = config
        scopes_supported = self.config.get("scopes_supported")
        self.scopes_supported = scopes_supported
        # add default token generator
        self.register_token_generator("default", self.create_bearer_token_generator())

    def query_client(self, client_id):
        """Default method for ``AuthorizationServer.query_client``. Developers MAY
        rewrite this function to meet their own needs.
        """
        try:
            return self.client_model.objects.get(client_id=client_id)
        except self.client_model.DoesNotExist:
            return None

    def save_token(self, token, request):
        """Default method for ``AuthorizationServer.save_token``. Developers MAY
        rewrite this function to meet their own needs.
        """
        client = request.client
        if request.user:
            user_id = request.user.pk
        else:
            user_id = client.user_id
        item = self.token_model(client_id=client.client_id, user_id=user_id, **token)
        item.save()
        return item

    def create_oauth2_request(self, request):
        return DjangoOAuth2Request(request)

    def create_json_request(self, request):
        return DjangoJsonRequest(request)

    def handle_response(self, status_code, payload, headers):
        if isinstance(payload, dict):
            payload = json_dumps(payload)
        resp = HttpResponse(payload, status=status_code)
        for k, v in headers:
            resp[k] = v
        return resp

    def send_signal(self, name, *args, **kwargs):
        if name == "after_authenticate_client":
            client_authenticated.send(*args, sender=self.__class__, **kwargs)
        elif name == "after_revoke_token":
            token_revoked.send(*args, sender=self.__class__, **kwargs)

    def register_device_code_grant(
        self, device_authorization_endpoint, device_code_grant
    ):
        """Register the OAuth 2.0 Device Authorization Grant (RFC 8628).

        It registers both the ``DeviceCodeGrant`` token grant and the
        ``DeviceAuthorizationEndpoint``. Unlike the authorization endpoint,
        the device authorization endpoint only accepts POST requests and
        responds with JSON (``device_code``, ``user_code``,
        ``verification_uri``, ``expires_in`` and ``interval``) instead of an
        OAuth redirect.

        Wire the returned POST-only views in the project ``urls.py``::

            from authlib.integrations.django_oauth2 import AuthorizationServer

            server = AuthorizationServer(OAuth2Client, OAuth2Token)
            server.register_device_code_grant(
                DeviceAuthorizationEndpoint, DeviceCodeGrant
            )

            urlpatterns = [
                path(
                    "device_authorization",
                    server.device_authorization_view,
                ),
                path(
                    "device_verification",
                    server.device_verification_view,
                ),
            ]

        :param device_authorization_endpoint: a ``DeviceAuthorizationEndpoint``
            subclass.
        :param device_code_grant: a ``DeviceCodeGrant`` subclass.
        """
        self.register_grant(device_code_grant)
        self.register_endpoint(device_authorization_endpoint)

    @property
    def device_authorization_view(self):
        """POST-only view for the device authorization endpoint."""

        @require_POST
        def device_authorization(request):
            return self.create_endpoint_response("device_authorization", request)

        return device_authorization

    def device_verification_view(self, request):
        """View for the end-user verification (confirmation) page.

        The default implementation approves every authenticated request;
        projects typically wrap it to inject the current user and the end
        user's decision::

            def device_verification(request):
                if request.POST.get("decision") == "deny":
                    grant_user = None
                else:
                    grant_user = request.user
                return server.create_device_authorization_response(
                    grant_user, request
                )
        """
        return self.create_device_authorization_response(request.user, request)

    def create_device_authorization_response(self, grant_user, request):
        """Create the response for the end-user verification (confirmation)
        page of the device authorization grant. Pass the authenticated end
        user when the end user approves the request, or ``None`` when denying
        it. The endpoint responds with JSON and is idempotent: a
        ``user_code`` can only be confirmed once, repeated confirmations
        return the recorded decision without overwriting it.
        """
        from authlib.oauth2.rfc8628 import DeviceAuthorizationEndpoint

        oauth2_request = self.create_oauth2_request(request)
        endpoint = self._endpoints[DeviceAuthorizationEndpoint.ENDPOINT_NAME][0]
        try:
            args = endpoint.create_authorization_response(
                oauth2_request, grant_user, grant_user=grant_user
            )
            return self.handle_response(*args)
        except OAuth2Error as error:
            return self.handle_error_response(oauth2_request, error)

    def create_bearer_token_generator(self):
        """Default method to create BearerToken generator."""
        conf = self.config.get("access_token_generator", True)
        access_token_generator = create_token_generator(conf, 42)

        conf = self.config.get("refresh_token_generator", False)
        refresh_token_generator = create_token_generator(conf, 48)

        conf = self.config.get("token_expires_in")
        expires_generator = create_token_expires_in_generator(conf)

        return BearerTokenGenerator(
            access_token_generator=access_token_generator,
            refresh_token_generator=refresh_token_generator,
            expires_generator=expires_generator,
        )


def create_token_generator(token_generator_conf, length=42):
    if callable(token_generator_conf):
        return token_generator_conf

    if isinstance(token_generator_conf, str):
        return import_string(token_generator_conf)
    elif token_generator_conf is True:

        def token_generator(*args, **kwargs):
            return _generate_token(length)

        return token_generator


def create_token_expires_in_generator(expires_in_conf=None):
    data = {}
    data.update(BearerTokenGenerator.GRANT_TYPES_EXPIRES_IN)
    if expires_in_conf:
        data.update(expires_in_conf)

    def expires_in(client, grant_type):
        return data.get(grant_type, BearerTokenGenerator.DEFAULT_EXPIRES_IN)

    return expires_in
