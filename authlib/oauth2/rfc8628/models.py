import time


class DeviceCredentialMixin:
    def get_client_id(self):
        raise NotImplementedError()

    def get_device_code(self):
        raise NotImplementedError()

    def get_scope(self):
        raise NotImplementedError()

    def get_user_code(self):
        raise NotImplementedError()

    def is_expired(self):
        raise NotImplementedError()

    def is_consumed(self):
        """Whether the device credential has already been consumed by a
        successful token request. Developers SHOULD re-implement it when the
        credential is persisted."""
        return False

    def consume(self):
        """Mark the device credential as consumed. The credential MUST NOT be
        consumed again in subsequent token requests. Developers SHOULD
        re-implement it when the credential is persisted; the default
        implementation is a no-op for backward compatibility."""


class DeviceCredentialDict(dict, DeviceCredentialMixin):
    def get_client_id(self):
        return self["client_id"]

    def get_device_code(self):
        return self.get("device_code")

    def get_scope(self):
        return self.get("scope")

    def get_user_code(self):
        return self["user_code"]

    def get_nonce(self):
        return self.get("nonce")

    def get_auth_time(self):
        return self.get("auth_time")

    def is_expired(self):
        expires_at = self.get("expires_at")
        if expires_at is not None:
            return expires_at < time.time()
        return False

    def is_consumed(self):
        return bool(self.get("consumed"))

    def consume(self):
        self["consumed"] = True
