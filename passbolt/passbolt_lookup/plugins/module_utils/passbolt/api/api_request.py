from http import HTTPMethod

from ansible_collections.passbolt.passbolt_lookup.plugins.module_utils.passbolt.auth.auth_credentials import \
    AuthCredentials


class APIRequest(object):
    def __init__(self, method: HTTPMethod, uri: str, auth_credentials: AuthCredentials = None, body: dict = None,
                 verify: bool = False, timeout: int = 30):
        self.method = method
        self.uri = uri
        self.auth_credentials = auth_credentials
        self.body = body
        self.verify = verify
        self.timeout = timeout
