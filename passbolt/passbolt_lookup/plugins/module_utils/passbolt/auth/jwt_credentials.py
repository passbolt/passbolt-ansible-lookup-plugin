from ansible_collections.passbolt.passbolt_lookup.plugins.module_utils.passbolt.auth.auth_credentials import AuthCredentials

class JWTCredentials(AuthCredentials):
    def __init__(self, access_token: str, refresh_token: str):
        self.access_token = access_token
        self.refresh_token = refresh_token

    def headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.access_token}"}
