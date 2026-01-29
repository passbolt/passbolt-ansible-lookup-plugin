from ansible_collections.passbolt.passbolt_lookup.plugins.module_utils.passbolt.account.passbolt_account import PassboltAccount
from ansible_collections.passbolt.passbolt_lookup.plugins.module_utils.passbolt.auth.jwt_auth_strategy import JWTAuthStrategy


class PassboltAPIClient(object):
    def __init__(self, passbolt_account: PassboltAccount, verify: bool = True, timeout: int = 30):
        self.passbolt_account = passbolt_account
        self.verify = verify
        self.timeout = timeout
        self.auth_credentials = None

    def login(self) -> bool:
        auth_credentials = JWTAuthStrategy.login(self.passbolt_account, verify = self.verify, timeout = self.timeout)
        if auth_credentials is None:
            return False
        self.auth_credentials = auth_credentials
        return True

    def logout(self) -> bool:
        raise NotImplementedError()

    def get_resource(self) -> None:
        raise NotImplementedError()