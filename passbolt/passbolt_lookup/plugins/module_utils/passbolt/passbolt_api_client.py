from ansible_collections.passbolt.passbolt_lookup.plugins.module_utils.passbolt.account.passbolt_account import PassboltAccount
from ansible_collections.passbolt.passbolt_lookup.plugins.module_utils.passbolt.auth.jwt_auth_strategy import JWTAuthStrategy
from ansible_collections.passbolt.passbolt_lookup.plugins.module_utils.passbolt.entities.passbolt_resource import PassboltResource
from ansible_collections.passbolt.passbolt_lookup.plugins.module_utils.passbolt.services.resource_service import ResourceService


class PassboltAPIClient(object):
    def __init__(self, passbolt_account: PassboltAccount, verify: bool = True, timeout: int = 30):
        self.passbolt_account = passbolt_account
        self.verify = verify
        self.timeout = timeout
        self.auth_credentials = None
        self._resource_service = None

    def login(self) -> bool:
        auth_credentials = JWTAuthStrategy.login(self.passbolt_account, verify=self.verify, timeout=self.timeout)
        if auth_credentials is None:
            return False
        self.auth_credentials = auth_credentials
        return True

    def logout(self) -> bool:
        if self._resource_service:
            self._resource_service.clear_cache()
            self._resource_service = None
        auth_credentials = self.auth_credentials
        self.auth_credentials = None
        return JWTAuthStrategy.logout(self.passbolt_account, auth_credentials, verify = self.verify,
                                      timeout = self.timeout)



    def get_resource_by_id(self, resource_id: str) -> PassboltResource:
        if self.auth_credentials is None:
            raise RuntimeError("Not logged in. Call login() first.")

        if self._resource_service is None:
            self._resource_service = ResourceService(
                passbolt_account=self.passbolt_account,
                auth_credentials=self.auth_credentials,
                verify=self.verify,
                timeout=self.timeout
            )

        return self._resource_service.get_resource_by_id(resource_id)

    def get_resource(self, resource_id: str) -> dict:
        resource = self.get_resource_by_id(resource_id)
        return resource.to_dict()
