from abc import ABC, abstractmethod

from ansible_collections.passbolt.passbolt_lookup.plugins.module_utils.passbolt.account.passbolt_account import PassboltAccount
from ansible_collections.passbolt.passbolt_lookup.plugins.module_utils.passbolt.auth.auth_credentials import AuthCredentials


class AuthStrategy(ABC):
    @classmethod
    @abstractmethod
    def login(cls, passbolt_account: PassboltAccount, verify: bool) -> AuthCredentials:
        pass

    @classmethod
    @abstractmethod
    def logout(cls, passbolt_account: PassboltAccount, auth_credentials: AuthCredentials, verify: bool) -> None:
        pass