from typing import Optional
import uuid

from ansible_collections.passbolt.passbolt_lookup.plugins.module_utils.passbolt.entities.passbolt_entity import PassboltEntity


class PassboltAccount(PassboltEntity):
    _api_json_schema: Optional[dict] = None

    def __init__(self, id: str, key_id: str, email: str, passphrase: str, fullbase_url: str, server_key_id: str):
        self.id = id
        self.key_id = key_id
        self.email = email
        self.passphrase = passphrase
        self.fullbase_url = fullbase_url
        self.server_key_id = server_key_id

    @classmethod
    def from_api_json(cls, data: dict) -> "PassboltAccount":
        """Create account from API JSON response."""
        raise NotImplementedError("PassboltAccount is created via PassboltAccountKitFactory")
