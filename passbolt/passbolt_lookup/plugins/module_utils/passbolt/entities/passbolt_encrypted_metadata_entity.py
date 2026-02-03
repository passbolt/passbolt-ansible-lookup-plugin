from abc import ABC
from typing import Optional

from ansible_collections.passbolt.passbolt_lookup.plugins.module_utils.passbolt.entities.passbolt_entity import PassboltEntity
from ansible_collections.passbolt.passbolt_lookup.plugins.module_utils.passbolt.entities.metadata_key import MetadataKey


class PassboltEncryptedMetadataEntity(PassboltEntity, ABC):
    """Interface for entities with encrypted metadata."""

    metadata_key: Optional[MetadataKey] = None
