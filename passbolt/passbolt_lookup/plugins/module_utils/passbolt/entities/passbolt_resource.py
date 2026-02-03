from dataclasses import dataclass, field
from typing import Optional
import uuid

from ansible_collections.passbolt.passbolt_lookup.plugins.module_utils.passbolt.entities.passbolt_encrypted_metadata_entity import PassboltEncryptedMetadataEntity
from ansible_collections.passbolt.passbolt_lookup.plugins.module_utils.passbolt.entities.metadata_key import MetadataKey


@dataclass
class PassboltResourceType:
    id: str
    slug: Optional[str] = None
    name: Optional[str] = None
    description: Optional[str] = None
    deleted: bool = False
    created: Optional[str] = None
    modified: Optional[str] = None


@dataclass
class PassboltResource(PassboltEncryptedMetadataEntity):
    id: Optional[uuid.UUID] = None
    name: Optional[str] = None
    username: Optional[str] = None
    description: Optional[str] = None
    note: Optional[str] = None
    password: Optional[str] = None
    uris: list[str] = field(default_factory=list)
    custom_fields: dict[str, str] = field(default_factory=dict)
    resource_type: Optional[PassboltResourceType] = None
    metadata_key: Optional[MetadataKey] = None
    icon: Optional[dict] = None
    totp: Optional[dict] = None

    def is_shared(self) -> bool:
        return self.metadata_key.is_shared_key() if self.metadata_key else False

    def to_dict(self) -> dict:
        """Return human-focused dictionary representation, omitting null/empty fields."""
        result = {}

        if self.name:
            result["name"] = self.name
        if self.username:
            result["username"] = self.username
        if self.password:
            result["password"] = self.password
        if self.description:
            result["description"] = self.description
        if self.note:
            result["note"] = self.note
        if self.uris:
            result["uris"] = self.uris
        if self.totp:
            result["totp"] = self.totp
        if self.custom_fields:
            result["custom_fields"] = self.custom_fields

        return result

    @classmethod
    def from_api_json(
        cls,
        data: dict,
        decrypted_metadata: dict,
        decrypted_secret: Optional[dict] = None,
    ) -> "PassboltResource":
        """Create resource from API JSON response with decrypted metadata and secret."""
        resource_id = data.get("id")
        resource_type_id = data.get("resource_type_id")
        metadata_key_id = data.get("metadata_key_id")
        metadata_key_type = data.get("metadata_key_type")

        name = decrypted_metadata.get("name")
        uris = decrypted_metadata.get("uris", [])
        if not uris and "uri" in decrypted_metadata:
            uri = decrypted_metadata.get("uri")
            if uri:
                uris = [uri]

        username = decrypted_metadata.get("username")
        description = decrypted_metadata.get("description")
        icon = decrypted_metadata.get("icon")

        password = None
        note = None
        totp = None
        custom_fields = {}

        if decrypted_secret:
            password = decrypted_secret.get("password")
            note = decrypted_secret.get("description")
            totp = decrypted_secret.get("totp")

            metadata_cf = decrypted_metadata.get("custom_fields") or []
            secret_cf = decrypted_secret.get("custom_fields") or []
            for meta_field in metadata_cf:
                cf_id = meta_field.get("id")
                cf_key = meta_field.get("metadata_key", cf_id)
                cf_value = None
                for secret_field in secret_cf:
                    if secret_field.get("id") == cf_id:
                        cf_value = secret_field.get("secret_value")
                        break
                custom_fields[cf_key] = cf_value

        resource_type = None
        if resource_type_id:
            resource_type = PassboltResourceType(id=resource_type_id)

        metadata_key = None
        if metadata_key_id and metadata_key_type:
            metadata_key = MetadataKey(
                id=uuid.UUID(metadata_key_id),
                type=metadata_key_type
            )

        return cls(
            id=uuid.UUID(resource_id) if resource_id else None,
            name=name,
            username=username,
            description=description,
            note=note,
            password=password,
            uris=uris,
            custom_fields=custom_fields,
            resource_type=resource_type,
            metadata_key=metadata_key,
            icon=icon,
            totp=totp,
        )
