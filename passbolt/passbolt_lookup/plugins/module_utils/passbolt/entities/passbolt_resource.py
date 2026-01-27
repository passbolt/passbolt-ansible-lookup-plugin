from dataclasses import dataclass, field
from typing import Optional, Any


@dataclass
class PassboltResourceIcon:
    url: Optional[str] = None
    hash: Optional[str] = None


@dataclass
class PassboltResource:
    name: str
    username: Optional[str] = None
    description: Optional[str] = None
    uris: list[str] = field(default_factory=list)
    icon: Optional[dict] = None
    metadata_custom_fields: list[dict] = field(default_factory=list)
    password: Optional[str] = None
    secret_description: Optional[str] = None
    totp: Optional[dict] = None
    secret_custom_fields: list[dict] = field(default_factory=list)
    resource_id: Optional[str] = None
    resource_type_id: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "metadata": {
                "name": self.name,
                "username": self.username,
                "description": self.description,
                "uris": self.uris,
                "icon": self.icon,
                "custom_fields": self.metadata_custom_fields,
            },
            "secret": {
                "password": self.password,
                "description": self.secret_description,
                "totp": self.totp,
                "custom_fields": self.secret_custom_fields,
            }
        }

    @classmethod
    def from_decrypted_data(
        cls,
        metadata: dict,
        secret: dict,
        resource_id: str,
        resource_type_id: Optional[str] = None
    ) -> "PassboltResource":
        name = metadata.get("name", "")
        uris = metadata.get("uris", [])
        if not uris and "uri" in metadata:
            uri = metadata.get("uri")
            if uri:
                uris = [uri]

        username = metadata.get("username")
        description = metadata.get("description")
        icon = metadata.get("icon")
        metadata_custom_fields = metadata.get("custom_fields", [])

        password = secret.get("password")
        secret_description = secret.get("description")
        totp = secret.get("totp")
        secret_custom_fields = secret.get("custom_fields", [])

        return cls(
            name=name,
            username=username,
            description=description,
            uris=uris,
            icon=icon,
            metadata_custom_fields=metadata_custom_fields,
            password=password,
            secret_description=secret_description,
            totp=totp,
            secret_custom_fields=secret_custom_fields,
            resource_id=resource_id,
            resource_type_id=resource_type_id
        )
