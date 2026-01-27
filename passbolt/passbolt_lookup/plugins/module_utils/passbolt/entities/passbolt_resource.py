from dataclasses import dataclass, field
from typing import Optional


@dataclass
class PassboltResourceIcon:
    url: Optional[str] = None
    hash: Optional[str] = None


@dataclass
class PassboltResource:
    name: str
    username: Optional[str] = None
    password: Optional[str] = None
    note: Optional[str] = None
    description: Optional[str] = None
    uris: list[str] = field(default_factory=list)
    custom_fields: dict = field(default_factory=dict)
    totp: Optional[dict] = None
    icon: Optional[PassboltResourceIcon] = None
    resource_id: Optional[str] = None
    resource_type_id: Optional[str] = None

    def to_dict(self) -> dict:
        result = {
            "name": self.name,
            "username": self.username,
            "password": self.password,
            "note": self.note,
            "description": self.description,
            "uris": self.uris,
            "custom_fields": self.custom_fields,
            "totp": self.totp,
        }

        if self.icon:
            result["icon"] = {
                "url": self.icon.url,
                "hash": self.icon.hash,
            }
        else:
            result["icon"] = None

        return result

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
        description = metadata.get("description")

        if not uris and "uri" in metadata:
            uri = metadata.get("uri")
            if uri:
                uris = [uri]

        password = secret.get("password")
        username = secret.get("username")
        note = secret.get("description")
        totp = secret.get("totp")

        custom_fields = {}
        if "custom_fields" in secret:
            custom_fields = secret.get("custom_fields", {})

        icon = None
        if "icon" in metadata and metadata["icon"]:
            icon_data = metadata["icon"]
            icon = PassboltResourceIcon(
                url=icon_data.get("url"),
                hash=icon_data.get("hash")
            )

        return cls(
            name=name,
            username=username,
            password=password,
            note=note,
            description=description,
            uris=uris,
            custom_fields=custom_fields,
            totp=totp,
            icon=icon,
            resource_id=resource_id,
            resource_type_id=resource_type_id
        )
