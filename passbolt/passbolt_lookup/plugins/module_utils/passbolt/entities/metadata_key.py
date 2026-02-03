from dataclasses import dataclass
from typing import Optional
import uuid


@dataclass
class MetadataKey:
    id: uuid.UUID
    type: str

    def is_shared_key(self) -> bool:
        return self.type == "shared_key"
