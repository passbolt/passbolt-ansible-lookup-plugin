from abc import ABC, abstractmethod
from typing import Optional
import uuid


class PassboltEntity(ABC):
    """Base interface for all Passbolt entities."""

    id: Optional[uuid.UUID] = None

    @classmethod
    @abstractmethod
    def from_api_json(cls, data: dict) -> "PassboltEntity":
        """Create entity from API JSON response."""
        pass
