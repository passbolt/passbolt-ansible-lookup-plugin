from abc import ABC, abstractmethod


class AuthCredentials(ABC):
    def headers(self) -> dict[str, str]:
        pass