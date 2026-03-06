import json
import jsonschema
from http import HTTPMethod
from typing import Optional
from urllib.parse import urljoin
import uuid

from ansible_collections.passbolt.passbolt_lookup.plugins.module_utils.passbolt.account.passbolt_account import PassboltAccount
from ansible_collections.passbolt.passbolt_lookup.plugins.module_utils.passbolt.api.api_request import APIRequest
from ansible_collections.passbolt.passbolt_lookup.plugins.module_utils.passbolt.auth.jwt_auth_strategy import JWTAuthStrategy
from ansible_collections.passbolt.passbolt_lookup.plugins.module_utils.passbolt.auth.auth_credentials import AuthCredentials
from ansible_collections.passbolt.passbolt_lookup.plugins.module_utils.passbolt.cryptography.gnupg_service import GnuPGService
from ansible_collections.passbolt.passbolt_lookup.plugins.module_utils.passbolt.entities.passbolt_resource import PassboltResource
from ansible_collections.passbolt.passbolt_lookup.plugins.module_utils.passbolt.http.http_client_service import HTTPClientService


class PassboltAPIClient:
    METADATA_KEY_TYPE_USER = "user_key"
    METADATA_KEY_TYPE_SHARED = "shared_key"
    USER_RESPONSE_SCHEMA = {
        "type": "object",
        "required": [
            "id",
            "active",
            "gpgkey"
        ],
        "properties": {
            "id": {
                "type": "string",
                "format": "uuid",
            },
            "active": {
                "type": "boolean",
            },
            "gpgkey": {
                "type": "object",
                "required": [
                    "armored_key",
                    "fingerprint",
                ],
                "properties": {
                    "armored_key": {
                        "type": "string",
                    },
                    "fingerprint": {
                        "type": "string",
                    }
                }
            },
        },
    }

    def __init__(self, passbolt_account: PassboltAccount, verify: bool = True, timeout: int = 30):
        self.passbolt_account = passbolt_account
        self.verify = verify
        self.timeout = timeout
        self.auth_credentials: Optional[AuthCredentials] = None
        self._metadata_key_cache: dict[str, str] = {}

    def login(self) -> bool:
        auth_credentials = JWTAuthStrategy.login(
            self.passbolt_account,
            verify=self.verify,
            timeout=self.timeout
        )
        if auth_credentials is None:
            return False
        self.auth_credentials = auth_credentials
        return True

    def logout(self) -> bool:
        self._metadata_key_cache.clear()
        auth_credentials = self.auth_credentials
        self.auth_credentials = None
        return JWTAuthStrategy.logout(
            self.passbolt_account,
            auth_credentials,
            verify=self.verify,
            timeout=self.timeout
        )

    def get_resource(self, id: uuid.UUID) -> PassboltResource:
        if self.auth_credentials is None:
            raise RuntimeError("Not logged in. Call login() first.")

        resource_body = self._fetch_resource(id)
        metadata = self._decrypt_metadata(resource_body)
        secret = self._decrypt_secret(resource_body)

        return PassboltResource.from_api_json(
            data=resource_body,
            decrypted_metadata=metadata,
            decrypted_secret=secret,
        )

    def _fetch_resource(self, id: uuid.UUID) -> dict:
        url = urljoin(
            self.passbolt_account.fullbase_url,
            f"resources/{id}.json?contain[secret]=1"
        )

        api_request = APIRequest(
            HTTPMethod.GET,
            url,
            auth_credentials=self.auth_credentials,
            verify=self.verify,
            timeout=self.timeout
        )

        api_response = HTTPClientService.send(api_request)

        if api_response.http_status_code == 404:
            raise LookupError(f"Resource '{id}' not found.")

        if not api_response.is_success():
            raise RuntimeError(
                f"Failed to fetch resource '{id}'. HTTP {api_response.http_status_code}"
            )

        body = api_response.body

        if body.get("deleted"):
            raise LookupError(f"Resource '{id}' has been deleted.")

        return body

    def _decrypt_metadata(self, resource_body: dict) -> dict:
        encrypted_metadata = resource_body.get("metadata")
        if not encrypted_metadata:
            raise ValueError("Resource has no encrypted metadata.")

        metadata_key_type = resource_body.get("metadata_key_type")

        if metadata_key_type == self.METADATA_KEY_TYPE_USER:
            decryption_passphrase = self.passbolt_account.passphrase
            metadata_key_fingerprint = self.passbolt_account.key_id
        elif metadata_key_type == self.METADATA_KEY_TYPE_SHARED:
            metadata_key_id = resource_body.get("metadata_key_id")
            if not metadata_key_id:
                raise ValueError("Resource uses shared_key but metadata_key_id is missing.")
            metadata_key_fingerprint = self._import_metadata_private_key(metadata_key_id)
            decryption_passphrase = None
        else:
            raise ValueError(f"Invalid metadata_key_type: '{metadata_key_type}'")

        decrypted_json = GnuPGService.decrypt_and_verify(encrypted_metadata, decryption_passphrase,
                                                         metadata_key_fingerprint)
        return json.loads(decrypted_json)

    def _import_metadata_private_key(self, metadata_key_id: str) -> str:
        if metadata_key_id not in self._metadata_key_cache:
            url = urljoin(
                self.passbolt_account.fullbase_url,
                "metadata/keys.json?contain[metadata_private_keys]=1"
            )

            api_request = APIRequest(
                HTTPMethod.GET,
                url,
                auth_credentials=self.auth_credentials,
                verify=self.verify,
                timeout=self.timeout
            )
            api_response = HTTPClientService.send(api_request)

            if not api_response.is_success():
                raise RuntimeError(f"Failed to fetch metadata keys. HTTP {api_response.http_status_code}")

            metadata_keys = api_response.body or []

            user_private_key_data = None
            for mk in metadata_keys:
                if mk.get("id") == metadata_key_id:
                    private_keys = mk.get("metadata_private_keys", [])
                    for pk in private_keys:
                        if (pk.get("user_id") == self.passbolt_account.id and
                            pk.get("metadata_key_id") == metadata_key_id):
                            user_private_key_data = pk.get("data")
                            break
                    break

            if not user_private_key_data:
                raise LookupError(
                    f"Metadata key '{metadata_key_id}' is not shared with user."
                )

            decrypted_json = GnuPGService.decrypt_and_verify(
                user_private_key_data,
                self.passbolt_account.passphrase,
                self.passbolt_account.key_id
            )

            key_data = json.loads(decrypted_json)
            armored_key = key_data.get("armored_key")
            if not armored_key:
                raise ValueError("Decrypted metadata key missing 'armored_key' field.")

            metadata_key_fingerprints = GnuPGService.import_key(armored_key, None)
            if len(metadata_key_fingerprints) != 2:
                raise RuntimeError("Expected 2 keys to be imported when importing metadata key, got %s" %
                                   len(metadata_key_fingerprints))
            if metadata_key_fingerprints[0] != metadata_key_fingerprints[1]:
                raise RuntimeError("Expected metadata public and private key fingerprint to match but didn't.")

            self._metadata_key_cache[metadata_key_id] = metadata_key_fingerprints[0]
        return self._metadata_key_cache[metadata_key_id]

    def _decrypt_secret(self, resource_body: dict) -> Optional[dict]:
        secrets = resource_body.get("secrets", [])
        if not secrets:
            return None

        user_secret = None
        for secret in secrets:
            if secret.get("user_id") == self.passbolt_account.id:
                user_secret = secret
                break

        if not user_secret:
            return None

        encrypted_secret = user_secret.get("data")
        if not encrypted_secret:
            return None

        if resource_body.get("personal"):
            secret_signature_fingerprint = self.passbolt_account.key_id
        else:
            modified_id = uuid.UUID(user_secret.get("modified_by", ""))
            url = urljoin(
                self.passbolt_account.fullbase_url,
                f"users/{modified_id}.json"
            )

            api_request = APIRequest(
                HTTPMethod.GET,
                url,
                auth_credentials=self.auth_credentials,
                verify=self.verify,
                timeout=self.timeout
            )
            api_response = HTTPClientService.send(api_request)

            if not api_response.is_success():
                raise RuntimeError(f"Failed to fetch resource modifier. HTTP {api_response.http_status_code}")
            user = api_response.body
            try:
                jsonschema.validate(user, self.USER_RESPONSE_SCHEMA)
            except jsonschema.ValidationError:
                raise ValueError("User schema validation failed.")

            if not user.get("active"):
                raise RuntimeError("User is not active.")

            user_gpg_key = user.get("gpgkey")
            imported_modifier_key_fingerprints = GnuPGService.import_key(user_gpg_key.get("armored_key"), None)
            if len(imported_modifier_key_fingerprints) != 1:
                raise RuntimeError("Expected 1 key to be imported when importing modifier key, got %s"
                                   % len(imported_modifier_key_fingerprints))
            if user_gpg_key.get("fingerprint") != imported_modifier_key_fingerprints[0]:
                raise RuntimeError("Modifier key fingerprint does not match imported fingerprint.")
            secret_signature_fingerprint = user_gpg_key.get("fingerprint")

        decrypted_json = GnuPGService.decrypt_and_verify(
            encrypted_secret,
            self.passbolt_account.passphrase,
            secret_signature_fingerprint
        )

        return json.loads(decrypted_json)
