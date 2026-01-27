import json
import re
from http import HTTPMethod
from typing import Optional
from urllib.parse import urljoin
import requests
import jsonschema

from ansible_collections.passbolt.passbolt_lookup.plugins.module_utils.passbolt.account.passbolt_account import \
    PassboltAccount
from ansible_collections.passbolt.passbolt_lookup.plugins.module_utils.passbolt.api.api_request import APIRequest
from ansible_collections.passbolt.passbolt_lookup.plugins.module_utils.passbolt.api.api_response import APIResponse
from ansible_collections.passbolt.passbolt_lookup.plugins.module_utils.passbolt.api.exceptions.resource_exceptions import (
    ResourceNotFound,
    ResourceDeleted,
    SecretShareMissing,
    MetadataMissing,
    MetadataKeyNotShared,
    DecryptError,
    IntegrityError,
    SchemaValidationError,
    InvalidResourceId,
)
from ansible_collections.passbolt.passbolt_lookup.plugins.module_utils.passbolt.auth.auth_credentials import \
    AuthCredentials
from ansible_collections.passbolt.passbolt_lookup.plugins.module_utils.passbolt.cryptography.gnupg_service import \
    GnuPGService
from ansible_collections.passbolt.passbolt_lookup.plugins.module_utils.passbolt.cryptography.exceptions.gnupg_exception import \
    GnuPGException
from ansible_collections.passbolt.passbolt_lookup.plugins.module_utils.passbolt.entities.passbolt_resource import \
    PassboltResource
from ansible_collections.passbolt.passbolt_lookup.plugins.module_utils.passbolt.http.http_client_service import \
    HTTPClientService


class ResourceService:
    UUID_V4_PATTERN = re.compile(
        r'^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$',
        re.IGNORECASE
    )

    METADATA_KEY_TYPE_USER = "user_key"
    METADATA_KEY_TYPE_SHARED = "shared_key"
    VALID_METADATA_KEY_TYPES = {METADATA_KEY_TYPE_USER, METADATA_KEY_TYPE_SHARED}

    METADATA_SCHEMA = {
        "type": "object",
        "required": ["object_type", "name"],
        "properties": {
            "object_type": {"type": "string", "const": "PASSBOLT_RESOURCE_METADATA"},
            "name": {"type": "string", "minLength": 1, "maxLength": 255},
            "uris": {"type": "array", "items": {"type": "string"}},
            "uri": {"type": "string"},
            "username": {"type": "string"},
            "description": {"type": ["string", "null"]},
            "icon": {
                "type": ["object", "null"],
                "properties": {
                    "url": {"type": "string"},
                    "hash": {"type": "string"}
                }
            }
        }
    }

    SECRET_SCHEMA = {
        "type": "object",
        "properties": {
            "password": {"type": "string"},
            "username": {"type": "string"},
            "description": {"type": ["string", "null"]},
            "totp": {
                "type": ["object", "null"],
                "properties": {
                    "secret_key": {"type": "string"},
                    "algorithm": {"type": "string"},
                    "digits": {"type": "integer"},
                    "period": {"type": "integer"}
                }
            },
            "custom_fields": {"type": "object"}
        }
    }

    def __init__(
        self,
        passbolt_account: PassboltAccount,
        auth_credentials: AuthCredentials,
        verify: bool = True,
        timeout: int = 30
    ):
        self.passbolt_account = passbolt_account
        self.auth_credentials = auth_credentials
        self.verify = verify
        self.timeout = timeout
        self._metadata_key_cache: dict[str, Optional[str]] = {}


    def get_resource_by_id(self, resource_id: str) -> PassboltResource:
        self._validate_resource_id(resource_id)
        api_response = self._fetch_resource(resource_id)
        resource_body = self._validate_response(api_response, resource_id)
        metadata = self._decrypt_metadata(resource_body)
        secret = self._decrypt_secret(resource_body)

        return PassboltResource.from_decrypted_data(
            metadata=metadata,
            secret=secret,
            resource_id=resource_id,
            resource_type_id=resource_body.get("resource_type_id")
        )

    def _validate_resource_id(self, resource_id: str) -> None:
        if not resource_id or not self.UUID_V4_PATTERN.match(resource_id):
            raise InvalidResourceId(f"Invalid resource ID format: '{resource_id}'. Expected UUIDv4.")

    def _fetch_resource(self, resource_id: str) -> APIResponse:
        url = urljoin(
            self.passbolt_account.fullbase_url,
            f"resources/{resource_id}.json?contain[secret]=1"
        )

        api_request = APIRequest(
            HTTPMethod.GET,
            url,
            auth_credentials=self.auth_credentials,
            verify=self.verify,
            timeout=self.timeout
        )

        return HTTPClientService.send(api_request)

    def _validate_response(self, api_response: APIResponse, resource_id: str) -> dict:
        if api_response.http_status_code == 404:
            raise ResourceNotFound(f"Resource '{resource_id}' not found.")

        if api_response.http_status_code == 401:
            raise ResourceNotFound(f"Authentication required to access resource '{resource_id}'.")

        if api_response.http_status_code == 403:
            raise ResourceNotFound(f"Access denied to resource '{resource_id}'.")

        if not api_response.is_success():
            raise ResourceNotFound(
                f"Failed to fetch resource '{resource_id}'. HTTP {api_response.http_status_code}"
            )

        body = api_response.body

        if body.get("id") != resource_id:
            raise IntegrityError(
                f"Resource ID mismatch. Requested '{resource_id}' but received '{body.get('id')}'."
            )

        if body.get("deleted"):
            raise ResourceDeleted(f"Resource '{resource_id}' has been deleted.")

        return body

    def _decrypt_metadata(self, resource_body: dict) -> dict:
        encrypted_metadata = resource_body.get("metadata")
        if not encrypted_metadata:
            raise MetadataMissing("Resource has no encrypted metadata.")

        metadata_key_type = resource_body.get("metadata_key_type")

        if metadata_key_type not in self.VALID_METADATA_KEY_TYPES:
            raise MetadataMissing(
                f"Invalid metadata_key_type: '{metadata_key_type}'. "
                f"Expected one of: {self.VALID_METADATA_KEY_TYPES}"
            )

        if metadata_key_type == self.METADATA_KEY_TYPE_USER:
            decryption_passphrase = self.passbolt_account.passphrase
        else:
            metadata_key_id = resource_body.get("metadata_key_id")
            if not metadata_key_id:
                raise MetadataMissing("Resource uses shared_key but metadata_key_id is missing.")
            self._get_metadata_private_key(metadata_key_id)
            decryption_passphrase = None

        try:
            decrypted_json = GnuPGService.decrypt(encrypted_metadata, decryption_passphrase)
        except GnuPGException as e:
            raise DecryptError(f"Failed to decrypt metadata: {e}")

        try:
            metadata = json.loads(decrypted_json)
        except json.JSONDecodeError as e:
            raise DecryptError(f"Decrypted metadata is not valid JSON: {e}")

        try:
            jsonschema.validate(metadata, self.METADATA_SCHEMA)
        except jsonschema.ValidationError as e:
            raise SchemaValidationError(f"Metadata schema validation failed: {e.message}")

        return metadata

    def _get_metadata_private_key(self, metadata_key_id: str) -> str:
        if metadata_key_id in self._metadata_key_cache:
            return self._metadata_key_cache[metadata_key_id]

        url = urljoin(
            self.passbolt_account.fullbase_url,
            "metadata/keys.json?contain[metadata_private_keys]=1"
        )

        headers = {"Authorization": f"Bearer {self.auth_credentials.access_token}"}
        response = requests.get(url, headers=headers, verify=self.verify, timeout=self.timeout)

        if response.status_code != 200:
            raise MetadataKeyNotShared(
                f"Failed to fetch metadata keys. HTTP {response.status_code}"
            )

        json_response = response.json()
        metadata_keys = json_response.get("body", [])

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
            raise MetadataKeyNotShared(
                f"Metadata key '{metadata_key_id}' is not shared with user '{self.passbolt_account.id}'."
            )

        try:
            decrypted_json = GnuPGService.decrypt(
                user_private_key_data,
                self.passbolt_account.passphrase
            )
        except GnuPGException as e:
            raise DecryptError(f"Failed to decrypt metadata private key: {e}")

        try:
            key_data = json.loads(decrypted_json)
            armored_key = key_data.get("armored_key")
            if not armored_key:
                raise DecryptError("Decrypted metadata key JSON missing 'armored_key' field.")
        except json.JSONDecodeError as e:
            raise DecryptError(f"Decrypted metadata key is not valid JSON: {e}")

        try:
            fingerprints = GnuPGService.import_key(armored_key, None)
            if not fingerprints:
                raise DecryptError("Failed to import decrypted metadata key to keyring.")
        except Exception as e:
            raise DecryptError(f"Failed to import metadata private key: {e}")

        self._metadata_key_cache[metadata_key_id] = None

        return None

    def _decrypt_secret(self, resource_body: dict) -> dict:
        secrets = resource_body.get("secrets", [])

        if not secrets:
            raise SecretShareMissing(f"Resource '{resource_body.get('id')}' has no secrets.")

        user_secret = None
        for secret in secrets:
            if secret.get("user_id") == self.passbolt_account.id:
                user_secret = secret
                break

        if not user_secret:
            raise SecretShareMissing(f"No secret share found for user '{self.passbolt_account.id}'.")

        encrypted_secret = user_secret.get("data")
        if not encrypted_secret:
            raise SecretShareMissing("Secret data is empty.")

        if not encrypted_secret.strip().startswith("-----BEGIN PGP MESSAGE-----"):
            raise DecryptError("Secret data is not valid PGP armor.")

        try:
            decrypted_json = GnuPGService.decrypt(
                encrypted_secret,
                self.passbolt_account.passphrase
            )
        except GnuPGException as e:
            raise DecryptError(f"Failed to decrypt secret: {e}")

        try:
            secret = json.loads(decrypted_json)
        except json.JSONDecodeError as e:
            raise DecryptError(f"Decrypted secret is not valid JSON: {e}")

        try:
            jsonschema.validate(secret, self.SECRET_SCHEMA)
        except jsonschema.ValidationError as e:
            raise SchemaValidationError(f"Secret schema validation failed: {e.message}")

        return secret

    def clear_cache(self) -> None:
        self._metadata_key_cache.clear()
