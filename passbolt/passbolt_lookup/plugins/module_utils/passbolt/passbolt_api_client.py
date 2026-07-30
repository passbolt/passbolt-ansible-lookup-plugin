import json
import jsonschema
from http import HTTPMethod
from typing import Iterator, Optional
from urllib.parse import urljoin
import uuid

from ansible.utils.display import Display

from ansible_collections.passbolt.passbolt_lookup.plugins.module_utils.passbolt.account.passbolt_account import PassboltAccount
from ansible_collections.passbolt.passbolt_lookup.plugins.module_utils.passbolt.api.api_request import APIRequest
from ansible_collections.passbolt.passbolt_lookup.plugins.module_utils.passbolt.api.api_response import APIResponse
from ansible_collections.passbolt.passbolt_lookup.plugins.module_utils.passbolt.auth.jwt_auth_strategy import JWTAuthStrategy
from ansible_collections.passbolt.passbolt_lookup.plugins.module_utils.passbolt.auth.auth_credentials import AuthCredentials
from ansible_collections.passbolt.passbolt_lookup.plugins.module_utils.passbolt.cryptography.exceptions.gnupg_exception import GnuPGException
from ansible_collections.passbolt.passbolt_lookup.plugins.module_utils.passbolt.cryptography.gnupg_service import GnuPGService
from ansible_collections.passbolt.passbolt_lookup.plugins.module_utils.passbolt.entities.passbolt_resource import PassboltResource
from ansible_collections.passbolt.passbolt_lookup.plugins.module_utils.passbolt.http.http_client_service import HTTPClientService

display = Display()


SCAN_PAGE_SIZE = 500
SCAN_MAX_PAGES = 10000


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
        self._session_key_cache: dict[str, str] = {}
        self._session_keys_loaded: bool = False

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
        self._session_key_cache.clear()
        self._session_keys_loaded = False
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

    def list_resources(self, page_size: int = 50) -> Iterator[dict]:
        if self.auth_credentials is None:
            raise RuntimeError("Not logged in. Call login() first.")

        page = 1
        while True:
            page_body = self._fetch_resources_page(page, page_size).body or []
            if not page_body:
                return
            for resource_body in page_body:
                yield resource_body
            if len(page_body) < page_size:
                return
            page += 1

    def find_resource_uuid_by_filters(
        self,
        expected_name: Optional[str] = None,
        expected_username: Optional[str] = None,
        expected_uri: Optional[str] = None,
    ) -> uuid.UUID:
        if self.auth_credentials is None:
            raise RuntimeError("Not logged in. Call login() first.")
        if all(f is None for f in [expected_name, expected_username, expected_uri]):
            raise ValueError("At least one of name, username, uri must be provided.")

        if not self._session_keys_loaded:
            self._load_session_keys()
            self._session_keys_loaded = True

        page = 1
        fetched = 0
        while True:
            if page > SCAN_MAX_PAGES:
                display.warning(
                    "Passbolt filter scan reached the %d-page safety limit; stopping. "
                    "Refine filters or pin by UUID." % SCAN_MAX_PAGES
                )
                break
            api_response = self._fetch_resources_page(page, SCAN_PAGE_SIZE)
            page_body = api_response.body or []
            if not page_body:
                break
            match = self._scan_page_for_match(page_body, expected_name, expected_username, expected_uri)
            if match is not None:
                return match
            fetched += len(page_body)
            pagination = (api_response.header or {}).get("pagination") or {}
            total = pagination.get("count")
            if total is not None and fetched >= total:
                break
            if len(page_body) < (pagination.get("limit") or SCAN_PAGE_SIZE):
                break
            page += 1

        raise LookupError(
            f"No resource found matching filters "
            f"(name={expected_name!r}, username={expected_username!r}, uri={expected_uri!r})."
        )

    def _scan_page_for_match(
        self,
        page_body: list,
        name: Optional[str],
        username: Optional[str],
        uri: Optional[str],
    ) -> Optional[uuid.UUID]:
        for resource_body in page_body:
            resource_id = resource_body.get("id")
            try:
                metadata = self._decrypt_metadata(resource_body, verify=True)
            except GnuPGException as exc:
                display.warning(
                    f"Could not decrypt or verify metadata for resource '{resource_id}', skipping: {exc}"
                )
                continue
            except Exception as exc:
                display.vvvv(
                    f"Metadata decryption failed for resource '{resource_id}', skipping: {exc}"
                )
                continue
            if self._metadata_matches_filters(metadata, name, username, uri):
                return uuid.UUID(resource_id)
        return None

    @staticmethod
    def _metadata_matches_filters(
        metadata: dict,
        name: Optional[str],
        username: Optional[str],
        uri: Optional[str],
    ) -> bool:
        if name is not None and metadata.get("name") != name:
            return False
        if username is not None and metadata.get("username") != username:
            return False
        if uri is not None:
            uris = metadata.get("uris") or []
            if not uris and metadata.get("uri"):
                uris = [metadata.get("uri")]
            if uri not in uris:
                return False
        return True

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

    def _fetch_resources_page(self, page: int, limit: int) -> APIResponse:
        url = urljoin(
            self.passbolt_account.fullbase_url,
            f"resources.json?page={page}&limit={limit}"
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
            raise RuntimeError(
                f"Failed to list resources page {page}. HTTP {api_response.http_status_code}"
            )

        return api_response

    def _decrypt_metadata(self, resource_body: dict, verify: bool = True) -> dict:
        encrypted_metadata = resource_body.get("metadata")
        if not encrypted_metadata:
            raise ValueError("Resource has no encrypted metadata.")

        resource_id = resource_body.get("id")
        session_key = self._session_key_cache.get(resource_id) if resource_id else None
        if session_key is not None:
            try:
                sign_fingerprint = self._resolve_metadata_key(resource_body)[1] if verify else None
                decrypted_json = GnuPGService.decrypt_with_session_key(
                    encrypted_metadata, session_key, sign_fingerprint)
                return json.loads(decrypted_json)
            except (GnuPGException, json.JSONDecodeError) as exc:
                display.vvvv(
                    f"Session-key decryption failed for resource '{resource_id}', "
                    f"falling back to asymmetric decryption: {exc}"
                )

        decryption_passphrase, metadata_key_fingerprint = self._resolve_metadata_key(resource_body)
        if verify:
            decrypted_json = GnuPGService.decrypt_and_verify(encrypted_metadata, decryption_passphrase,
                                                             metadata_key_fingerprint)
        else:
            decrypted_json = GnuPGService.decrypt(encrypted_metadata, decryption_passphrase)
        return json.loads(decrypted_json)

    def _resolve_metadata_key(self, resource_body: dict) -> tuple[Optional[str], str]:
        metadata_key_type = resource_body.get("metadata_key_type")

        if metadata_key_type == self.METADATA_KEY_TYPE_USER:
            return self.passbolt_account.passphrase, self.passbolt_account.key_id
        elif metadata_key_type == self.METADATA_KEY_TYPE_SHARED:
            metadata_key_id = resource_body.get("metadata_key_id")
            if not metadata_key_id:
                raise ValueError("Resource uses shared_key but metadata_key_id is missing.")
            return None, self._import_metadata_private_key(metadata_key_id)
        else:
            raise ValueError(f"Invalid metadata_key_type: '{metadata_key_type}'")

    def _load_session_keys(self) -> None:
        try:
            url = urljoin(self.passbolt_account.fullbase_url, "metadata/session-keys.json")
            api_response = HTTPClientService.send(APIRequest(
                HTTPMethod.GET, url, auth_credentials=self.auth_credentials,
                verify=self.verify, timeout=self.timeout))
            if not api_response.is_success():
                display.vvvv("Metadata session keys unavailable (HTTP %s); proceeding without cache."
                             % api_response.http_status_code)
                return
            for entry in api_response.body or []:
                data = entry.get("data")
                if not data:
                    continue
                bundle = json.loads(GnuPGService.decrypt(data, self.passbolt_account.passphrase))
                if bundle.get("object_type") != "PASSBOLT_SESSION_KEYS":
                    continue
                for sk in bundle.get("session_keys", []):
                    if (sk.get("foreign_model") == "Resource"
                            and sk.get("foreign_id") and sk.get("session_key")):
                        self._session_key_cache[sk["foreign_id"]] = sk["session_key"]
            display.vvvv("Loaded %d metadata session key(s) from cache."
                         % len(self._session_key_cache))
        except Exception as exc:
            display.vvvv("Failed to load metadata session keys; proceeding without cache: %s" % exc)

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

            decrypted_json = GnuPGService.decrypt_and_verify_any(
                user_private_key_data,
                self.passbolt_account.passphrase,
                {
                    self.passbolt_account.key_id,
                    self.passbolt_account.server_key_id,
                }
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
