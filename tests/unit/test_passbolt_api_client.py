import json
import unittest
import uuid
from unittest.mock import MagicMock, patch

from ansible_collections.passbolt.passbolt_lookup.plugins.module_utils.passbolt.account.passbolt_account import (
    PassboltAccount,
)
from ansible_collections.passbolt.passbolt_lookup.plugins.module_utils.passbolt.api.api_response import (
    APIResponse,
)
from ansible_collections.passbolt.passbolt_lookup.plugins.module_utils.passbolt.auth.auth_credentials import (
    AuthCredentials,
)
from ansible_collections.passbolt.passbolt_lookup.plugins.module_utils.passbolt.auth.exceptions.authentication_exception import (
    AuthenticationException,
)
from ansible_collections.passbolt.passbolt_lookup.plugins.module_utils.passbolt.auth.jwt_credentials import (
    JWTCredentials,
)
from ansible_collections.passbolt.passbolt_lookup.plugins.module_utils.passbolt.cryptography.exceptions.gnupg_exception import (
    GnuPGException,
)
from ansible_collections.passbolt.passbolt_lookup.plugins.module_utils.passbolt.passbolt_api_client import (
    PassboltAPIClient,
)

# --- Constants ---

USER_ID = "e1f2e3f4-5555-6666-7777-888888888888"
OTHER_USER_ID = "a1b2c3d4-9999-0000-4444-012012012012"
OTHER_USER_KEY_FINGERPRINT = "AABBAABB"
USER_KEY_FINGERPRINT = "AABBCCDD"
SERVER_KEY_FINGERPRINT = "EEFF0011"
RESOURCE_ID = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
RESOURCE_UUID = uuid.UUID(RESOURCE_ID)
PASSPHRASE = "testpass"

DECRYPTED_METADATA = {
    "name": "Test Resource",
    "username": "admin",
    "uris": ["https://example.com"],
}

DECRYPTED_SECRET = {
    "password": "s3cret",
    "description": "A note",
}

_PATCH_HTTP = "ansible_collections.passbolt.passbolt_lookup.plugins.module_utils.passbolt.http.http_client_service.HTTPClientService.send"
_PATCH_DECRYPT_AND_VERIFY = "ansible_collections.passbolt.passbolt_lookup.plugins.module_utils.passbolt.cryptography.gnupg_service.GnuPGService.decrypt_and_verify"
_PATCH_DECRYPT = "ansible_collections.passbolt.passbolt_lookup.plugins.module_utils.passbolt.cryptography.gnupg_service.GnuPGService.decrypt"
_PATCH_IMPORT_KEY = "ansible_collections.passbolt.passbolt_lookup.plugins.module_utils.passbolt.cryptography.gnupg_service.GnuPGService.import_key"
_PATCH_JWT_LOGIN = "ansible_collections.passbolt.passbolt_lookup.plugins.module_utils.passbolt.auth.jwt_auth_strategy.JWTAuthStrategy.login"
_PATCH_JWT_LOGOUT = "ansible_collections.passbolt.passbolt_lookup.plugins.module_utils.passbolt.auth.jwt_auth_strategy.JWTAuthStrategy.logout"
_PATCH_DISPLAY = "ansible_collections.passbolt.passbolt_lookup.plugins.module_utils.passbolt.passbolt_api_client.display"
_PATCH_DECRYPT_METADATA = "ansible_collections.passbolt.passbolt_lookup.plugins.module_utils.passbolt.passbolt_api_client.PassboltAPIClient._decrypt_metadata"
_PATCH_DECRYPT_WITH_SESSION_KEY = "ansible_collections.passbolt.passbolt_lookup.plugins.module_utils.passbolt.cryptography.gnupg_service.GnuPGService.decrypt_with_session_key"
_PATCH_LOAD_SESSION_KEYS = "ansible_collections.passbolt.passbolt_lookup.plugins.module_utils.passbolt.passbolt_api_client.PassboltAPIClient._load_session_keys"


def _make_api_response(status_code, body, success=True, pagination=None):
    header = {"status": "success" if success else "error"}
    if pagination is not None:
        header["pagination"] = pagination
    content = {"header": header, "body": body}
    return APIResponse(status_code, {"Content-Type": "application/json"}, content)


def _make_client():
    account = PassboltAccount(
        id=USER_ID,
        key_id=USER_KEY_FINGERPRINT,
        email="test@example.com",
        passphrase=PASSPHRASE,
        fullbase_url="https://passbolt.local/",
        server_key_id=SERVER_KEY_FINGERPRINT,
    )
    client = PassboltAPIClient(account, verify=False, timeout=5)
    client.auth_credentials = MagicMock(spec=AuthCredentials)
    # Pretend the session-key bundle was already loaded (empty cache) so scan tests do not
    # trigger the lazy GET /metadata/session-keys.json. Session-key behaviour is covered
    # explicitly in TestSessionKeys.
    client._session_keys_loaded = True
    return client


class TestFetchResource(unittest.TestCase):

    @patch(_PATCH_HTTP)
    def test_success(self, mock_send):
        body = {"id": RESOURCE_ID, "metadata": "encrypted", "secrets": []}
        mock_send.return_value = _make_api_response(200, body)

        client = _make_client()
        result = client._fetch_resource(RESOURCE_UUID)

        self.assertEqual(result["id"], RESOURCE_ID)

    @patch(_PATCH_HTTP)
    def test_404_raises_lookup_error(self, mock_send):
        mock_send.return_value = _make_api_response(404, None, success=False)

        client = _make_client()
        with self.assertRaises(LookupError) as ctx:
            client._fetch_resource(RESOURCE_UUID)

        self.assertIn(RESOURCE_ID, str(ctx.exception))

    @patch(_PATCH_HTTP)
    def test_500_raises_runtime_error(self, mock_send):
        mock_send.return_value = _make_api_response(500, None, success=False)

        client = _make_client()
        with self.assertRaises(RuntimeError):
            client._fetch_resource(RESOURCE_UUID)

    @patch(_PATCH_HTTP)
    def test_deleted_raises_lookup_error(self, mock_send):
        body = {"id": RESOURCE_ID, "deleted": True}
        mock_send.return_value = _make_api_response(200, body)

        client = _make_client()
        with self.assertRaises(LookupError) as ctx:
            client._fetch_resource(RESOURCE_UUID)

        self.assertIn("deleted", str(ctx.exception))


class TestDecryptMetadata(unittest.TestCase):

    @patch(_PATCH_DECRYPT_AND_VERIFY)
    def test_user_key(self, mock_decrypt_and_verify):
        mock_decrypt_and_verify.return_value = json.dumps(DECRYPTED_METADATA)

        client = _make_client()
        resource_body = {
            "metadata": "-----BEGIN PGP MESSAGE-----\nfake\n-----END PGP MESSAGE-----",
            "metadata_key_type": "user_key",
        }

        result = client._decrypt_metadata(resource_body)

        mock_decrypt_and_verify.assert_called_once_with(resource_body["metadata"], PASSPHRASE, USER_KEY_FINGERPRINT)
        self.assertEqual(result, DECRYPTED_METADATA)

    @patch(_PATCH_IMPORT_KEY)
    @patch(_PATCH_DECRYPT_AND_VERIFY)
    @patch(_PATCH_HTTP)
    def test_shared_key(self, mock_send, mock_decrypt_and_verify, mock_import_key):
        metadata_key_id = "mk-1111-2222-3333-444444444444"

        # First decrypt call: decrypting the metadata private key data
        # Second decrypt call: decrypting the actual metadata
        mock_decrypt_and_verify.side_effect = [
            json.dumps({"armored_key": "-----BEGIN PGP PRIVATE KEY-----\nfake\n-----END PGP PRIVATE KEY-----"}),
            json.dumps(DECRYPTED_METADATA),
        ]
        mock_import_key.return_value = ["AAAAAAAA", "AAAAAAAA"]

        # HTTPClientService.send returns metadata keys list
        metadata_keys_body = [
            {
                "id": metadata_key_id,
                "metadata_private_keys": [
                    {
                        "user_id": USER_ID,
                        "metadata_key_id": metadata_key_id,
                        "data": "encrypted-private-key-data",
                    }
                ],
            }
        ]
        mock_send.return_value = _make_api_response(200, metadata_keys_body)

        client = _make_client()
        resource_body = {
            "metadata": "encrypted-metadata",
            "metadata_key_type": "shared_key",
            "metadata_key_id": metadata_key_id,
        }

        result = client._decrypt_metadata(resource_body)

        self.assertEqual(result, DECRYPTED_METADATA)
        # Second decrypt call should use passphrase=None (shared key already imported)
        self.assertIsNone(mock_decrypt_and_verify.call_args_list[1][0][1])
        mock_import_key.assert_called_once()

    @patch(_PATCH_IMPORT_KEY)
    @patch(_PATCH_DECRYPT_AND_VERIFY)
    @patch(_PATCH_HTTP)
    def test_shared_key_mismatched_fingerprints(self, mock_send, mock_decrypt_and_verify, mock_import_key):
        metadata_key_id = "mk-1111-2222-3333-444444444444"

        # First decrypt call: decrypting the metadata private key data
        # Second decrypt call: decrypting the actual metadata
        mock_decrypt_and_verify.side_effect = [
            json.dumps({"armored_key": "-----BEGIN PGP PRIVATE KEY-----\nfake\n-----END PGP PRIVATE KEY-----"}),
            json.dumps(DECRYPTED_METADATA),
        ]
        mock_import_key.return_value = ["AAAAAAAA", "BBBBBBBB"]

        # HTTPClientService.send returns metadata keys list
        metadata_keys_body = [
            {
                "id": metadata_key_id,
                "metadata_private_keys": [
                    {
                        "user_id": USER_ID,
                        "metadata_key_id": metadata_key_id,
                        "data": "encrypted-private-key-data",
                    }
                ],
            }
        ]
        mock_send.return_value = _make_api_response(200, metadata_keys_body)

        client = _make_client()
        resource_body = {
            "metadata": "encrypted-metadata",
            "metadata_key_type": "shared_key",
            "metadata_key_id": metadata_key_id,
        }

        with self.assertRaises(RuntimeError) as ctx:
            client._decrypt_metadata(resource_body)
        self.assertIn("expected metadata public and private key fingerprint to match",
                      str(ctx.exception).lower())
        mock_import_key.assert_called_once()

    @patch(_PATCH_DECRYPT_AND_VERIFY)
    def test_missing_metadata_raises(self, mock_decrypt_and_verify):
        client = _make_client()

        with self.assertRaises(ValueError) as ctx:
            client._decrypt_metadata({"metadata_key_type": "user_key"})

        self.assertIn("no encrypted metadata", str(ctx.exception).lower())
        mock_decrypt_and_verify.assert_not_called()

    @patch(_PATCH_DECRYPT_AND_VERIFY)
    def test_invalid_type_raises(self, mock_decrypt_and_verify):
        client = _make_client()
        resource_body = {
            "metadata": "some-data",
            "metadata_key_type": "bogus",
        }

        with self.assertRaises(ValueError) as ctx:
            client._decrypt_metadata(resource_body)

        self.assertIn("bogus", str(ctx.exception))
        mock_decrypt_and_verify.assert_not_called()

    @patch(_PATCH_DECRYPT_AND_VERIFY)
    @patch(_PATCH_DECRYPT)
    def test_user_key_verify_false_skips_verification(self, mock_decrypt, mock_decrypt_and_verify):
        mock_decrypt.return_value = json.dumps(DECRYPTED_METADATA)

        client = _make_client()
        resource_body = {
            "metadata": "-----BEGIN PGP MESSAGE-----\nfake\n-----END PGP MESSAGE-----",
            "metadata_key_type": "user_key",
        }

        result = client._decrypt_metadata(resource_body, verify=False)

        mock_decrypt.assert_called_once_with(resource_body["metadata"], PASSPHRASE)
        mock_decrypt_and_verify.assert_not_called()
        self.assertEqual(result, DECRYPTED_METADATA)

    @patch(_PATCH_IMPORT_KEY)
    @patch(_PATCH_DECRYPT_AND_VERIFY)
    @patch(_PATCH_DECRYPT)
    @patch(_PATCH_HTTP)
    def test_shared_key_verify_false_still_imports_key(self, mock_send, mock_decrypt, mock_decrypt_and_verify, mock_import_key):
        metadata_key_id = "mk-1111-2222-3333-444444444444"

        # decrypt_and_verify is still used to unwrap the metadata private key
        # (that path is unchanged); decrypt (no verify) is used for the metadata blob.
        mock_decrypt_and_verify.return_value = json.dumps(
            {"armored_key": "-----BEGIN PGP PRIVATE KEY-----\nfake\n-----END PGP PRIVATE KEY-----"}
        )
        mock_decrypt.return_value = json.dumps(DECRYPTED_METADATA)
        mock_import_key.return_value = ["AAAAAAAA", "AAAAAAAA"]

        metadata_keys_body = [
            {
                "id": metadata_key_id,
                "metadata_private_keys": [
                    {
                        "user_id": USER_ID,
                        "metadata_key_id": metadata_key_id,
                        "data": "encrypted-private-key-data",
                    }
                ],
            }
        ]
        mock_send.return_value = _make_api_response(200, metadata_keys_body)

        client = _make_client()
        resource_body = {
            "metadata": "encrypted-metadata",
            "metadata_key_type": "shared_key",
            "metadata_key_id": metadata_key_id,
        }

        result = client._decrypt_metadata(resource_body, verify=False)

        self.assertEqual(result, DECRYPTED_METADATA)
        mock_import_key.assert_called_once()
        mock_decrypt.assert_called_once_with("encrypted-metadata", None)


class TestDecryptSecret(unittest.TestCase):

    @patch(_PATCH_DECRYPT_AND_VERIFY)
    def test_success_personal_resource(self, mock_decrypt_and_verify):
        mock_decrypt_and_verify.return_value = json.dumps(DECRYPTED_SECRET)

        client = _make_client()
        resource_body = {
            "modified_by": USER_ID,
            "personal": True,
            "secrets": [
                {
                    "user_id": USER_ID,
                    "data": "encrypted-secret-data",
                }
            ]
        }

        result = client._decrypt_secret(resource_body)

        self.assertEqual(result, DECRYPTED_SECRET)
        mock_decrypt_and_verify.assert_called_once_with("encrypted-secret-data", PASSPHRASE, USER_KEY_FINGERPRINT)

    @patch(_PATCH_DECRYPT_AND_VERIFY)
    @patch(_PATCH_IMPORT_KEY)
    @patch(_PATCH_HTTP)
    def test_success_shared_resource(self, mock_send, mock_import, mock_decrypt_and_verify):
        mock_import.return_value = [OTHER_USER_KEY_FINGERPRINT]
        mock_decrypt_and_verify.return_value = json.dumps(DECRYPTED_SECRET)
        user_body = {
            "id": OTHER_USER_ID,
            "active": True,
            "gpgkey": {
                "fingerprint": OTHER_USER_KEY_FINGERPRINT,
                "armored_key": "-----BEGIN PGP PRIVATE KEY-----\nis this real life\n-----END PGP PRIVATE KEY-----"
            }
        }
        mock_send.return_value = _make_api_response(200, user_body)

        client = _make_client()
        resource_body = {
            "personal": False,
            "secrets": [
                {
                    "user_id": USER_ID,
                    "modified_by": OTHER_USER_ID,
                    "data": "encrypted-secret-data",
                }
            ]
        }
        result = client._decrypt_secret(resource_body)

        self.assertEqual(result, DECRYPTED_SECRET)
        mock_import.assert_called_once_with("-----BEGIN PGP PRIVATE KEY-----\nis this real life\n-----END PGP PRIVATE KEY-----", None)
        mock_decrypt_and_verify.assert_called_once_with("encrypted-secret-data", PASSPHRASE, OTHER_USER_KEY_FINGERPRINT)

    @patch(_PATCH_DECRYPT_AND_VERIFY)
    def test_no_secrets_returns_none(self, mock_decrypt_and_verify):
        client = _make_client()
        result = client._decrypt_secret({"secrets": []})

        self.assertIsNone(result)
        mock_decrypt_and_verify.assert_not_called()

    @patch(_PATCH_DECRYPT_AND_VERIFY)
    def test_no_matching_user_returns_none(self, mock_decrypt_and_verify):
        client = _make_client()
        resource_body = {
            "secrets": [
                {
                    "user_id": OTHER_USER_ID,
                    "data": "encrypted",
                }
            ]
        }

        result = client._decrypt_secret(resource_body)

        self.assertIsNone(result)
        mock_decrypt_and_verify.assert_not_called()


class TestLogin(unittest.TestCase):

    @patch(_PATCH_JWT_LOGIN)
    def test_success_returns_true_and_stores_credentials(self, mock_jwt_login):
        mock_credentials = JWTCredentials("access-token", "refresh-token")
        mock_jwt_login.return_value = mock_credentials

        client = _make_client()
        client.auth_credentials = None
        result = client.login()

        self.assertTrue(result)
        self.assertIs(client.auth_credentials, mock_credentials)

    @patch(_PATCH_JWT_LOGIN)
    def test_propagates_authentication_exception(self, mock_jwt_login):
        mock_jwt_login.side_effect = AuthenticationException("auth failed")

        client = _make_client()
        client.auth_credentials = None

        with self.assertRaises(AuthenticationException):
            client.login()


class TestLogout(unittest.TestCase):

    def _make_logged_in_client(self):
        client = _make_client()
        client.auth_credentials = JWTCredentials("access-token", "refresh-token")
        client._metadata_key_cache = {"mk-1": "FP1", "mk-2": "FP2"}
        client._session_key_cache = {"res-1": "9:AAAA", "res-2": "9:BBBB"}
        return client

    @patch(_PATCH_JWT_LOGOUT)
    def test_success_returns_true_and_clears_state(self, mock_jwt_logout):
        mock_jwt_logout.return_value = True

        client = self._make_logged_in_client()
        result = client.logout()

        self.assertTrue(result)
        self.assertIsNone(client.auth_credentials)
        self.assertEqual(client._metadata_key_cache, {})
        self.assertEqual(client._session_key_cache, {})
        self.assertFalse(client._session_keys_loaded)
        mock_jwt_logout.assert_called_once()

    @patch(_PATCH_JWT_LOGOUT)
    def test_server_failure_still_clears_local_state(self, mock_jwt_logout):
        mock_jwt_logout.return_value = False

        client = self._make_logged_in_client()
        result = client.logout()

        self.assertFalse(result)
        self.assertIsNone(client.auth_credentials)
        self.assertEqual(client._metadata_key_cache, {})

    @patch(_PATCH_JWT_LOGOUT)
    def test_server_exception_still_clears_local_state(self, mock_jwt_logout):
        mock_jwt_logout.side_effect = Exception("connection timeout")

        client = self._make_logged_in_client()

        with self.assertRaises(Exception) as ctx:
            client.logout()

        self.assertIn("connection timeout", str(ctx.exception))
        self.assertIsNone(client.auth_credentials)
        self.assertEqual(client._metadata_key_cache, {})

    @patch(_PATCH_JWT_LOGOUT)
    def test_original_credentials_passed_to_strategy(self, mock_jwt_logout):
        mock_jwt_logout.return_value = True

        client = self._make_logged_in_client()
        original_creds = client.auth_credentials

        client.logout()

        passed_creds = mock_jwt_logout.call_args[0][1]
        self.assertIs(passed_creds, original_creds)
        self.assertIsNone(client.auth_credentials)

    @patch(_PATCH_JWT_LOGOUT)
    def test_verify_and_timeout_forwarded(self, mock_jwt_logout):
        mock_jwt_logout.return_value = True

        client = self._make_logged_in_client()
        client.logout()

        mock_jwt_logout.assert_called_once_with(
            client.passbolt_account,
            unittest.mock.ANY,
            verify=False,
            timeout=5,
        )


class TestGetResource(unittest.TestCase):

    def test_not_logged_in_raises(self):
        account = PassboltAccount(
            id=USER_ID,
            key_id="AABBCCDD",
            email="test@example.com",
            passphrase=PASSPHRASE,
            fullbase_url="https://passbolt.local/",
            server_key_id="EEFF0011",
        )
        client = PassboltAPIClient(account, verify=False, timeout=5)
        # auth_credentials is None by default

        with self.assertRaises(RuntimeError) as ctx:
            client.get_resource(RESOURCE_UUID)

        self.assertIn("Not logged in", str(ctx.exception))


def _make_resource_body(resource_id, name=None, username=None, uris=None, uri=None,
                        metadata="encrypted", metadata_key_type="user_key"):
    body = {
        "id": resource_id,
        "metadata": metadata,
        "metadata_key_type": metadata_key_type,
    }
    return body


def _make_decrypted_metadata(name=None, username=None, uris=None, uri=None):
    md = {}
    if name is not None:
        md["name"] = name
    if username is not None:
        md["username"] = username
    if uris is not None:
        md["uris"] = uris
    if uri is not None:
        md["uri"] = uri
    return md


def _called_urls(mock_send):
    return [call.args[0].uri for call in mock_send.call_args_list]


class TestListResources(unittest.TestCase):

    @patch(_PATCH_HTTP)
    def test_yields_resources_from_single_page(self, mock_send):
        bodies = [{"id": f"id-{i}"} for i in range(3)]
        mock_send.return_value = _make_api_response(200, bodies)

        client = _make_client()
        result = list(client.list_resources(page_size=50))

        self.assertEqual(result, bodies)
        self.assertEqual(mock_send.call_count, 1)

    @patch(_PATCH_HTTP)
    def test_paginates_until_short_page(self, mock_send):
        page1 = [{"id": f"id-p1-{i}"} for i in range(50)]
        page2 = [{"id": f"id-p2-{i}"} for i in range(7)]
        mock_send.side_effect = [
            _make_api_response(200, page1),
            _make_api_response(200, page2),
        ]

        client = _make_client()
        result = list(client.list_resources(page_size=50))

        self.assertEqual(len(result), 57)
        self.assertEqual(mock_send.call_count, 2)
        urls = _called_urls(mock_send)
        self.assertIn("page=1", urls[0])
        self.assertIn("limit=50", urls[0])
        self.assertIn("page=2", urls[1])

    @patch(_PATCH_HTTP)
    def test_stops_on_empty_first_page(self, mock_send):
        mock_send.return_value = _make_api_response(200, [])

        client = _make_client()
        result = list(client.list_resources(page_size=50))

        self.assertEqual(result, [])
        self.assertEqual(mock_send.call_count, 1)

    def test_not_logged_in_raises(self):
        account = PassboltAccount(
            id=USER_ID,
            key_id=USER_KEY_FINGERPRINT,
            email="test@example.com",
            passphrase=PASSPHRASE,
            fullbase_url="https://passbolt.local/",
            server_key_id=SERVER_KEY_FINGERPRINT,
        )
        client = PassboltAPIClient(account, verify=False, timeout=5)

        with self.assertRaises(RuntimeError) as ctx:
            list(client.list_resources())

        self.assertIn("Not logged in", str(ctx.exception))

    @patch(_PATCH_HTTP)
    def test_url_does_not_contain_secret(self, mock_send):
        page1 = [{"id": "id-1"}]
        mock_send.return_value = _make_api_response(200, page1)

        client = _make_client()
        list(client.list_resources(page_size=50))

        for url in _called_urls(mock_send):
            self.assertNotIn("contain[secret]", url)

    @patch(_PATCH_HTTP)
    def test_consumer_break_stops_paging(self, mock_send):
        page1 = [{"id": f"id-{i}"} for i in range(50)]
        mock_send.side_effect = [
            _make_api_response(200, page1),
            _make_api_response(500, None, success=False),  # would fail if reached
        ]

        client = _make_client()
        gen = client.list_resources(page_size=50)
        first = next(gen)
        gen.close()

        self.assertEqual(first, page1[0])
        self.assertEqual(mock_send.call_count, 1)

    @patch(_PATCH_HTTP)
    def test_http_error_raises_runtime_error(self, mock_send):
        page1 = [{"id": f"id-{i}"} for i in range(50)]
        mock_send.side_effect = [
            _make_api_response(200, page1),
            _make_api_response(500, None, success=False),
        ]

        client = _make_client()
        gen = client.list_resources(page_size=50)
        # Drain page 1
        page1_yielded = [next(gen) for _ in range(50)]
        self.assertEqual(len(page1_yielded), 50)

        with self.assertRaises(RuntimeError) as ctx:
            next(gen)

        self.assertIn("page 2", str(ctx.exception))


class TestFindResourceUuidByFilters(unittest.TestCase):

    def test_no_filters_raises_value_error(self):
        client = _make_client()
        with self.assertRaises(ValueError) as ctx:
            client.find_resource_uuid_by_filters()
        self.assertIn("At least one of name, username, uri", str(ctx.exception))

    def test_not_logged_in_raises(self):
        account = PassboltAccount(
            id=USER_ID,
            key_id=USER_KEY_FINGERPRINT,
            email="test@example.com",
            passphrase=PASSPHRASE,
            fullbase_url="https://passbolt.local/",
            server_key_id=SERVER_KEY_FINGERPRINT,
        )
        client = PassboltAPIClient(account, verify=False, timeout=5)

        with self.assertRaises(RuntimeError) as ctx:
            client.find_resource_uuid_by_filters(expected_name="anything")

        self.assertIn("Not logged in", str(ctx.exception))

    @patch(_PATCH_DECRYPT_METADATA)
    @patch(_PATCH_HTTP)
    def test_single_match_by_name(self, mock_send, mock_decrypt):
        match_id = "11111111-1111-1111-1111-111111111111"
        bodies = [
            _make_resource_body("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
            _make_resource_body(match_id),
            _make_resource_body("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"),
        ]
        mock_send.return_value = _make_api_response(200, bodies)
        mock_decrypt.side_effect = [
            _make_decrypted_metadata(name="other-1"),
            _make_decrypted_metadata(name="acme-db"),
            _make_decrypted_metadata(name="other-2"),
        ]

        client = _make_client()
        result = client.find_resource_uuid_by_filters(expected_name="acme-db")

        self.assertEqual(result, uuid.UUID(match_id))

    @patch(_PATCH_DECRYPT_METADATA)
    @patch(_PATCH_HTTP)
    def test_filters_compose_as_and(self, mock_send, mock_decrypt):
        match_id = "22222222-2222-2222-2222-222222222222"
        bodies = [
            _make_resource_body("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
            _make_resource_body(match_id),
        ]
        mock_send.return_value = _make_api_response(200, bodies)
        # Resource A: name matches but username does not
        # Resource B: name + username + uri all match
        mock_decrypt.side_effect = [
            _make_decrypted_metadata(name="db-prod", username="root", uris=["https://other"]),
            _make_decrypted_metadata(name="db-prod", username="app", uris=["https://db.acme.internal"]),
        ]

        client = _make_client()
        result = client.find_resource_uuid_by_filters(
            expected_name="db-prod", expected_username="app", expected_uri="https://db.acme.internal"
        )

        self.assertEqual(result, uuid.UUID(match_id))

    @patch(_PATCH_DECRYPT_METADATA)
    @patch(_PATCH_HTTP)
    def test_uri_matches_any_in_uris_list(self, mock_send, mock_decrypt):
        match_id = "33333333-3333-3333-3333-333333333333"
        bodies = [_make_resource_body(match_id)]
        mock_send.return_value = _make_api_response(200, bodies)
        mock_decrypt.return_value = _make_decrypted_metadata(uris=["https://x", "https://y", "https://z"])

        client = _make_client()
        result = client.find_resource_uuid_by_filters(expected_uri="https://y")

        self.assertEqual(result, uuid.UUID(match_id))

    @patch(_PATCH_DECRYPT_METADATA)
    @patch(_PATCH_HTTP)
    def test_uri_legacy_single_uri_field(self, mock_send, mock_decrypt):
        match_id = "44444444-4444-4444-4444-444444444444"
        bodies = [_make_resource_body(match_id)]
        mock_send.return_value = _make_api_response(200, bodies)
        mock_decrypt.return_value = _make_decrypted_metadata(uri="https://legacy")

        client = _make_client()
        result = client.find_resource_uuid_by_filters(expected_uri="https://legacy")

        self.assertEqual(result, uuid.UUID(match_id))

    @patch(_PATCH_DECRYPT_METADATA)
    @patch(_PATCH_HTTP)
    def test_no_match_raises_lookup_error(self, mock_send, mock_decrypt):
        bodies = [
            _make_resource_body(f"{i}{i}{i}{i}{i}{i}{i}{i}-{i}{i}{i}{i}-{i}{i}{i}{i}-{i}{i}{i}{i}-{i}{i}{i}{i}{i}{i}{i}{i}{i}{i}{i}{i}")
            for i in range(1, 6)
        ]
        mock_send.return_value = _make_api_response(200, bodies)
        mock_decrypt.side_effect = [
            _make_decrypted_metadata(name=f"other-{i}") for i in range(5)
        ]

        client = _make_client()
        with self.assertRaises(LookupError) as ctx:
            client.find_resource_uuid_by_filters(expected_name="not-there")

        msg = str(ctx.exception)
        self.assertIn("not-there", msg)
        self.assertIn("name=", msg)

    @patch(_PATCH_DECRYPT_METADATA)
    @patch(_PATCH_HTTP)
    def test_first_match_wins_short_circuits(self, mock_send, mock_decrypt):
        first_id = "55555555-5555-5555-5555-555555555555"
        second_id = "66666666-6666-6666-6666-666666666666"
        bodies = [
            _make_resource_body(first_id),
            _make_resource_body(second_id),
        ]
        mock_send.return_value = _make_api_response(200, bodies)
        mock_decrypt.side_effect = [
            _make_decrypted_metadata(name="db"),
            _make_decrypted_metadata(name="db"),
        ]

        client = _make_client()
        result = client.find_resource_uuid_by_filters(expected_name="db")

        self.assertEqual(result, uuid.UUID(first_id))
        # The second resource must never be decrypted.
        self.assertEqual(mock_decrypt.call_count, 1)

    @patch(_PATCH_DISPLAY)
    @patch(_PATCH_DECRYPT_METADATA)
    @patch(_PATCH_HTTP)
    def test_metadata_decryption_failure_skipped(self, mock_send, mock_decrypt, mock_display):
        bad_id = "77777777-7777-7777-7777-777777777777"
        good_id = "88888888-8888-8888-8888-888888888888"
        bodies = [
            _make_resource_body(bad_id),
            _make_resource_body(good_id),
        ]
        mock_send.return_value = _make_api_response(200, bodies)
        mock_decrypt.side_effect = [
            ValueError("schema bogus"),
            _make_decrypted_metadata(name="db"),
        ]

        client = _make_client()
        result = client.find_resource_uuid_by_filters(expected_name="db")

        self.assertEqual(result, uuid.UUID(good_id))
        mock_display.vvvv.assert_called_once()
        self.assertIn(bad_id, mock_display.vvvv.call_args[0][0])

    @patch(_PATCH_DISPLAY)
    @patch(_PATCH_DECRYPT_METADATA)
    @patch(_PATCH_HTTP)
    def test_metadata_crypto_failure_warns_and_continues(self, mock_send, mock_decrypt, mock_display):
        bad_id = "99999999-9999-9999-9999-999999999999"
        good_id = "88888888-8888-8888-8888-888888888888"
        bodies = [
            _make_resource_body(bad_id),
            _make_resource_body(good_id),
        ]
        mock_send.return_value = _make_api_response(200, bodies)
        mock_decrypt.side_effect = [
            GnuPGException("Couldn't decrypt data"),
            _make_decrypted_metadata(name="db"),
        ]

        client = _make_client()
        result = client.find_resource_uuid_by_filters(expected_name="db")

        self.assertEqual(result, uuid.UUID(good_id))
        mock_display.warning.assert_called_once()
        self.assertIn(bad_id, mock_display.warning.call_args[0][0])

    @patch(_PATCH_DECRYPT_METADATA)
    @patch(_PATCH_HTTP)
    def test_scan_calls_decrypt_metadata_with_verification(self, mock_send, mock_decrypt):
        match_id = "99999999-9999-9999-9999-999999999999"
        bodies = [_make_resource_body(match_id)]
        mock_send.return_value = _make_api_response(200, bodies)
        mock_decrypt.return_value = _make_decrypted_metadata(name="db")

        client = _make_client()
        client.find_resource_uuid_by_filters(expected_name="db")

        mock_decrypt.assert_called_once()
        # The scan verifies signatures, so a tampered or unverifiable resource is skipped
        # rather than matched on forged metadata.
        self.assertEqual(mock_decrypt.call_args.kwargs.get("verify"), True)

    @patch(_PATCH_DECRYPT_METADATA)
    @patch(_PATCH_HTTP)
    def test_pagination_stops_on_match(self, mock_send, mock_decrypt):
        match_id = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
        page1 = [
            _make_resource_body("cccccccc-cccc-cccc-cccc-cccccccccccc"),
            _make_resource_body(match_id),
        ] + [_make_resource_body(f"dddddddd-dddd-dddd-dddd-{i:012d}") for i in range(48)]
        # If page2 were fetched, this would explode.
        mock_send.side_effect = [
            _make_api_response(200, page1),
            _make_api_response(500, None, success=False),
        ]
        mock_decrypt.side_effect = [
            _make_decrypted_metadata(name="other"),
            _make_decrypted_metadata(name="db"),
        ]

        client = _make_client()
        result = client.find_resource_uuid_by_filters(expected_name="db")

        self.assertEqual(result, uuid.UUID(match_id))
        self.assertEqual(mock_send.call_count, 1)

    @patch(_PATCH_DECRYPT_METADATA)
    @patch(_PATCH_HTTP)
    def test_no_contain_secret_during_scan(self, mock_send, mock_decrypt):
        match_id = "eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee"
        bodies = [_make_resource_body(match_id)]
        mock_send.return_value = _make_api_response(200, bodies)
        mock_decrypt.return_value = _make_decrypted_metadata(name="db")

        client = _make_client()
        client.find_resource_uuid_by_filters(expected_name="db")

        for url in _called_urls(mock_send):
            self.assertNotIn("contain[secret]", url)

    @patch(_PATCH_DECRYPT_METADATA)
    @patch(_PATCH_HTTP)
    def test_pagination_stops_once_count_reached(self, mock_send, mock_decrypt):
        page1 = [_make_resource_body(f"aaaaaaaa-aaaa-aaaa-aaaa-{i:012d}") for i in range(2)]
        page2 = [_make_resource_body(f"bbbbbbbb-bbbb-bbbb-bbbb-{i:012d}") for i in range(2)]
        # count=4 across two pages of 2; no match anywhere. A third fetch would StopIteration.
        mock_send.side_effect = [
            _make_api_response(200, page1, pagination={"limit": 2, "page": 1, "count": 4}),
            _make_api_response(200, page2, pagination={"limit": 2, "page": 2, "count": 4}),
        ]
        mock_decrypt.return_value = _make_decrypted_metadata(name="nope")

        client = _make_client()
        with self.assertRaises(LookupError):
            client.find_resource_uuid_by_filters(expected_name="absent")

        self.assertEqual(mock_send.call_count, 2)

    @patch(_PATCH_DECRYPT_METADATA)
    @patch(_PATCH_HTTP)
    def test_server_capped_limit_keeps_paginating(self, mock_send, mock_decrypt):
        # Server caps the page at 2 even though SCAN_PAGE_SIZE requests more: a full page must
        # not be mistaken for the last one. Match lives on the second page.
        match_id = "cccccccc-cccc-cccc-cccc-cccccccccccc"
        page1 = [_make_resource_body(f"dddddddd-dddd-dddd-dddd-{i:012d}") for i in range(2)]
        page2 = [_make_resource_body(match_id)]
        mock_send.side_effect = [
            _make_api_response(200, page1, pagination={"limit": 2, "page": 1}),
            _make_api_response(200, page2, pagination={"limit": 2, "page": 2}),
        ]

        def fake_decrypt(resource_body, verify=True):
            if resource_body["id"] == match_id:
                return _make_decrypted_metadata(name="db")
            return _make_decrypted_metadata(name="other")

        mock_decrypt.side_effect = fake_decrypt

        client = _make_client()
        result = client.find_resource_uuid_by_filters(expected_name="db")

        self.assertEqual(result, uuid.UUID(match_id))
        self.assertEqual(mock_send.call_count, 2)

    @patch("ansible_collections.passbolt.passbolt_lookup.plugins.module_utils.passbolt.passbolt_api_client.SCAN_MAX_PAGES", 3)
    @patch(_PATCH_DISPLAY)
    @patch(_PATCH_DECRYPT_METADATA)
    @patch(_PATCH_HTTP)
    def test_pagination_safety_limit_stops_runaway_scan(self, mock_send, mock_decrypt, mock_display):
        # Server ignores pagination: every page is full, no count, no match. The scan must be
        # bounded by SCAN_MAX_PAGES instead of looping forever.
        full_page = [_make_resource_body("eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee")]
        mock_send.return_value = _make_api_response(200, full_page, pagination={"limit": 1})
        mock_decrypt.return_value = _make_decrypted_metadata(name="nope")

        client = _make_client()
        with self.assertRaises(LookupError):
            client.find_resource_uuid_by_filters(expected_name="absent")

        self.assertEqual(mock_send.call_count, 3)
        mock_display.warning.assert_called_once()


class TestSessionKeys(unittest.TestCase):

    SESSION_KEY = "9:DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF"

    @patch(_PATCH_DECRYPT)
    @patch(_PATCH_DECRYPT_AND_VERIFY)
    @patch(_PATCH_DECRYPT_WITH_SESSION_KEY)
    def test_hit_uses_session_key_and_skips_asymmetric(self, mock_sk, mock_dav, mock_d):
        mock_sk.return_value = json.dumps(DECRYPTED_METADATA)

        client = _make_client()
        client._session_key_cache = {RESOURCE_ID: self.SESSION_KEY}
        resource_body = {
            "id": RESOURCE_ID,
            "metadata": "encrypted",
            "metadata_key_type": "user_key",
        }

        result = client._decrypt_metadata(resource_body)

        self.assertEqual(result, DECRYPTED_METADATA)
        mock_sk.assert_called_once()
        mock_dav.assert_not_called()
        mock_d.assert_not_called()

    @patch(_PATCH_DECRYPT_WITH_SESSION_KEY)
    def test_hit_verify_false_passes_no_fingerprint(self, mock_sk):
        mock_sk.return_value = json.dumps(DECRYPTED_METADATA)

        client = _make_client()
        client._session_key_cache = {RESOURCE_ID: self.SESSION_KEY}
        resource_body = {"id": RESOURCE_ID, "metadata": "enc", "metadata_key_type": "user_key"}

        client._decrypt_metadata(resource_body, verify=False)

        mock_sk.assert_called_once_with("enc", self.SESSION_KEY, None)

    @patch(_PATCH_DECRYPT_WITH_SESSION_KEY)
    def test_hit_verify_true_passes_signer_fingerprint(self, mock_sk):
        mock_sk.return_value = json.dumps(DECRYPTED_METADATA)

        client = _make_client()
        client._session_key_cache = {RESOURCE_ID: self.SESSION_KEY}
        resource_body = {"id": RESOURCE_ID, "metadata": "enc", "metadata_key_type": "user_key"}

        client._decrypt_metadata(resource_body, verify=True)

        mock_sk.assert_called_once_with("enc", self.SESSION_KEY, USER_KEY_FINGERPRINT)

    @patch(_PATCH_DECRYPT_AND_VERIFY)
    @patch(_PATCH_DECRYPT_WITH_SESSION_KEY)
    def test_miss_falls_back_to_asymmetric(self, mock_sk, mock_dav):
        mock_dav.return_value = json.dumps(DECRYPTED_METADATA)

        client = _make_client()
        client._session_key_cache = {"some-other-id": self.SESSION_KEY}
        resource_body = {"id": RESOURCE_ID, "metadata": "enc", "metadata_key_type": "user_key"}

        result = client._decrypt_metadata(resource_body)

        self.assertEqual(result, DECRYPTED_METADATA)
        mock_sk.assert_not_called()
        mock_dav.assert_called_once_with("enc", PASSPHRASE, USER_KEY_FINGERPRINT)

    @patch(_PATCH_DISPLAY)
    @patch(_PATCH_DECRYPT_AND_VERIFY)
    @patch(_PATCH_DECRYPT_WITH_SESSION_KEY)
    def test_stale_session_key_falls_back_to_asymmetric(self, mock_sk, mock_dav, mock_display):
        # Stale session key (e.g. metadata rotated server-side) -> GnuPGException -> fallback.
        mock_sk.side_effect = GnuPGException("session key no longer valid")
        mock_dav.return_value = json.dumps(DECRYPTED_METADATA)

        client = _make_client()
        client._session_key_cache = {RESOURCE_ID: self.SESSION_KEY}
        resource_body = {"id": RESOURCE_ID, "metadata": "enc", "metadata_key_type": "user_key"}

        result = client._decrypt_metadata(resource_body)

        self.assertEqual(result, DECRYPTED_METADATA)
        mock_sk.assert_called_once()
        mock_dav.assert_called_once_with("enc", PASSPHRASE, USER_KEY_FINGERPRINT)
        mock_display.vvvv.assert_called_once()
        self.assertIn(RESOURCE_ID, mock_display.vvvv.call_args[0][0])

    @patch(_PATCH_DISPLAY)
    @patch(_PATCH_DECRYPT_AND_VERIFY)
    @patch(_PATCH_DECRYPT_WITH_SESSION_KEY)
    def test_garbage_plaintext_falls_back_to_asymmetric(self, mock_sk, mock_dav, mock_display):
        # Wrong/stale session key decrypted to non-JSON garbage with a zero exit: json.loads
        # raises, and we must fall back rather than crash the lookup.
        mock_sk.return_value = "not-json-at-all"
        mock_dav.return_value = json.dumps(DECRYPTED_METADATA)

        client = _make_client()
        client._session_key_cache = {RESOURCE_ID: self.SESSION_KEY}
        resource_body = {"id": RESOURCE_ID, "metadata": "enc", "metadata_key_type": "user_key"}

        result = client._decrypt_metadata(resource_body)

        self.assertEqual(result, DECRYPTED_METADATA)
        mock_sk.assert_called_once()
        mock_dav.assert_called_once_with("enc", PASSPHRASE, USER_KEY_FINGERPRINT)
        mock_display.vvvv.assert_called_once()

    @patch(_PATCH_DECRYPT)
    @patch(_PATCH_HTTP)
    def test_load_session_keys_populates_cache(self, mock_send, mock_decrypt):
        entries = [{
            "id": "sk-entry-1",
            "user_id": USER_ID,
            "data": "-----BEGIN PGP MESSAGE-----\nbundle\n-----END PGP MESSAGE-----",
        }]
        mock_send.return_value = _make_api_response(200, entries)
        mock_decrypt.return_value = json.dumps({
            "object_type": "PASSBOLT_SESSION_KEYS",
            "session_keys": [
                {"foreign_model": "Resource", "foreign_id": "res-1", "session_key": "9:AAAA"},
                {"foreign_model": "Resource", "foreign_id": "res-2", "session_key": "9:BBBB"},
            ],
        })

        client = _make_client()
        client._load_session_keys()

        self.assertEqual(client._session_key_cache, {"res-1": "9:AAAA", "res-2": "9:BBBB"})
        mock_decrypt.assert_called_once_with(entries[0]["data"], PASSPHRASE)
        for url in _called_urls(mock_send):
            self.assertIn("metadata/session-keys.json", url)

    @patch(_PATCH_DECRYPT)
    @patch(_PATCH_HTTP)
    def test_load_session_keys_http_failure_is_non_fatal(self, mock_send, mock_decrypt):
        mock_send.return_value = _make_api_response(500, None, success=False)

        client = _make_client()
        client._load_session_keys()  # must not raise

        self.assertEqual(client._session_key_cache, {})
        mock_decrypt.assert_not_called()

    @patch(_PATCH_DECRYPT)
    @patch(_PATCH_HTTP)
    def test_load_session_keys_wrong_object_type_skipped(self, mock_send, mock_decrypt):
        entries = [{"id": "sk-1", "data": "blob"}]
        mock_send.return_value = _make_api_response(200, entries)
        mock_decrypt.return_value = json.dumps({"object_type": "SOMETHING_ELSE", "session_keys": [
            {"foreign_model": "Resource", "foreign_id": "res-1", "session_key": "9:AAAA"},
        ]})

        client = _make_client()
        client._load_session_keys()

        self.assertEqual(client._session_key_cache, {})

    @patch(_PATCH_DECRYPT_METADATA)
    @patch(_PATCH_HTTP)
    @patch(_PATCH_LOAD_SESSION_KEYS)
    def test_filter_scan_loads_session_keys_once(self, mock_load, mock_send, mock_decrypt):
        match_id = "11111111-1111-1111-1111-111111111111"
        mock_send.return_value = _make_api_response(200, [_make_resource_body(match_id)])
        mock_decrypt.return_value = _make_decrypted_metadata(name="db")

        client = _make_client()
        client._session_keys_loaded = False  # simulate a fresh, just-logged-in client

        client.find_resource_uuid_by_filters(expected_name="db")

        mock_load.assert_called_once()
        self.assertTrue(client._session_keys_loaded)


if __name__ == "__main__":
    unittest.main()
