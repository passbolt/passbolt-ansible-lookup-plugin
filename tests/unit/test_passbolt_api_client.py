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
from ansible_collections.passbolt.passbolt_lookup.plugins.module_utils.passbolt.passbolt_api_client import (
    PassboltAPIClient,
)

# --- Constants ---

USER_ID = "u1u2u3u4-5555-6666-7777-888888888888"
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
_PATCH_DECRYPT = "ansible_collections.passbolt.passbolt_lookup.plugins.module_utils.passbolt.cryptography.gnupg_service.GnuPGService.decrypt"
_PATCH_IMPORT_KEY = "ansible_collections.passbolt.passbolt_lookup.plugins.module_utils.passbolt.cryptography.gnupg_service.GnuPGService.import_key"


def _make_api_response(status_code, body, success=True):
    content = {
        "header": {"status": "success" if success else "error"},
        "body": body,
    }
    return APIResponse(status_code, {"Content-Type": "application/json"}, content)


def _make_client():
    account = PassboltAccount(
        id=USER_ID,
        key_id="AABBCCDD",
        email="test@example.com",
        passphrase=PASSPHRASE,
        fullbase_url="https://passbolt.local/",
        server_key_id="EEFF0011",
    )
    client = PassboltAPIClient(account, verify=False, timeout=5)
    client.auth_credentials = MagicMock(spec=AuthCredentials)
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

    @patch(_PATCH_DECRYPT)
    def test_user_key(self, mock_decrypt):
        mock_decrypt.return_value = json.dumps(DECRYPTED_METADATA)

        client = _make_client()
        resource_body = {
            "metadata": "-----BEGIN PGP MESSAGE-----\nfake\n-----END PGP MESSAGE-----",
            "metadata_key_type": "user_key",
        }

        result = client._decrypt_metadata(resource_body)

        mock_decrypt.assert_called_once_with(
            resource_body["metadata"], PASSPHRASE
        )
        self.assertEqual(result, DECRYPTED_METADATA)

    @patch(_PATCH_IMPORT_KEY)
    @patch(_PATCH_DECRYPT)
    @patch(_PATCH_HTTP)
    def test_shared_key(self, mock_send, mock_decrypt, mock_import_key):
        metadata_key_id = "mk-1111-2222-3333-444444444444"

        # First decrypt call: decrypting the metadata private key data
        # Second decrypt call: decrypting the actual metadata
        mock_decrypt.side_effect = [
            json.dumps({"armored_key": "-----BEGIN PGP PRIVATE KEY-----\nfake\n-----END PGP PRIVATE KEY-----"}),
            json.dumps(DECRYPTED_METADATA),
        ]

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
        self.assertIsNone(mock_decrypt.call_args_list[1][0][1])
        mock_import_key.assert_called_once()

    @patch(_PATCH_DECRYPT)
    def test_missing_metadata_raises(self, mock_decrypt):
        client = _make_client()

        with self.assertRaises(ValueError) as ctx:
            client._decrypt_metadata({"metadata_key_type": "user_key"})

        self.assertIn("no encrypted metadata", str(ctx.exception).lower())
        mock_decrypt.assert_not_called()

    @patch(_PATCH_DECRYPT)
    def test_invalid_type_raises(self, mock_decrypt):
        client = _make_client()
        resource_body = {
            "metadata": "some-data",
            "metadata_key_type": "bogus",
        }

        with self.assertRaises(ValueError) as ctx:
            client._decrypt_metadata(resource_body)

        self.assertIn("bogus", str(ctx.exception))
        mock_decrypt.assert_not_called()


class TestDecryptSecret(unittest.TestCase):

    @patch(_PATCH_DECRYPT)
    def test_success(self, mock_decrypt):
        mock_decrypt.return_value = json.dumps(DECRYPTED_SECRET)

        client = _make_client()
        resource_body = {
            "secrets": [
                {
                    "user_id": USER_ID,
                    "data": "encrypted-secret-data",
                }
            ]
        }

        result = client._decrypt_secret(resource_body)

        self.assertEqual(result, DECRYPTED_SECRET)
        mock_decrypt.assert_called_once_with("encrypted-secret-data", PASSPHRASE)

    @patch(_PATCH_DECRYPT)
    def test_no_secrets_returns_none(self, mock_decrypt):
        client = _make_client()
        result = client._decrypt_secret({"secrets": []})

        self.assertIsNone(result)
        mock_decrypt.assert_not_called()

    @patch(_PATCH_DECRYPT)
    def test_no_matching_user_returns_none(self, mock_decrypt):
        client = _make_client()
        resource_body = {
            "secrets": [
                {
                    "user_id": "other-user-id",
                    "data": "encrypted",
                }
            ]
        }

        result = client._decrypt_secret(resource_body)

        self.assertIsNone(result)
        mock_decrypt.assert_not_called()


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


if __name__ == "__main__":
    unittest.main()
