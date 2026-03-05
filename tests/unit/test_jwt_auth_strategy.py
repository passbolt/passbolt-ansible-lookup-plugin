import json
import unittest
import uuid
from unittest.mock import patch

from ansible_collections.passbolt.passbolt_lookup.plugins.module_utils.passbolt.account.passbolt_account import (
    PassboltAccount,
)
from ansible_collections.passbolt.passbolt_lookup.plugins.module_utils.passbolt.api.api_response import (
    APIResponse,
)
from ansible_collections.passbolt.passbolt_lookup.plugins.module_utils.passbolt.auth.exceptions.authentication_exception import (
    AuthenticationException,
)
from ansible_collections.passbolt.passbolt_lookup.plugins.module_utils.passbolt.auth.jwt_auth_strategy import (
    JWTAuthStrategy,
)
from ansible_collections.passbolt.passbolt_lookup.plugins.module_utils.passbolt.auth.jwt_credentials import (
    JWTCredentials,
)

# --- Constants ---

USER_ID = "u1u2u3u4-5555-6666-7777-888888888888"
USER_KEY_FINGERPRINT = "AABBCCDD"
PASSPHRASE = "testpass"
SERVER_KEY_FINGERPRINT = "EEFF0011"
VERIFY_TOKEN = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
ACCESS_TOKEN = "access-token-value"
REFRESH_TOKEN = "ffffffff-0000-1111-2222-333333333333"
FIXED_TIME = 1_000_000.0
TOKEN_EXPIRY = int(FIXED_TIME + JWTAuthStrategy.VERIFY_TOKEN_LIFETIME_SECONDS)
ENCRYPTED_CHALLENGE = "encrypted-challenge-response"

_PATCH_HTTP = "ansible_collections.passbolt.passbolt_lookup.plugins.module_utils.passbolt.http.http_client_service.HTTPClientService.send"
_PATCH_ENCRYPT = "ansible_collections.passbolt.passbolt_lookup.plugins.module_utils.passbolt.cryptography.gnupg_service.GnuPGService.encrypt"
_PATCH_DECRYPT = "ansible_collections.passbolt.passbolt_lookup.plugins.module_utils.passbolt.cryptography.gnupg_service.GnuPGService.decrypt"
_PATCH_UUID = "ansible_collections.passbolt.passbolt_lookup.plugins.module_utils.passbolt.auth.jwt_auth_strategy.uuid.uuid4"
_PATCH_TIME = "ansible_collections.passbolt.passbolt_lookup.plugins.module_utils.passbolt.auth.jwt_auth_strategy.time.time"


def _make_passbolt_account():
    return PassboltAccount(
        id=USER_ID,
        key_id=USER_KEY_FINGERPRINT,
        email="test@example.com",
        passphrase=PASSPHRASE,
        fullbase_url="https://passbolt.local/",
        server_key_id=SERVER_KEY_FINGERPRINT,
    )


def _make_login_response(servertime, success=True):
    content = {
        "header": {
            "status": "success" if success else "error",
            "servertime": servertime,
        },
        "body": {"challenge": ENCRYPTED_CHALLENGE},
    }
    status_code = 200 if success else 400
    return APIResponse(status_code, {"Content-Type": "application/json"}, content)


def _valid_challenge_json():
    return json.dumps({
        "version": "1.0.0",
        "domain": "https://passbolt.local/",
        "access_token": ACCESS_TOKEN,
        "refresh_token": REFRESH_TOKEN,
        "verify_token": VERIFY_TOKEN,
    })


class TestJWTAuthStrategyLogin(unittest.TestCase):

    @patch(_PATCH_TIME)
    @patch(_PATCH_UUID)
    @patch(_PATCH_DECRYPT)
    @patch(_PATCH_ENCRYPT)
    @patch(_PATCH_HTTP)
    def test_success(self, mock_send, mock_encrypt, mock_decrypt, mock_uuid4, mock_time):
        mock_uuid4.return_value = uuid.UUID(VERIFY_TOKEN)
        mock_time.return_value = FIXED_TIME
        mock_encrypt.return_value = "enc"
        mock_send.return_value = _make_login_response(servertime=TOKEN_EXPIRY - 1)
        mock_decrypt.return_value = _valid_challenge_json()

        result = JWTAuthStrategy.login(_make_passbolt_account())

        mock_decrypt.assert_called_once_with(ENCRYPTED_CHALLENGE, PASSPHRASE, SERVER_KEY_FINGERPRINT)
        self.assertIsInstance(result, JWTCredentials)
        self.assertEqual(result.access_token, ACCESS_TOKEN)
        self.assertEqual(result.refresh_token, REFRESH_TOKEN)

    @patch(_PATCH_TIME)
    @patch(_PATCH_UUID)
    @patch(_PATCH_DECRYPT)
    @patch(_PATCH_ENCRYPT)
    @patch(_PATCH_HTTP)
    def test_http_failure_raises(self, mock_send, mock_encrypt, mock_decrypt, mock_uuid4, mock_time):
        mock_uuid4.return_value = uuid.UUID(VERIFY_TOKEN)
        mock_time.return_value = FIXED_TIME
        mock_encrypt.return_value = "enc"
        mock_send.return_value = _make_login_response(servertime=TOKEN_EXPIRY - 1, success=False)

        with self.assertRaises(AuthenticationException) as ctx:
            JWTAuthStrategy.login(_make_passbolt_account())

        self.assertIn("Response isn't success", str(ctx.exception))

    @patch(_PATCH_TIME)
    @patch(_PATCH_UUID)
    @patch(_PATCH_DECRYPT)
    @patch(_PATCH_ENCRYPT)
    @patch(_PATCH_HTTP)
    def test_servertime_expired_raises(self, mock_send, mock_encrypt, mock_decrypt, mock_uuid4, mock_time):
        mock_uuid4.return_value = uuid.UUID(VERIFY_TOKEN)
        mock_time.return_value = FIXED_TIME
        mock_encrypt.return_value = "enc"
        mock_send.return_value = _make_login_response(servertime=TOKEN_EXPIRY + 1)

        with self.assertRaises(AuthenticationException) as ctx:
            JWTAuthStrategy.login(_make_passbolt_account())

        self.assertIn("expired", str(ctx.exception).lower())

    @patch(_PATCH_TIME)
    @patch(_PATCH_UUID)
    @patch(_PATCH_DECRYPT)
    @patch(_PATCH_ENCRYPT)
    @patch(_PATCH_HTTP)
    def test_invalid_schema_raises(self, mock_send, mock_encrypt, mock_decrypt, mock_uuid4, mock_time):
        mock_uuid4.return_value = uuid.UUID(VERIFY_TOKEN)
        mock_time.return_value = FIXED_TIME
        mock_encrypt.return_value = "enc"
        mock_send.return_value = _make_login_response(servertime=TOKEN_EXPIRY - 1)
        mock_decrypt.return_value = json.dumps({"version": "1.0.0"})  # missing required fields

        with self.assertRaises(AuthenticationException) as ctx:
            JWTAuthStrategy.login(_make_passbolt_account())

        self.assertIn("invalid challenge response", str(ctx.exception).lower())

    @patch(_PATCH_TIME)
    @patch(_PATCH_UUID)
    @patch(_PATCH_DECRYPT)
    @patch(_PATCH_ENCRYPT)
    @patch(_PATCH_HTTP)
    def test_wrong_verify_token_raises(self, mock_send, mock_encrypt, mock_decrypt, mock_uuid4, mock_time):
        mock_uuid4.return_value = uuid.UUID(VERIFY_TOKEN)
        mock_time.return_value = FIXED_TIME
        mock_encrypt.return_value = "enc"
        mock_send.return_value = _make_login_response(servertime=TOKEN_EXPIRY - 1)
        mock_decrypt.return_value = json.dumps({
            "version": "1.0.0",
            "domain": "https://passbolt.local/",
            "access_token": ACCESS_TOKEN,
            "refresh_token": REFRESH_TOKEN,
            "verify_token": "00000000-0000-0000-0000-000000000000",  # wrong token
        })

        with self.assertRaises(AuthenticationException) as ctx:
            JWTAuthStrategy.login(_make_passbolt_account())

        self.assertIn("wrong", str(ctx.exception).lower())


if __name__ == "__main__":
    unittest.main()
