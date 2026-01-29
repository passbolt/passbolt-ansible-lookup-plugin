import json
import time
import uuid
from urllib.parse import urljoin

import jsonschema

from ansible_collections.passbolt.passbolt_lookup.plugins.module_utils.passbolt.account.passbolt_account import \
    PassboltAccount
from ansible_collections.passbolt.passbolt_lookup.plugins.module_utils.passbolt.auth.jwt_credentials import \
    JWTCredentials
from ansible_collections.passbolt.passbolt_lookup.plugins.module_utils.passbolt.api.api_request import APIRequest
from ansible_collections.passbolt.passbolt_lookup.plugins.module_utils.passbolt.auth.auth_strategy import AuthStrategy
from ansible_collections.passbolt.passbolt_lookup.plugins.module_utils.passbolt.cryptography.gnupg_service import \
    GnuPGService
from ansible_collections.passbolt.passbolt_lookup.plugins.module_utils.passbolt.http.http_client_service import \
    HTTPClientService
from ansible_collections.passbolt.passbolt_lookup.plugins.module_utils.passbolt.http.http_method import HTTPMethod
from ansible_collections.passbolt.passbolt_lookup.plugins.module_utils.passbolt.auth.auth_credentials import AuthCredentials
from ansible_collections.passbolt.passbolt_lookup.plugins.module_utils.passbolt.auth.exceptions.authentication_exception import \
    AuthenticationException


class JWTAuthStrategy(AuthStrategy):
    VERIFY_TOKEN_LIFETIME_SECONDS = 30
    DECRYPTED_CHALLENGE_RESPONSE_SCHEMA = {
        "type": "object",
        "required": [
            "version",
            "domain",
            "access_token",
            "refresh_token",
            "verify_token",
        ],
        "properties": {
            "version": {
                "type": "string",
                "const": "1.0.0",
            },
            "domain": {
                "type": "string",
            },
            "access_token": {
                "type": "string",
            },
            "refresh_token": {
                "type": "string",
                "format": "uuid",
            },
            "verify_token": {
                "type": "string",
                "format": "uuid",
            }
        }
    }

    @classmethod
    def login(cls, passbolt_account: PassboltAccount, verify: bool = True, timeout: int = 30) -> AuthCredentials:
        token_expiry = int(time.time() + cls.VERIFY_TOKEN_LIFETIME_SECONDS)
        challenge = {
            "version": "1.0.0",
            "domain": passbolt_account.fullbase_url,
            "verify_token": str(uuid.uuid4()),
            "verify_token_expiry": token_expiry
        }
        encrypted_challenge = GnuPGService.encrypt(json.dumps(challenge), passbolt_account.server_key_id,
                                                   passbolt_account.key_id, passbolt_account.passphrase)
        challenge_body = {
            "user_id": passbolt_account.id,
            "challenge": encrypted_challenge,
        }
        api_request = APIRequest(HTTPMethod.POST, urljoin(passbolt_account.fullbase_url, "auth/jwt/login.json"),
                                 body=challenge_body, verify=verify, timeout=timeout)
        api_response = HTTPClientService.send(api_request)
        if not api_response.is_success():
            raise AuthenticationException("Response isn't success.")

        current_time = time.time()
        if current_time > token_expiry or api_response.header["servertime"] > token_expiry:
            raise AuthenticationException("The verification token sent to the server expired.")

        decrypted_challenge = json.loads(
            GnuPGService.decrypt(api_response.body["challenge"], passbolt_account.passphrase))
        try:
            jsonschema.validate(decrypted_challenge, cls.DECRYPTED_CHALLENGE_RESPONSE_SCHEMA)
        except jsonschema.ValidationError:
            raise AuthenticationException("The server returned an invalid challenge response.")

        if decrypted_challenge["verify_token"] != challenge["verify_token"]:
            raise AuthenticationException("The verification token returned by the server is wrong.")

        return JWTCredentials(decrypted_challenge['access_token'], decrypted_challenge["refresh_token"])

    @classmethod
    def logout(cls, passbolt_account: PassboltAccount, jwt_credentials: JWTCredentials, verify: bool = True,
               timeout: int = 30) -> bool:
        api_request = APIRequest(HTTPMethod.POST, urljoin(passbolt_account.fullbase_url, "auth/jwt/logout.json"),
                                 auth_credentials=jwt_credentials, body={"refresh_token": jwt_credentials.refresh_token},
                                 verify=verify, timeout=timeout)
        api_response = HTTPClientService.send(api_request)
        return api_response.is_success()
