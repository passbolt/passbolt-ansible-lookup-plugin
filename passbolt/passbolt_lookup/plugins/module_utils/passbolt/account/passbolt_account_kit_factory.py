import base64
import binascii
import json
from http import HTTPMethod
from urllib.parse import urljoin

import jsonschema

from ansible_collections.passbolt.passbolt_lookup.plugins.module_utils.passbolt.account.passbolt_account import \
    PassboltAccount
from ansible_collections.passbolt.passbolt_lookup.plugins.module_utils.passbolt.api.api_request import APIRequest
from ansible_collections.passbolt.passbolt_lookup.plugins.module_utils.passbolt.cryptography.gnupg_service import \
    GnuPGService
from ansible_collections.passbolt.passbolt_lookup.plugins.module_utils.passbolt.http.http_client_service import \
    HTTPClientService
from ansible_collections.passbolt.passbolt_lookup.plugins.module_utils.passbolt.account.exceptions.passbolt_account_kit_deserialization_exception import \
    PassboltAccountKitDeserializationException


class PassboltAccountKitFactory(object):
    PGP_KEY_MAX_LENGTH = 50_000
    JSON_SCHEMA = {
        "type": "object",
        "required": [
            "domain",
            "user_id",
            "username",
            "first_name",
            "last_name",
            "user_private_armored_key",
            "server_public_armored_key",
            "user_public_armored_key",
            "security_token",
        ],
        "properties": {
            "domain": {
                "type": "string"
            },
            "user_id": {
                "type": "string",
                "format": "uuid"
            },
            "username": {
                "type": "string",
            },
            "first_name": {
                "type": "string",
                "minLength": 1,
                "maxLength": 255,
            },
            "last_name": {
                "type": "string",
                "minLength": 1,
                "maxLength": 255,
            },
            "security_token": {
                "type": "object",
                "required": [
                    "code",
                    "color",
                    "textcolor"
                ],
                "properties": {
                    "code": {
                        "type": "string",
                        "pattern": "^[a-zA-Z0-9-_]{3}$"
                    },
                    "color": {
                        "type": "string",
                        "format": "x-hex-color"
                    },
                    "textcolor": {
                        "type": "string",
                        "format": "x-hex-color"
                    }
                }
            },
            "user_private_armored_key": {
                "type": "string",
                "maxLength": PGP_KEY_MAX_LENGTH
            },
            "user_public_armored_key": {
                "type": "string",
                "maxLength": PGP_KEY_MAX_LENGTH
            },
            "server_public_armored_key": {
                "type": "string",
                "maxLength": PGP_KEY_MAX_LENGTH
            },
        },
    }

    @classmethod
    def from_string(cls, raw_account_kit: str, passphrase: str, verify: bool = True,
                    timeout: int = 30) -> PassboltAccount:
        # Decode and validate account kit
        account_kit_str = raw_account_kit.strip()
        if account_kit_str == "":
            raise PassboltAccountKitDeserializationException("Cannot deserialize empty account kit string.")
        try:
            decoded_account_kit_bytes = base64.b64decode(account_kit_str)
        except binascii.Error:
            raise PassboltAccountKitDeserializationException("Raw account kit string isn't valid base64.")

        decoded_account_kit_str = decoded_account_kit_bytes.decode('ascii')
        if not (decoded_account_kit_str.startswith("-----BEGIN PGP SIGNED MESSAGE-----")
                and decoded_account_kit_str.endswith("-----END PGP SIGNATURE-----\n")):
            raise PassboltAccountKitDeserializationException("Account kit doesn't seem to be a PGP signed message.")

        account_kit = json.loads(GnuPGService.verify(decoded_account_kit_str, None))
        try:
            jsonschema.validate(account_kit, cls.JSON_SCHEMA)
        except jsonschema.ValidationError:
            raise PassboltAccountKitDeserializationException("Invalid account kit format.")

        import_user_key_fingerprints = GnuPGService.import_key(account_kit["user_private_armored_key"], passphrase)
        if len(import_user_key_fingerprints) != 2:
            raise PassboltAccountKitDeserializationException("Expected 2 fingerprints to be imported when importing "
                                                             "user key in keyring, got %s." %
                                                             len(import_user_key_fingerprints))

        if import_user_key_fingerprints[0] != import_user_key_fingerprints[1]:
            raise PassboltAccountKitDeserializationException("Imported user key fingerprints don't match together.")
        user_key_fingerprint = import_user_key_fingerprints[0]

        GnuPGService.verify(decoded_account_kit_str, user_key_fingerprint)

        import_server_key_fingerprints = GnuPGService.import_key(account_kit["server_public_armored_key"], None)
        if len(import_server_key_fingerprints) > 1:
            raise PassboltAccountKitDeserializationException("Multiple keys have been imported when importing "
                                                             "server key in keyring, got %s." % len(import_server_key_fingerprints))

        res = HTTPClientService.send(
            APIRequest(HTTPMethod.GET, urljoin(account_kit["domain"], "auth/verify.json"), verify=verify,
                       timeout=timeout))
        server_advertised_fingerprint = res.body["fingerprint"]
        if len(import_server_key_fingerprints) > 0 and server_advertised_fingerprint != import_server_key_fingerprints[0]:
            raise PassboltAccountKitDeserializationException("Server announced fingerprint doesn't match imported "
                                                             "fingerprint from account kit.")

        return PassboltAccount(account_kit["user_id"], user_key_fingerprint, account_kit["username"],
                               passphrase, account_kit["domain"], server_advertised_fingerprint)
