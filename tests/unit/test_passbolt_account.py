import unittest
from urllib.parse import urljoin

from ansible_collections.passbolt.passbolt_lookup.plugins.module_utils.passbolt.account.passbolt_account import (
    PassboltAccount,
)


def _make_account(fullbase_url):
    return PassboltAccount(
        id="user-id",
        key_id="key-id",
        email="test@example.com",
        passphrase="passphrase",
        fullbase_url=fullbase_url,
        server_key_id="server-key-id",
    )


class TestFullbaseUrl(unittest.TestCase):

    def test_keeps_path_without_trailing_slash(self):
        # passbolt cloud account kits have a domain like https://cloud.passbolt.com/<organisation>
        account = _make_account("https://cloud.passbolt.com/acme")

        self.assertEqual(account.fullbase_url, "https://cloud.passbolt.com/acme/")
        self.assertEqual(urljoin(account.fullbase_url, "auth/jwt/login.json"),
                         "https://cloud.passbolt.com/acme/auth/jwt/login.json")

    def test_keeps_path_with_trailing_slash(self):
        account = _make_account("https://cloud.passbolt.com/acme/")

        self.assertEqual(account.fullbase_url, "https://cloud.passbolt.com/acme/")

    def test_domain_without_path(self):
        account = _make_account("https://passbolt.local")

        self.assertEqual(account.fullbase_url, "https://passbolt.local/")
