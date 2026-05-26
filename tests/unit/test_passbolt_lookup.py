import unittest
import uuid
from unittest.mock import MagicMock, patch

from ansible.errors import AnsibleError

from ansible_collections.passbolt.passbolt_lookup.plugins.lookup.passbolt_lookup import (
    LookupModule,
)


RESOURCE_UUID_STR = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
RENDERED_ACCOUNT_KIT = "cmVuZGVyZWQta2l0"  # placeholder; value content is not exercised here
RENDERED_PASSPHRASE = "rendered-passphrase"
RAW_ACCOUNT_KIT_EXPR = "{{ lookup('ansible.builtin.env', 'PASSBOLT_ACCOUNT_KIT') }}"
RAW_PASSPHRASE_EXPR = "{{ lookup('ansible.builtin.env', 'PASSBOLT_PASSPHRASE') }}"

_PATCH_FACTORY = "ansible_collections.passbolt.passbolt_lookup.plugins.lookup.passbolt_lookup.PassboltAccountKitFactory.from_string"
_PATCH_CLIENT_CLS = "ansible_collections.passbolt.passbolt_lookup.plugins.lookup.passbolt_lookup.PassboltAPIClient"


def _make_lookup(rendered_passbolt_vars):
    """Construct a LookupModule with a templar that returns the supplied dict
    when called with the raw ``passbolt`` block, mimicking Ansible's
    Jinja2 rendering step."""
    lookup = LookupModule()
    templar = MagicMock()
    templar.template.return_value = rendered_passbolt_vars
    lookup._templar = templar
    return lookup


class TestPassboltVarsTemplating(unittest.TestCase):

    @patch(_PATCH_CLIENT_CLS)
    @patch(_PATCH_FACTORY)
    def test_jinja2_expressions_are_rendered_before_reaching_factory(
        self, mock_from_string, mock_client_cls
    ):
        """Regression test for GH #1: a literal {{ ... }} string in
        passbolt.account_kit / passbolt.passphrase must be rendered via the
        templar before being handed to PassboltAccountKitFactory.from_string()."""
        raw_passbolt_vars = {
            "account_kit": RAW_ACCOUNT_KIT_EXPR,
            "passphrase": RAW_PASSPHRASE_EXPR,
        }
        rendered_passbolt_vars = {
            "account_kit": RENDERED_ACCOUNT_KIT,
            "passphrase": RENDERED_PASSPHRASE,
        }

        lookup = _make_lookup(rendered_passbolt_vars)
        lookup.set_options = MagicMock()
        lookup.get_option = MagicMock(side_effect=lambda name: {"skip_ssl_verification": True, "timeout": 30}[name])

        mock_client = MagicMock()
        mock_client.login.return_value = True
        mock_client.logout.return_value = True
        mock_client.get_resource.return_value.to_dict.return_value = {"name": "ok"}
        mock_client_cls.return_value = mock_client

        lookup.run([RESOURCE_UUID_STR], variables={"passbolt": raw_passbolt_vars})

        # Templar must have been called with the raw passbolt block
        lookup._templar.template.assert_called_once_with(raw_passbolt_vars)

        # Factory must have been called with the rendered values, NOT the {{ ... }} literals
        args, _ = mock_from_string.call_args
        self.assertEqual(args[0], RENDERED_ACCOUNT_KIT)
        self.assertEqual(args[1], RENDERED_PASSPHRASE)
        self.assertNotIn("{{", args[0])
        self.assertNotIn("{{", args[1])

    @patch(_PATCH_CLIENT_CLS)
    @patch(_PATCH_FACTORY)
    def test_missing_passbolt_block_raises(self, mock_from_string, mock_client_cls):
        lookup = _make_lookup({})
        lookup.set_options = MagicMock()
        lookup.get_option = MagicMock(return_value=None)

        with self.assertRaises(AnsibleError) as ctx:
            lookup.run([RESOURCE_UUID_STR], variables={})

        self.assertIn("passbolt.account_kit", str(ctx.exception))
        mock_from_string.assert_not_called()

    @patch(_PATCH_CLIENT_CLS)
    @patch(_PATCH_FACTORY)
    def test_missing_passphrase_raises(self, mock_from_string, mock_client_cls):
        rendered = {"account_kit": RENDERED_ACCOUNT_KIT}
        lookup = _make_lookup(rendered)
        lookup.set_options = MagicMock()
        lookup.get_option = MagicMock(return_value=None)

        with self.assertRaises(AnsibleError) as ctx:
            lookup.run([RESOURCE_UUID_STR], variables={"passbolt": {"account_kit": "x"}})

        self.assertIn("passbolt.passphrase", str(ctx.exception))
        mock_from_string.assert_not_called()

    @patch(_PATCH_CLIENT_CLS)
    @patch(_PATCH_FACTORY)
    def test_omit_placeholder_in_account_kit_raises_clear_error(
        self, mock_from_string, mock_client_cls
    ):
        """When the customer uses default=(... | default(omit)) and both
        fallbacks are unset, Ansible's templar substitutes a string of the
        form ``__omit_place_holder__<hex>`` rather than dropping the key.
        Without an explicit check, that string would reach the factory and
        fail base64 decoding with a confusing message."""
        rendered = {
            "account_kit": "__omit_place_holder__deadbeef",
            "passphrase": RENDERED_PASSPHRASE,
        }
        lookup = _make_lookup(rendered)
        lookup.set_options = MagicMock()
        lookup.get_option = MagicMock(return_value=None)

        with self.assertRaises(AnsibleError) as ctx:
            lookup.run([RESOURCE_UUID_STR], variables={"passbolt": {"account_kit": "x", "passphrase": "y"}})

        self.assertIn("passbolt.account_kit", str(ctx.exception))
        mock_from_string.assert_not_called()


if __name__ == "__main__":
    unittest.main()
