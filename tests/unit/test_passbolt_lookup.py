import unittest
import uuid
from unittest.mock import MagicMock, patch
from ansible.errors import AnsibleError

from ansible_collections.passbolt.passbolt_lookup.plugins.lookup.passbolt_lookup import (
    LookupModule,
    UUID_REGEX,
)


VARIABLES = {
    "passbolt": {
        "account_kit": "fake-account-kit",
        "passphrase": "fake-passphrase",
    }
}

RESOURCE_UUID_STR = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
RENDERED_ACCOUNT_KIT = "cmVuZGVyZWQta2l0"  # placeholder; value content is not exercised here
RENDERED_PASSPHRASE = "rendered-passphrase"
RAW_ACCOUNT_KIT_EXPR = "{{ lookup('ansible.builtin.env', 'PASSBOLT_ACCOUNT_KIT') }}"
RAW_PASSPHRASE_EXPR = "{{ lookup('ansible.builtin.env', 'PASSBOLT_PASSPHRASE') }}"
VALID_UUID = "44bfd25f-ca08-4415-9975-45ed92c6a737"
RESOLVED_UUID = "11111111-1111-1111-1111-111111111111"

_PATCH_FACTORY = "ansible_collections.passbolt.passbolt_lookup.plugins.lookup.passbolt_lookup.PassboltAccountKitFactory"
_PATCH_API_CLIENT = "ansible_collections.passbolt.passbolt_lookup.plugins.lookup.passbolt_lookup.PassboltAPIClient"


def _make_lookup(rendered_passbolt_vars={}, direct_options=None):
    """Build a LookupModule with options pre-applied (skipping the real DOCUMENTATION pipeline).
    and mimick Ansible's Jinja2 rendering."""
    lookup = LookupModule()
    
    templar = MagicMock()
    templar.template.return_value = rendered_passbolt_vars
    lookup._templar = templar

    options = {
        "name": None,
        "username": None,
        "uri": None,
        "skip_ssl_verification": True,
        "timeout": 30,
    }
    if direct_options:
        options.update(direct_options)

    lookup.set_options = MagicMock()
    lookup.get_option = MagicMock(side_effect=lambda key: options.get(key))
    return lookup


def _stub_api_client(mock_api_client, decrypted_resource=None):
    instance = MagicMock()
    instance.login.return_value = True
    instance.logout.return_value = True
    resource_obj = MagicMock()
    resource_obj.to_dict.return_value = decrypted_resource or {"name": "stub"}
    instance.get_resource.return_value = resource_obj
    instance.find_resource_uuid_by_filters.return_value = uuid.UUID(RESOLVED_UUID)
    mock_api_client.return_value = instance
    return instance


class TestPassboltVarsTemplating(unittest.TestCase):

    @patch(_PATCH_API_CLIENT)
    @patch(_PATCH_FACTORY)
    def test_jinja2_expressions_are_rendered_before_reaching_factory(
        self, mock_factory, mock_api_client
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

        lookup = _make_lookup(rendered_passbolt_vars=rendered_passbolt_vars)

        mock_client = MagicMock()
        mock_client.login.return_value = True
        mock_client.logout.return_value = True
        mock_client.get_resource.return_value.to_dict.return_value = {"name": "ok"}
        mock_api_client.return_value = mock_client

        lookup.run([RESOURCE_UUID_STR], variables={"passbolt": raw_passbolt_vars})

        # Templar must have been called with the raw passbolt block
        lookup._templar.template.assert_called_once_with(raw_passbolt_vars)

        # Factory must have been called with the rendered values, NOT the {{ ... }} literals
        args, _ = mock_factory.from_string.call_args
        self.assertEqual(args[0], RENDERED_ACCOUNT_KIT)
        self.assertEqual(args[1], RENDERED_PASSPHRASE)
        self.assertNotIn("{{", args[0])
        self.assertNotIn("{{", args[1])

    @patch(_PATCH_API_CLIENT)
    @patch(_PATCH_FACTORY)
    def test_missing_passbolt_block_raises(self, mock_factory, mock_api_client):
        lookup = _make_lookup()
        lookup.set_options = MagicMock()
        lookup.get_option = MagicMock(return_value=None)

        with self.assertRaises(AnsibleError) as ctx:
            lookup.run([RESOURCE_UUID_STR], variables={})

        self.assertIn("passbolt.account_kit", str(ctx.exception))
        mock_factory.assert_not_called()

    @patch(_PATCH_API_CLIENT)
    @patch(_PATCH_FACTORY)
    def test_missing_passphrase_raises(self, mock_factory, mock_api_client):
        rendered = {"account_kit": RENDERED_ACCOUNT_KIT}
        lookup = _make_lookup(rendered_passbolt_vars=rendered)
        lookup.set_options = MagicMock()
        lookup.get_option = MagicMock(return_value=None)

        with self.assertRaises(AnsibleError) as ctx:
            lookup.run([RESOURCE_UUID_STR], variables={"passbolt": {"account_kit": "x"}})

        self.assertIn("passbolt.passphrase", str(ctx.exception))
        mock_factory.from_string.assert_not_called()

    @patch(_PATCH_API_CLIENT)
    @patch(_PATCH_FACTORY)
    def test_omit_placeholder_in_account_kit_raises_clear_error(
        self, mock_factory, mock_api_client
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
        lookup = _make_lookup(rendered_passbolt_vars=rendered)
        lookup.set_options = MagicMock()
        lookup.get_option = MagicMock(return_value=None)

        with self.assertRaises(AnsibleError) as ctx:
            lookup.run([RESOURCE_UUID_STR], variables={"passbolt": {"account_kit": "x", "passphrase": "y"}})

        self.assertIn("passbolt.account_kit", str(ctx.exception))
        mock_factory.from_string.assert_not_called()


class TestUuidRegex(unittest.TestCase):

    def test_matches_canonical_uuid(self):
        self.assertTrue(UUID_REGEX.match("44bfd25f-ca08-4415-9975-45ed92c6a737"))

    def test_matches_uppercase_uuid(self):
        self.assertTrue(UUID_REGEX.match("44BFD25F-CA08-4415-9975-45ED92C6A737"))

    def test_rejects_name_like_string(self):
        self.assertIsNone(UUID_REGEX.match("acme-db-production"))

    def test_rejects_partial_uuid(self):
        self.assertIsNone(UUID_REGEX.match("44bfd25f-ca08-4415"))

    def test_rejects_uuid_with_extra_chars(self):
        self.assertIsNone(UUID_REGEX.match(" 44bfd25f-ca08-4415-9975-45ed92c6a737"))


class TestRunDispatchUuid(unittest.TestCase):

    @patch(_PATCH_FACTORY)
    @patch(_PATCH_API_CLIENT)
    def test_uuid_positional_calls_get_resource(self, mock_api_client, mock_factory):
        api = _stub_api_client(mock_api_client)
        plugin = _make_lookup(rendered_passbolt_vars=VARIABLES["passbolt"])

        result = plugin.run([VALID_UUID], variables=VARIABLES)

        self.assertEqual(result, [{"name": "stub"}])
        api.get_resource.assert_called_once_with(uuid.UUID(VALID_UUID))
        api.find_resource_uuid_by_filters.assert_not_called()

    @patch(_PATCH_FACTORY)
    @patch(_PATCH_API_CLIENT)
    def test_uppercase_uuid_accepted(self, mock_api_client, mock_factory):
        api = _stub_api_client(mock_api_client)
        plugin = _make_lookup(rendered_passbolt_vars=VARIABLES["passbolt"])

        plugin.run([VALID_UUID.upper()], variables=VARIABLES)

        api.get_resource.assert_called_once_with(uuid.UUID(VALID_UUID))
        api.find_resource_uuid_by_filters.assert_not_called()


class TestRunDispatchFilters(unittest.TestCase):

    @patch(_PATCH_FACTORY)
    @patch(_PATCH_API_CLIENT)
    def test_name_kwarg_routes_through_resolver(self, mock_api_client, mock_factory):
        api = _stub_api_client(mock_api_client)
        plugin = _make_lookup(direct_options={"name": "acme-db"},
                              rendered_passbolt_vars=VARIABLES["passbolt"])

        plugin.run([], variables=VARIABLES)

        api.find_resource_uuid_by_filters.assert_called_once_with(
            expected_name="acme-db", expected_username=None, expected_uri=None
        )
        api.get_resource.assert_called_once_with(uuid.UUID(RESOLVED_UUID))

    @patch(_PATCH_FACTORY)
    @patch(_PATCH_API_CLIENT)
    def test_all_filter_kwargs_forwarded(self, mock_api_client, mock_factory):
        api = _stub_api_client(mock_api_client)
        plugin = _make_lookup(direct_options={
            "name": "db-prod",
            "username": "app",
            "uri": "https://db.acme.internal",
        }, rendered_passbolt_vars=VARIABLES["passbolt"])

        plugin.run([], variables=VARIABLES)

        api.find_resource_uuid_by_filters.assert_called_once_with(
            expected_name="db-prod", expected_username="app", expected_uri="https://db.acme.internal"
        )

    @patch(_PATCH_FACTORY)
    @patch(_PATCH_API_CLIENT)
    def test_username_only_filter(self, mock_api_client, mock_factory):
        api = _stub_api_client(mock_api_client)
        plugin = _make_lookup(direct_options={"username": "root"},
                              rendered_passbolt_vars=VARIABLES["passbolt"])

        plugin.run([], variables=VARIABLES)

        api.find_resource_uuid_by_filters.assert_called_once_with(
            expected_name=None, expected_username="root", expected_uri=None
        )

    @patch(_PATCH_FACTORY)
    @patch(_PATCH_API_CLIENT)
    def test_uri_only_filter(self, mock_api_client, mock_factory):
        api = _stub_api_client(mock_api_client)
        plugin = _make_lookup(direct_options={"uri": "https://x"},
                              rendered_passbolt_vars=VARIABLES["passbolt"])

        plugin.run([], variables=VARIABLES)

        api.find_resource_uuid_by_filters.assert_called_once_with(
            expected_name=None, expected_username=None, expected_uri="https://x"
        )


class TestRunValidationErrors(unittest.TestCase):

    @patch(_PATCH_FACTORY)
    @patch(_PATCH_API_CLIENT)
    def test_no_args_raises(self, mock_api_client, mock_factory):
        plugin = _make_lookup(rendered_passbolt_vars=VARIABLES["passbolt"])

        with self.assertRaises(AnsibleError) as ctx:
            plugin.run([], variables=VARIABLES)

        self.assertIn("UUID positional argument or at least one", str(ctx.exception))
        mock_api_client.assert_not_called()

    @patch(_PATCH_FACTORY)
    @patch(_PATCH_API_CLIENT)
    def test_too_many_positional_raises(self, mock_api_client, mock_factory):
        plugin = _make_lookup(rendered_passbolt_vars=VARIABLES["passbolt"])

        with self.assertRaises(AnsibleError) as ctx:
            plugin.run([VALID_UUID, "extra"], variables=VARIABLES)

        self.assertIn("at most 1 positional argument", str(ctx.exception))
        mock_api_client.assert_not_called()

    @patch(_PATCH_FACTORY)
    @patch(_PATCH_API_CLIENT)
    def test_non_uuid_positional_raises(self, mock_api_client, mock_factory):
        plugin = _make_lookup(rendered_passbolt_vars=VARIABLES["passbolt"])

        with self.assertRaises(AnsibleError) as ctx:
            plugin.run(["acme-db-production"], variables=VARIABLES)

        self.assertIn("must be a valid UUID", str(ctx.exception))
        mock_api_client.assert_not_called()

    @patch(_PATCH_FACTORY)
    @patch(_PATCH_API_CLIENT)
    def test_positional_uuid_with_filter_kwargs_raises(self, mock_api_client, mock_factory):
        plugin = _make_lookup(direct_options={"name": "acme-db"},
                              rendered_passbolt_vars=VARIABLES["passbolt"])

        with self.assertRaises(AnsibleError) as ctx:
            plugin.run([VALID_UUID], variables=VARIABLES)

        self.assertIn("Cannot combine", str(ctx.exception))
        mock_api_client.assert_not_called()

    def test_missing_account_kit_raises(self):
        plugin = _make_lookup()

        with self.assertRaises(AnsibleError) as ctx:
            plugin.run([VALID_UUID], variables={"passbolt": {"passphrase": "x"}})

        self.assertIn("account_kit", str(ctx.exception))

    def test_missing_passphrase_raises(self):
        passbolt_vars = {"account_kit": "x"}
        plugin = _make_lookup(rendered_passbolt_vars=passbolt_vars)

        with self.assertRaises(AnsibleError) as ctx:
            plugin.run([VALID_UUID], variables={"passbolt": passbolt_vars})

        self.assertIn("passphrase", str(ctx.exception))


class TestRunRegression(unittest.TestCase):
    """UUID code path must remain byte-for-byte unchanged."""

    @patch(_PATCH_FACTORY)
    @patch(_PATCH_API_CLIENT)
    def test_uuid_path_does_not_call_find_resource(self, mock_api_client, mock_factory):
        api = _stub_api_client(mock_api_client)
        plugin = _make_lookup(rendered_passbolt_vars=VARIABLES["passbolt"])

        plugin.run([VALID_UUID], variables=VARIABLES)

        api.find_resource_uuid_by_filters.assert_not_called()

    @patch(_PATCH_FACTORY)
    @patch(_PATCH_API_CLIENT)
    def test_returns_list_with_single_resource_dict(self, mock_api_client, mock_factory):
        _stub_api_client(mock_api_client, decrypted_resource={"name": "x", "password": "p"})
        plugin = _make_lookup(rendered_passbolt_vars=VARIABLES["passbolt"])

        result = plugin.run([VALID_UUID], variables=VARIABLES)

        self.assertEqual(result, [{"name": "x", "password": "p"}])

    @patch(_PATCH_FACTORY)
    @patch(_PATCH_API_CLIENT)
    def test_login_logout_called(self, mock_api_client, mock_factory):
        api = _stub_api_client(mock_api_client)
        plugin = _make_lookup(rendered_passbolt_vars=VARIABLES["passbolt"])

        plugin.run([VALID_UUID], variables=VARIABLES)

        api.login.assert_called_once()
        api.logout.assert_called_once()

    @patch(_PATCH_FACTORY)
    @patch(_PATCH_API_CLIENT)
    def test_filters_path_also_calls_logout(self, mock_api_client, mock_factory):
        api = _stub_api_client(mock_api_client)
        plugin = _make_lookup(direct_options={"name": "acme-db"},
                              rendered_passbolt_vars=VARIABLES["passbolt"])

        plugin.run([], variables=VARIABLES)

        api.login.assert_called_once()
        api.logout.assert_called_once()


class TestRunWrapsExceptions(unittest.TestCase):

    @patch(_PATCH_FACTORY)
    @patch(_PATCH_API_CLIENT)
    def test_lookup_error_wrapped_as_ansible_error(self, mock_api_client, mock_factory):
        api = _stub_api_client(mock_api_client)
        api.find_resource_uuid_by_filters.side_effect = LookupError("no match")
        plugin = _make_lookup(direct_options={"name": "ghost"},
                              rendered_passbolt_vars=VARIABLES["passbolt"])

        with self.assertRaises(AnsibleError) as ctx:
            plugin.run([], variables=VARIABLES)

        self.assertIn("Passbolt lookup failed", str(ctx.exception))
        self.assertIn("no match", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
