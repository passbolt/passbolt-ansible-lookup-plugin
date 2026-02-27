import unittest
import uuid

from ansible_collections.passbolt.passbolt_lookup.plugins.module_utils.passbolt.entities.passbolt_resource import (
    PassboltResource,
)

# --- Fixture constants ---

RESOURCE_ID = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
RESOURCE_TYPE_ID = "d1d2d3d4-aaaa-bbbb-cccc-dddddddddddd"
METADATA_KEY_ID = "e1e2e3e4-ffff-0000-1111-222222222222"

FULL_API_DATA = {
    "id": RESOURCE_ID,
    "resource_type_id": RESOURCE_TYPE_ID,
    "metadata_key_id": METADATA_KEY_ID,
    "metadata_key_type": "user_key",
}

FULL_DECRYPTED_METADATA = {
    "name": "My Server Login",
    "username": "admin",
    "uris": ["https://server.example.com", "https://server2.example.com"],
    "description": "Production server credentials",
    "icon": {"emoji": "lock"},
    "custom_fields": [
        {"id": "cf-1", "metadata_key": "api_key"},
        {"id": "cf-2", "metadata_key": "region"},
    ],
}

FULL_DECRYPTED_SECRET = {
    "password": "S3cureP@ss!",
    "description": "Keep this safe",
    "totp": {
        "secret_key": "JBSWY3DPEHPK3PXP",
        "period": 30,
        "digits": 6,
        "algorithm": "SHA1",
    },
    "custom_fields": [
        {"id": "cf-1", "secret_value": "sk-live-abc123"},
        {"id": "cf-2", "secret_value": "us-east-1"},
    ],
}


class TestPassboltResourceFromApiJson(unittest.TestCase):

    def test_full_resource(self):
        resource = PassboltResource.from_api_json(
            FULL_API_DATA, FULL_DECRYPTED_METADATA, FULL_DECRYPTED_SECRET
        )

        self.assertEqual(resource.id, uuid.UUID(RESOURCE_ID))
        self.assertEqual(resource.name, "My Server Login")
        self.assertEqual(resource.username, "admin")
        self.assertEqual(resource.password, "S3cureP@ss!")
        self.assertEqual(resource.note, "Keep this safe")
        self.assertEqual(resource.description, "Production server credentials")
        self.assertEqual(
            resource.uris,
            ["https://server.example.com", "https://server2.example.com"],
        )
        self.assertEqual(resource.totp["secret_key"], "JBSWY3DPEHPK3PXP")
        self.assertEqual(resource.icon, {"emoji": "lock"})
        self.assertEqual(
            resource.custom_fields,
            {"api_key": "sk-live-abc123", "region": "us-east-1"},
        )
        self.assertIsNotNone(resource.resource_type)
        self.assertEqual(resource.resource_type.id, RESOURCE_TYPE_ID)

    def test_no_secret(self):
        resource = PassboltResource.from_api_json(
            FULL_API_DATA, FULL_DECRYPTED_METADATA, None
        )

        self.assertEqual(resource.name, "My Server Login")
        self.assertIsNone(resource.password)
        self.assertIsNone(resource.note)
        self.assertIsNone(resource.totp)
        self.assertEqual(resource.custom_fields, {})

    def test_password_only_no_custom_fields(self):
        metadata = {"name": "Simple Login", "username": "user1"}
        secret = {"password": "hunter2"}

        resource = PassboltResource.from_api_json(FULL_API_DATA, metadata, secret)

        self.assertEqual(resource.password, "hunter2")
        self.assertEqual(resource.custom_fields, {})
        self.assertIsNone(resource.totp)
        self.assertIsNone(resource.note)

    def test_custom_fields_only_no_password(self):
        metadata = {
            "name": "API Keys Only",
            "custom_fields": [{"id": "cf-1", "metadata_key": "api_key"}],
        }
        secret = {
            "custom_fields": [{"id": "cf-1", "secret_value": "sk-live-abc123"}],
        }

        resource = PassboltResource.from_api_json(FULL_API_DATA, metadata, secret)

        self.assertIsNone(resource.password)
        self.assertEqual(resource.custom_fields, {"api_key": "sk-live-abc123"})

    def test_single_uri_fallback(self):
        metadata = {"name": "Single URI", "uri": "https://login.example.com"}

        resource = PassboltResource.from_api_json(FULL_API_DATA, metadata, None)

        self.assertEqual(resource.uris, ["https://login.example.com"])

    def test_shared_metadata_key(self):
        data = {
            **FULL_API_DATA,
            "metadata_key_type": "shared_key",
        }

        resource = PassboltResource.from_api_json(
            data, FULL_DECRYPTED_METADATA, None
        )

        self.assertTrue(resource.is_shared())

    def test_user_metadata_key(self):
        resource = PassboltResource.from_api_json(
            FULL_API_DATA, FULL_DECRYPTED_METADATA, None
        )

        self.assertFalse(resource.is_shared())


class TestPassboltResourceToDict(unittest.TestCase):

    def test_full_resource(self):
        resource = PassboltResource.from_api_json(
            FULL_API_DATA, FULL_DECRYPTED_METADATA, FULL_DECRYPTED_SECRET
        )
        d = resource.to_dict()

        self.assertIn("name", d)
        self.assertIn("username", d)
        self.assertIn("password", d)
        self.assertIn("description", d)
        self.assertIn("note", d)
        self.assertIn("uris", d)
        self.assertIn("totp", d)
        self.assertIn("custom_fields", d)

    def test_omits_none_and_empty(self):
        resource = PassboltResource(name="Minimal", password="secret123")
        d = resource.to_dict()

        self.assertEqual(d, {"name": "Minimal", "password": "secret123"})

    def test_custom_fields_only(self):
        resource = PassboltResource(
            name="Keys", custom_fields={"api_key": "abc"}
        )
        d = resource.to_dict()

        self.assertNotIn("password", d)
        self.assertEqual(d["custom_fields"], {"api_key": "abc"})


if __name__ == "__main__":
    unittest.main()
