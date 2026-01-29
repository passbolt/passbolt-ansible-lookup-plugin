# Passbolt Ansible Lookup Plugin

## Configuration

This lookup plugin directly interact with the Passbolt server's API, and thus needs
to authenticate. In order to do that, it utilizes our **Account Kit**, which can be
downloaded in the Passbolt web UI, under `Profile` > `Desktop app setup` >
`Download your account kit`.

## Usage

Once installed, the collection can be used in your playbook by adding it to its
`collections` section and by calling it:

```yaml
lookup('passbolt.passbolt_lookup.passbolt_lookup', '<resource UUID>')
```

### Return format
The lookup returns a dictionary with two sections:
- metadata (decrypted public information)
- secret (decrypted sensitive information)

```json
  {
    "metadata": {
        "custom_fields": [
            {
                "id": "1834f12f-2a0e-4bad-83c7-9a7c5c1260bb",
                "metadata_key": "A custom key",
                "type": "text"
            },
            {
                "id": "b0f7f950-9535-449e-a8a4-0972ebcc0e17",
                "metadata_key": "Another custom key",
                "type": "text"
            }
        ],
        "description": "An unencrypted description if it exists",
        "icon": {
            "background_color": "#FFE144",
            "type": "keepass-icon-set",
            "value": 9
        },
        "name": "The name of the resource",
        "uris": [
            "https://urlX.com",
            "https://urlY.com"
        ],
        "username": "YOUR_USERNAME"
    },
    "secret": {
        "custom_fields": [
            {
                "id": "1834f12f-2a0e-4bad-83c7-9a7c5c1260bb",
                "secret_value": "The secret value for custom fields",
                "type": "text"
            },
            {
                "id": "b0f7f950-9535-449e-a8a4-0972ebcc0e17",
                "secret_value": "A second secret value for custom fields",
                "type": "text"
            }
        ],
        "description": "The secure note if it exists",
        "password": "The super secret password",
        "totp": {
            "algorithm": "SHA1",
            "digits": 6,
            "period": 30,
            "secret_key": "The TOTP secret key"
        }
    }
}
```

### Options

| Name                    | Mandatory? | Format  | Default | Description                                                           |
|-------------------------|------------|---------|---------|-----------------------------------------------------------------------|
| `skip_ssl_verification` | ❌          | Boolean | `false` | Should we ignore SSL validation errors when calling the Passbolt API? |
| `timeout`               | ❌          | Integer | `30`    | How long to wait for the Passbolt API to reply.                       |

### Variables

| Name                   | Mandatory? | Description                              |
|------------------------|------------|------------------------------------------|
| `passbolt.account_kit` | ✅          | The content of the Passbolt account kit. |
| `passbolt.passphrase`  | ✅          | The passphrase for the Passbolt account. |

> ⚠️ Both of these variables are considered secrets and should be treated as such:
> please avoid storing them unencrypted, please use [Ansible vault](https://docs.ansible.com/projects/ansible/latest/vault_guide/index.html)
> or similar for storing those.

### Supported Features

- **API v5 Metadata Encryption**: Supports both `user_key` and `shared_key` metadata encryption types
- **TOTP**: Returns TOTP configuration if present (secret_key, algorithm, digits, period)
- **Custom Fields**: Supports custom fields in both metadata and secret sections

### Error Handling

The plugin raises specific exceptions for different error scenarios:

| Exception              | Description                                              |
|------------------------|----------------------------------------------------------|
| `InvalidResourceId`    | The provided UUID is not a valid UUIDv4 format           |
| `ResourceNotFound`     | Resource doesn't exist or user lacks access (404/401/403)|
| `ResourceDeleted`      | The resource has been soft-deleted                       |
| `SecretShareMissing`   | No secret share found for the authenticated user         |
| `MetadataMissing`      | Resource has no encrypted metadata                       |
| `MetadataKeyNotShared` | Shared metadata key is not accessible by the user        |
| `DecryptError`         | Failed to decrypt metadata or secret (wrong key/corrupt) |
| `SchemaValidationError`| Decrypted data doesn't match expected JSON schema        |
| `IntegrityError`       | Response ID doesn't match requested resource ID          |

## Development

This project uses Python, and we recommend creating a [virtual environment](https://docs.python.org/3/library/venv.html)
to handle dependencies:

```bash
python -m venv .venv
source .venv/bin/activate
```

Once the virtual environment activated, dependencies can be installed using
the following command:

```bash
pip install -r passbolt/passbolt_lookup/requirements.txt
```

This project is using an Ansible collection, named `passbolt_lookup` and
under the `passbolt` namespace. The [lookup plugin](passbolt/passbolt_lookup/plugins/lookup/passbolt_lookup.py)
is simple and utilizes a local Passbolt API client, which code is located
under the [module_utils](passbolt/passbolt_lookup/plugins/module_utils/passbolt)
directory.

Installing the collection can be done using the following command:

```bash
# Add --force to override the local install, useful when developing.
ansible-galaxy collection install ./passbolt
```

A sample (and simple) [playbook](playbook.yaml) is provided for helping in
testing the lookup plugin using a debug call.

## Copyright & License

(c) 2025 Passbolt SA

Passbolt is registered trademark of Passbolt S.A.

AGPLv3 - https://www.gnu.org/licenses/agpl-3.0.en.html
