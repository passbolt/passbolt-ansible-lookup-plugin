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
      "custom_fields": {
        "a key": "a value (secret)",
        "another key": "another value (secret)"
      },
  "description": "a searchable desc",
      "icon": {
        "background_color": "#E88BA8",
        "type": "keepass-icon-set",
        "value": 10
      },
      "name": "a random password",
      "note": "a secure note",
      "password": "darkside",
      "totp": {
        "algorithm": "SHA1",
        "digits": 6,
        "period": 30,
        "secret_key": "JBSWY3DPEHPK3PXP"
      },
      "uris": [
        "https://oneurl.com",
        "https://anotherurl.com"
      ],
      "username": "anakin"
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

- **API v5 Metadata Encryption**: Supports both shared and personal metadata-encrypted resources
- **Custom Fields**: Supports custom fields in both metadata and secret sections

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
