# Passbolt Ansible Lookup Plugin

## Configuration

This lookup plugin directly interact with the Passbolt server's API, and thus needs
to authenticate. In order to do that, it utilizes our **Account Kit**, which can be
downloaded in the Passbolt web UI, under `Profile` > `Desktop app setup` >
`Download your account kit`.

## Usage

Once installed, the collection can be used in your playbook by adding it to its `collections` section and by calling it. The plugin accepts either a resource UUID as the first positional argument, **or** one or more of the `name`, `username`, `uri` keyword arguments to resolve a resource by its decrypted metadata:

```yaml
# By UUID (recommended for production):
lookup('passbolt.passbolt_lookup.passbolt_lookup', '<resource UUID>')

# By name:
lookup('passbolt.passbolt_lookup.passbolt_lookup', name='acme-db-production')

# By any combination of name, username, uri (composed as AND):
lookup('passbolt.passbolt_lookup.passbolt_lookup', name='db-prod', username='app', uri='https://db.acme.internal')
```

The big win of name/username/uri lookup is that it lets you build the lookup key from playbook variables something a static UUID cannot do:

```yaml
# Multi-tenant: resolve a different secret per customer/environment:
lookup('passbolt.passbolt_lookup.passbolt_lookup', name="{{ customer }}-db-{{ env }}")
```

### Filter semantics and disambiguation

- All supplied filters must match (AND-composition). Comparison is **exact and case-sensitive**.
- The `uri` filter matches if **any** URI in the resource's URI list equals the supplied value.
- **First match wins**: if multiple resources satisfy the filters, the plugin returns the first one encountered in the server's pagination order. Since the product doesn't does not enforce uniqueness on resource names, collisions are possible especially in shared vaults. The plugin does not try to detect or arbitrate them.
- **For production playbooks, pin lookups by UUID** whenever possible, or combine filters (`name + uri`, `username + uri`) so that the resolution is unambiguous on the operator's side. The plugin will not warn you if more than one resource matched (by design).
- A signature verification failure on a scanned resource is logged via `display.warning()` with the offending resource UUID and the scan continues (so a single tampered or malformed resource cannot block automation).

### Performance

The filter-based resolution path is **strictly slower** than the UUID path: it walks `GET /resources.json` page by page and decrypts each resource's metadata until a match is found. Concretely:
- **UUID lookup**: 1 HTTP round-trip, 1 metadata decryption.
- **Filter lookup**: up to N HTTP round-trips and M metadata decryptions, where M is the number of resources scanned before the first match.

Recommendations:

- For hot paths and tight loops, use UUIDs.
- If you need filter-based lookup inside a loop, resolve once at the top of the play and reuse the value with `set_fact`.
- Each filter lookup decrypts metadata for the scanned resources. The Ansible controller host should therefore be considered a trust-sensitive environment even when only metadata is exposed (names, usernames and URIs disclose organisational topology)

#### Metadata session keys (filter lookups only)

Filter lookups (`name`/`username`/`uri`) reuse the session keys passbolt caches server-side, so metadata decrypts fast instead of running a slow private-key operation on every scanned resource. Missing or stale keys fall back automatically, with identical results.

> [IMPORTANT]
> This cache is filled by clients that have already opened your resources, the plugin only reads it. On large vaults e.g., 7K+, a filter lookup on resources that no client has ever loaded is slow. The easiest fix is to log in to your passbolt account once (web, mobile or desktop) and the cache builds itself. Pinning by UUID skips the scan entirely and is recommended for better performances overall.

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

| Name                    | Mandatory? | Format  | Default | Description                                                                                  |
|-------------------------|------------|---------|---------|----------------------------------------------------------------------------------------------|
| `name`                  | ❌          | String  | `None`  | Filter by decrypted resource name (exact, case-sensitive). Mutually exclusive with the UUID. |
| `username`              | ❌          | String  | `None`  | Filter by decrypted resource username (exact, case-sensitive).                               |
| `uri`                   | ❌          | String  | `None`  | Filter by decrypted resource URI (exact, case-sensitive). Matches any URI in the list.       |
| `skip_ssl_verification` | ❌          | Boolean | `false` | Should we ignore SSL validation errors when calling the Passbolt API?                        |
| `timeout`               | ❌          | Integer | `30`    | How long to wait for the Passbolt API to reply.                                              |

At least one of: a UUID positional argument, or one of `name`/`username`/`uri`
must be supplied. Mixing a positional UUID with filter kwargs is rejected.

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

### Running Tests

Unit tests can be run from the repository root without installing the collection:

```bash
python -m pytest tests/unit/ -v
```

Tests use `unittest.mock` to mock HTTP and GnuPG dependencies, so no Passbolt
server or GPG keyring is required.

## Copyright & License

(c) 2025 Passbolt SA

Passbolt is registered trademark of Passbolt S.A.

AGPLv3 - https://www.gnu.org/licenses/agpl-3.0.en.html
