from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

DOCUMENTATION = r"""
  name: passbolt_lookup
  author: Passbolt <contact@passbolt.com>
  version_added: "0.1"
  short_description: Passbolt Lookup Plugin
  description:
      - This lookup plugin returns a resource stored in Passbolt.
      - Pass a Passbolt resource UUID as the first positional argument, or
        use one or more of the C(name), C(username), C(uri) keyword arguments
        to resolve a resource by its decrypted metadata.
      - When filters are used, all supplied filters must match (AND-composition,
        exact case-sensitive). The first match in the server's pagination order
        is returned; pin by UUID in production or refine filters when uniqueness
        is required.
  options:
    _terms:
      description:
        - Passbolt resource UUID to query. Optional when at least one of
          C(name), C(username) or C(uri) is provided.
      required: False
    name:
      description:
        - Filter by decrypted resource name (exact, case-sensitive).
      type: str
      required: False
    username:
      description:
        - Filter by decrypted resource username (exact, case-sensitive).
      type: str
      required: False
    uri:
      description:
        - Filter by decrypted resource URI (exact, case-sensitive). Matches
          if any URI in the resource's URI list equals this value.
      type: str
      required: False
    skip_ssl_verification:
      description:
        - Skip SSL verification when doing HTTP calls with the Passbolt API.
      type: bool
      default: false
    timeout:
      description:
        - How long to wait for the Passbolt API to reply.
      type: int
      default: 30
"""

import re
import uuid

from ansible.errors import AnsibleError
from ansible.plugins.lookup import LookupBase
from ansible.utils.display import Display

from ansible_collections.passbolt.passbolt_lookup.plugins.module_utils.passbolt.passbolt_api_client import \
    PassboltAPIClient
from ansible_collections.passbolt.passbolt_lookup.plugins.module_utils.passbolt.account.passbolt_account_kit_factory import \
    PassboltAccountKitFactory

display = Display()

UUID_REGEX = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)

_OMIT_PLACEHOLDER_PREFIX = '__omit_place_holder__'


def _is_omit_placeholder(value):
    return isinstance(value, str) and value.startswith(_OMIT_PLACEHOLDER_PREFIX)


class LookupModule(LookupBase):
    ACCOUNT_KIT_OPTION_KEY = 'account_kit'
    ACCOUNT_PASSPHRASE_OPTION_KEY = 'passphrase'

    def run(self, terms, variables=None, **kwargs):
        self.set_options(var_options=variables, direct=kwargs)

        passbolt_vars = self._templar.template(variables.get('passbolt', {}))

        for required_key in (self.ACCOUNT_KIT_OPTION_KEY, self.ACCOUNT_PASSPHRASE_OPTION_KEY):
            if required_key not in passbolt_vars or _is_omit_placeholder(passbolt_vars[required_key]):
                raise AnsibleError(
                    "Variable 'passbolt.%s' is required but not provided." % required_key
                )

        name_filter = self.get_option('name')
        username_filter = self.get_option('username')
        uri_filter = self.get_option('uri')
        has_filters = any(f is not None for f in (name_filter, username_filter, uri_filter))

        if len(terms) > 1:
            raise AnsibleError("expected at most 1 positional argument, got %d" % len(terms))

        if len(terms) == 1:
            positional = terms[0]
            if has_filters:
                raise AnsibleError(
                    "Cannot combine a positional UUID with name/username/uri filters; "
                    "use one or the other."
                )
            if not isinstance(positional, str) or not UUID_REGEX.match(positional):
                raise AnsibleError(
                    "Positional argument must be a valid UUID. To resolve by name, "
                    "username or URI, pass them as keyword arguments instead."
                )
            resolution_mode = "uuid"
        else:
            if not has_filters:
                raise AnsibleError(
                    "expected either a UUID positional argument or at least one of "
                    "name/username/uri keyword arguments."
                )
            resolution_mode = "filters"

        display.vvvv(u"Skipping SSL validation is set to '%s'." % self.get_option('skip_ssl_verification'))
        try:
            passbolt_account = PassboltAccountKitFactory.from_string(
                passbolt_vars[self.ACCOUNT_KIT_OPTION_KEY],
                passbolt_vars[self.ACCOUNT_PASSPHRASE_OPTION_KEY],
                verify=not self.get_option('skip_ssl_verification'),
                timeout=self.get_option('timeout')
            )
            passbolt_api_client = PassboltAPIClient(
                passbolt_account,
                verify=not self.get_option('skip_ssl_verification'),
                timeout=self.get_option('timeout')
            )

            if passbolt_api_client.login():
                display.vvvv('Logged in')

            if resolution_mode == "uuid":
                resource_uuid = uuid.UUID(terms[0])
                display.vvvv(u"Passbolt lookup using '%s' as resource uuid." % resource_uuid)
            else:
                display.vvvv(
                    u"Passbolt lookup resolving by filters (name=%r, username=%r, uri=%r)."
                    % (name_filter, username_filter, uri_filter)
                )
                resource_uuid = passbolt_api_client.find_resource_uuid_by_filters(
                    expected_name=name_filter,
                    expected_username=username_filter,
                    expected_uri=uri_filter,
                )
                display.vvvv(u"Resolved to UUID '%s'." % resource_uuid)

            resource = passbolt_api_client.get_resource(resource_uuid).to_dict()
            display.vvvv('Resource retrieved successfully')

            if passbolt_api_client.logout():
                display.vvvv('Logged out')

            return [resource]

        except Exception as e:
            raise AnsibleError("Passbolt lookup failed: %s" % e)
