from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

DOCUMENTATION = r"""
  name: passbolt_lookup
  author: Passbolt <contact@passbolt.com>
  version_added: "0.1"
  short_description: Passbolt Lookup Plugin
  description:
      - This lookup plugin returns a resource stored in Passbolt.
  options:
    _terms:
      description: Passbolt resource UUID to query.
      required: True
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

import uuid

from ansible.errors import AnsibleError
from ansible.plugins.lookup import LookupBase
from ansible.utils.display import Display

from ansible_collections.passbolt.passbolt_lookup.plugins.module_utils.passbolt.passbolt_api_client import \
    PassboltAPIClient
from ansible_collections.passbolt.passbolt_lookup.plugins.module_utils.passbolt.account.passbolt_account_kit_factory import \
    PassboltAccountKitFactory

display = Display()

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

        if len(terms) != 1:
            raise AnsibleError("expected 1 argument, got %d" % len(terms))
        resource_uuid = terms[0]
        display.debug("resource_uuid is: %s" % resource_uuid)
        display.vvvv(u"Passbolt lookup using '%s' as resource uuid." % resource_uuid)

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

            resource = passbolt_api_client.get_resource(uuid.UUID(resource_uuid)).to_dict()
            display.vvvv('Resource retrieved successfully')

            if passbolt_api_client.logout():
                display.vvvv('Logged out')

            return [resource]

        except Exception as e:
            raise AnsibleError("Passbolt lookup failed: %s" % e)
