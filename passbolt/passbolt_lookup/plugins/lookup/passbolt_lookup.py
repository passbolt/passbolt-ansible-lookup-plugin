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

from ansible.errors import AnsibleError
from ansible.plugins.lookup import LookupBase
from ansible.utils.display import Display

from ansible_collections.passbolt.passbolt_lookup.plugins.module_utils.passbolt.passbolt_api_client import \
    PassboltAPIClient
from ansible_collections.passbolt.passbolt_lookup.plugins.module_utils.passbolt.account.passbolt_account_kit_factory import \
    PassboltAccountKitFactory
from ansible_collections.passbolt.passbolt_lookup.plugins.module_utils.passbolt.cryptography.exceptions.gnupg_exception import \
    GnuPGException
from ansible_collections.passbolt.passbolt_lookup.plugins.module_utils.passbolt.account.exceptions.passbolt_account_kit_deserialization_exception import \
    PassboltAccountKitDeserializationException
from ansible_collections.passbolt.passbolt_lookup.plugins.module_utils.passbolt.api.exceptions.api_format_exception import \
    APIFormatException
from ansible_collections.passbolt.passbolt_lookup.plugins.module_utils.passbolt.auth.exceptions.authentication_exception import \
    AuthenticationException

display = Display()


class LookupModule(LookupBase):
    ACCOUNT_KIT_OPTION_KEY = 'account_kit'
    ACCOUNT_PASSPHRASE_OPTION_KEY = 'passphrase'

    def run(self, terms, variables=None, **kwargs):
        self.set_options(var_options=variables, direct=kwargs)

        if not 'passbolt' in variables or not self.ACCOUNT_KIT_OPTION_KEY in variables['passbolt']:
            raise AnsibleError("Variable 'passbolt.%s' is required but not provided." % self.ACCOUNT_KIT_OPTION_KEY)

        if not self.ACCOUNT_PASSPHRASE_OPTION_KEY in variables['passbolt']:
            raise AnsibleError("Variable 'passbolt.%s' is required but not provided." % self.ACCOUNT_PASSPHRASE_OPTION_KEY)

        if len(terms) != 1:
            raise AnsibleError("expected 1 argument, got %d" % len(terms))
        resource_uuid = terms[0]
        display.debug("resource_uuid is: %s" % resource_uuid)
        display.vvvv(u"Passbolt lookup using '%s' as resource uuid." % resource_uuid)

        display.vvvv(u"Skipping SSL validation is set to '%s'." % self.get_option('skip_ssl_verification'))
        try:
            passbolt_account = PassboltAccountKitFactory.from_string(variables['passbolt'][self.ACCOUNT_KIT_OPTION_KEY],
                                                                     variables['passbolt'][
                                                                         self.ACCOUNT_PASSPHRASE_OPTION_KEY],
                                                                     verify=not self.get_option(
                                                                         'skip_ssl_verification'),
                                                                     timeout=self.get_option('timeout'))
            passbolt_api_client = PassboltAPIClient(passbolt_account,
                                                    verify=not self.get_option('skip_ssl_verification'),
                                                    timeout=self.get_option('timeout'))
            if passbolt_api_client.login():
                display.vvvv('Logged in')
        except GnuPGException as e:
            raise AnsibleError("A GnuPG exception occurred: '%s'" % e)
        except APIFormatException as e:
            raise AnsibleError("There was a problem with what the API returned: '%s'" % e)
        except AuthenticationException as e:
            raise AnsibleError("There was a problem when authenticating with the API: '%s'" % e)
        except PassboltAccountKitDeserializationException as e:
            raise AnsibleError("There was a problem when deserializing the Passbolt account kit: '%s'" % e)
        except Exception as e:
            raise AnsibleError("An unknown exception occurred: '%s'" % e)

        return []
