"""
Make ansible_collections.passbolt.passbolt_lookup imports resolve to the
repo's source tree so tests run without installing the collection.
"""
import pathlib
import sys
import types

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent

# The repo has:  passbolt/passbolt_lookup/plugins/...
# Imports use:   ansible_collections.passbolt.passbolt_lookup.plugins....
#
# Create synthetic namespace packages for the prefix, then point __path__
# at the real source so normal imports work.

_NAMESPACE_CHAIN = [
    "ansible_collections",
    "ansible_collections.passbolt",
    "ansible_collections.passbolt.passbolt_lookup",
    "ansible_collections.passbolt.passbolt_lookup.plugins",
    "ansible_collections.passbolt.passbolt_lookup.plugins.module_utils",
]

_SOURCE_ROOT = REPO_ROOT / "passbolt" / "passbolt_lookup" / "plugins" / "module_utils"

for ns in _NAMESPACE_CHAIN:
    if ns not in sys.modules:
        mod = types.ModuleType(ns)
        mod.__path__ = []
        mod.__package__ = ns
        sys.modules[ns] = mod

sys.modules[_NAMESPACE_CHAIN[-1]].__path__ = [str(_SOURCE_ROOT)]
