"""unifi_reconciler — GitOps reconciler for UDM SE zone-based firewall policies.

Ownership is explicit, not name-encoded: the reconciler owns exactly the
policies listed in the committed ownership ledger (``managed-state.json``). A
live policy whose name is not in the ledger is never modified or pruned, so
hand-made UI rules and built-in/predefined rules are safe until you adopt them
with ``unifi-reconciler export``. See ``unifi-firewall/README.md`` for the full model.
"""

__version__ = "0.2.0"

# Filename of the ownership ledger, resolved relative to the rules/ directory.
STATE_FILENAME = "managed-state.json"
