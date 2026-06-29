"""Desired-vs-live diff over the *owned* subset only.

Ownership is explicit and keyed on the controller's stable **id** (not the name —
UniFi names are non-unique): a policy is eligible for update/delete iff its id is
in the ledger (``managed-state.json``), passed in as ``managed``. Unmanaged
(hand-made UI / predefined) policies are reported for visibility but never mutated.
A desired rule whose id exists live but is *unmanaged* is reported as a conflict
(adopt it via ``export`` first).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from .normalized import NormalizedPolicy


class ChangeType(str, Enum):
    CREATE = "create"
    UPDATE = "update"
    DELETE = "delete"


@dataclass(frozen=True)
class Change:
    type: ChangeType
    name: str
    desired: NormalizedPolicy | None
    live: NormalizedPolicy | None

    @property
    def policy_id(self) -> str | None:
        return self.live.policy_id if self.live else None


@dataclass
class Plan:
    changes: list[Change] = field(default_factory=list)
    unmanaged_names: list[str] = field(default_factory=list)
    conflicts: list[str] = field(default_factory=list)
    """Desired rules whose id exists live but isn't in the ledger — must be adopted
    (via ``export``) before they can be managed."""
    stale_predefined: list[str] = field(default_factory=list)
    """Desired rules whose id is no longer on the live controller, but whose name
    matches a live predefined rule. The controller regenerated the predefined rule's
    id (e.g. after a firmware update). Re-run ``unifi-reconciler export`` to pick up the new
    id, then commit the updated YAML + managed-state.json."""

    @property
    def empty(self) -> bool:
        return not self.changes

    def of(self, *types: ChangeType) -> list[Change]:
        return [c for c in self.changes if c.type in types]


def is_managed(policy_id: str | None, managed: set[str]) -> bool:
    return policy_id is not None and policy_id in managed


def build_plan(
    desired: list[NormalizedPolicy],
    live: list[NormalizedPolicy],
    managed: set[str],
) -> Plan:
    live_by_id = {p.policy_id: p for p in live if p.policy_id}
    live_managed = {pid: p for pid, p in live_by_id.items() if pid in managed}
    unmanaged = sorted(p.name for p in live if not is_managed(p.policy_id, managed))
    live_predefined_names = {p.name for p in live if p.predefined}

    plan = Plan(unmanaged_names=unmanaged)

    # creates + updates, matched by id
    for want in desired:
        pid = want.policy_id
        if pid and pid in live_managed:
            have = live_managed[pid]
            if want.comparable() != have.comparable():
                plan.changes.append(Change(ChangeType.UPDATE, want.name, want, have))
        elif pid and pid in live_by_id:
            # id exists live but isn't owned — adopt via export before managing.
            plan.conflicts.append(want.name)
        elif want.name in live_predefined_names:
            # id is gone but a live predefined rule with the same name exists —
            # the controller regenerated the predefined rule's id (e.g. firmware
            # update). Creating it via POST is rejected as respond-traffic. Skip
            # and tell the user to re-export to pick up the new id.
            plan.stale_predefined.append(want.name)
        else:
            # no id (new rule) or an id no longer present live → a create.
            plan.changes.append(Change(ChangeType.CREATE, want.name, want, None))

    # deletes: owned-and-live but no longer desired
    desired_ids = {p.policy_id for p in desired if p.policy_id}
    for pid, have in live_managed.items():
        if pid not in desired_ids:
            plan.changes.append(Change(ChangeType.DELETE, have.name, None, have))

    plan.changes.sort(key=lambda c: (c.type.value, c.name, c.policy_id or ""))
    plan.conflicts.sort()
    plan.stale_predefined.sort()
    return plan
