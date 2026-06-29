"""Plan/apply orchestration tying loader → diff → safety → client together."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from .client import APIError, PolicyStore
from .diff import Change, ChangeType, Plan, build_plan, is_managed
from .loader import load_managed_state, load_policies
from .normalized import NormalizedPolicy, from_desired
from .safety import SafetyConfig, check


class ZoneError(RuntimeError):
    pass


@dataclass
class ReconcileResult:
    plan: Plan
    applied: bool
    backup: list[dict]  # pre-change managed policies, for revert
    created_ids: dict[str, str] = field(default_factory=dict)  # name → real UDM id
    respond_traffic_skipped: list[str] = field(default_factory=list)
    """CREATE attempts rejected as respond-traffic rules (predefined rules with
    stale IDs that the controller won't let you re-create). Re-run
    ``unifi-reconciler export`` to adopt the current IDs."""


def _desired_from_rules(rules_dir: Path) -> list[NormalizedPolicy]:
    return [from_desired(p) for p in load_policies(rules_dir)]


def _validate_zone_refs(desired: list[NormalizedPolicy], zones: dict[str, str]) -> None:
    referenced = {p.src_zone for p in desired} | {p.dst_zone for p in desired}
    unknown = sorted(referenced - set(zones))
    if unknown:
        raise ZoneError(
            f"rules reference zones that do not exist on the controller: {unknown}; "
            f"known zones: {sorted(zones)}"
        )


def plan(store: PolicyStore, rules_dir: Path) -> tuple[Plan, dict[str, str], list[NormalizedPolicy]]:
    desired = _desired_from_rules(rules_dir)
    managed = load_managed_state(rules_dir)
    zones = store.list_zones()
    _validate_zone_refs(desired, zones)
    live = store.list_policies()
    return build_plan(desired, live, managed), zones, desired


def _backup(live: list[NormalizedPolicy], managed: set[str]) -> list[dict]:
    return [
        {
            "name": p.name,
            "policy_id": p.policy_id,
            "enabled": p.enabled,
            "action": p.action.value,
            "index": p.index,
            "src_zone": p.src_zone,
            "dst_zone": p.dst_zone,
            "protocol": p.protocol.value,
            "logging": p.logging,
            "description": p.description,
        }
        for p in live
        if is_managed(p.policy_id, managed)
    ]


def _apply_change(store: PolicyStore, change: Change, zones: dict[str, str]) -> str | None:
    """Apply one change. Returns the new policy id for CREATE, None otherwise."""
    if change.type == ChangeType.CREATE:
        if change.desired is None:
            raise ValueError(f"CREATE change for {change.name!r} has no desired policy")
        return store.create_policy(change.desired, zones)
    elif change.type == ChangeType.UPDATE:
        if change.policy_id is None:
            raise ValueError(f"UPDATE change for {change.name!r} has no policy_id")
        if change.desired is None:
            raise ValueError(f"UPDATE change for {change.name!r} has no desired policy")
        store.update_policy(change.policy_id, change.desired, zones)
    elif change.type == ChangeType.DELETE:
        if change.policy_id is None:
            raise ValueError(f"DELETE change for {change.name!r} has no policy_id")
        store.delete_policy(change.policy_id)
    return None


def reconcile(
    store: PolicyStore,
    rules_dir: Path,
    *,
    apply: bool,
    safety_cfg: SafetyConfig | None = None,
) -> ReconcileResult:
    desired = _desired_from_rules(rules_dir)
    managed = load_managed_state(rules_dir)
    zones = store.list_zones()
    _validate_zone_refs(desired, zones)
    live = store.list_policies()
    the_plan = build_plan(desired, live, managed)
    backup = _backup(live, managed)

    report = check(the_plan, managed, safety_cfg)
    report.raise_if_unsafe()

    if not apply or the_plan.empty:
        return ReconcileResult(plan=the_plan, applied=False, backup=backup)

    # Deletes last so a rename (delete old + create new) never leaves a gap where
    # the intended policy is absent.
    ordered = the_plan.of(ChangeType.CREATE, ChangeType.UPDATE) + the_plan.of(
        ChangeType.DELETE
    )
    created_ids: dict[str, str] = {}
    respond_traffic_skipped: list[str] = []
    for change in ordered:
        try:
            new_id = _apply_change(store, change, zones)
        except APIError as exc:
            if change.type == ChangeType.CREATE and "respond traffic" in str(exc).lower():
                respond_traffic_skipped.append(change.name)
                continue
            raise
        if new_id and change.type == ChangeType.CREATE:
            created_ids[change.name] = new_id

    return ReconcileResult(plan=the_plan, applied=True, backup=backup,
                           created_ids=created_ids,
                           respond_traffic_skipped=respond_traffic_skipped)


def backup_json(result: ReconcileResult) -> str:
    return json.dumps(result.backup, indent=2, sort_keys=True)
