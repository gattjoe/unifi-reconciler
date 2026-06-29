"""Pre-apply safety guardrails. Any violation aborts the whole run — a firewall
mistake can lock you out of the gateway, so these are hard stops, not warnings.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .diff import Change, ChangeType, Plan, is_managed
from .model import Action


@dataclass
class SafetyConfig:
    admin_zones: tuple[str, ...] = ("Internal",)
    """Zones from which the operator administers the UDM. A managed policy that
    BLOCK/REJECTs traffic out of one of these (to the gateway) risks lockout."""

    admin_dst_zones: tuple[str, ...] = ("Gateway",)
    """Destination zones that constitute the management plane. The broad-block
    lockout check only fires when *both* the source is an admin zone AND the
    destination is one of these zones. Blocking Internal→External is safe;
    blocking Internal→Gateway is what would cut off UDM access."""

    admin_networks: tuple[str, ...] = ()
    """Network names within an admin zone that represent the management plane (e.g.
    ``("Default",)``). A managed BLOCK/REJECT scoped to one of these networks is also
    refused as a lockout risk, even when it is narrower than the whole zone. From
    ``UNIFI_ADMIN_NETWORKS`` (comma-separated). Empty = skip network-level check."""


class SafetyError(RuntimeError):
    pass


@dataclass
class SafetyReport:
    violations: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.violations

    def raise_if_unsafe(self) -> None:
        if self.violations:
            joined = "\n  - ".join(self.violations)
            raise SafetyError(f"refusing to apply, {len(self.violations)} guardrail "
                              f"violation(s):\n  - {joined}")


def _would_cut_admin(change: Change, cfg: SafetyConfig) -> bool:
    p = change.desired
    if p is None or not p.enabled:
        return False
    if p.action == Action.ALLOW:
        return False
    if p.src_zone not in cfg.admin_zones:
        return False
    if cfg.admin_dst_zones and p.dst_zone not in cfg.admin_dst_zones:
        return False
    # Broad block: no source/destination scoping at all → lockout risk.
    # dst_networks is treated as equivalent to dst_ips (both scope the destination side).
    if not p.src_ips and not p.dst_ips and not p.src_networks and not p.dst_networks:
        return True
    # Scoped to a specific source network, but that network IS an admin network → still a risk.
    if p.src_networks and cfg.admin_networks:
        return bool(set(p.src_networks) & set(cfg.admin_networks))
    return False


def check(
    plan: Plan,
    managed: set[str],
    cfg: SafetyConfig | None = None,
) -> SafetyReport:
    """Validate a plan before it is applied. ``managed`` is the ownership ledger."""
    cfg = cfg or SafetyConfig()
    report = SafetyReport()

    # 0. Conflict-protection: a desired rule that collides with an unmanaged live
    #    policy must be adopted (via export) before it can be managed — otherwise
    #    applying would create a duplicate of a hand-made/predefined rule.
    for name in plan.conflicts:
        report.violations.append(
            f"policy {name!r} matches an existing live policy that is NOT in the "
            "ledger — refusing to create a duplicate. Run `unifi-reconciler export` to "
            "adopt it into managed-state.json first, or rename your rule."
        )

    # 1. Delete-protection: only owned (ledger) policies may ever be deleted/updated.
    for change in plan.of(ChangeType.DELETE, ChangeType.UPDATE):
        if not is_managed(change.policy_id, managed):
            report.violations.append(
                f"refusing to {change.type.value} unmanaged policy {change.name!r} "
                "(not in the ownership ledger) — this should be impossible; aborting"
            )

    # 2. Lockout-protection: no broad block out of an admin zone/network.
    for change in plan.of(ChangeType.CREATE, ChangeType.UPDATE):
        p = change.desired
        if p is not None and _would_cut_admin(change, cfg):
            scope = (f"networks {list(p.src_networks)}" if p.src_networks
                     else f"zone {p.src_zone!r}")
            report.violations.append(
                f"policy {change.name!r} would {p.action.value} traffic from "
                f"admin {scope} — refusing (would risk locking out gateway "
                "management). Scope with source ips/ports, or remove from "
                "SafetyConfig admin_zones/admin_networks."
            )

    return report
