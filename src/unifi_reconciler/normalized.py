"""Wire-neutral normalized policy representation.

Both *desired* (from declarative YAML) and *live* (from the UDM) policies are
projected onto :class:`NormalizedPolicy` so the diff engine compares like with
like. Zones are carried as **names** here; id<->name resolution happens only at
the client boundary.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .model import Action, ConnectionStateType, FirewallPolicy, IpVersion, Protocol


class _DontCare:
    """Wildcard sentinel used in ``comparable()``.

    Represents an *unset* optional field in a desired policy. Compares equal to
    any value so a YAML rule that has no opinion on a field (e.g. no
    ``connection_state_type:`` line) never generates a spurious diff against a
    live rule that carries an explicit value. When the field IS set in the YAML,
    the real value is used and compared normally.

    Python's reflected-equality protocol ensures both ``_DONT_CARE == X`` and
    ``X == _DONT_CARE`` return ``True`` for any ``X``: ``str.__eq__(_DontCare())``
    returns ``NotImplemented``, so Python falls back to ``_DontCare.__eq__``."""

    __slots__ = ()

    def __eq__(self, other: object) -> bool:
        return True

    def __hash__(self) -> int:
        return 0

    def __repr__(self) -> str:
        return "<unset>"


_DONT_CARE = _DontCare()


@dataclass(frozen=True)
class NormalizedPolicy:
    name: str
    enabled: bool
    action: Action
    index: int
    src_zone: str
    dst_zone: str
    protocol: Protocol
    logging: bool
    description: str
    src_ips: tuple[str, ...] = ()
    src_ports: tuple[str, ...] = ()
    src_networks: tuple[str, ...] = ()
    src_web_domains: tuple[str, ...] = ()
    src_web_matching_type: str = ""
    src_app_ids: tuple[str, ...] = ()
    src_app_category_ids: tuple[str, ...] = ()
    src_macs: tuple[str, ...] = ()
    dst_ips: tuple[str, ...] = ()
    dst_ports: tuple[str, ...] = ()
    dst_networks: tuple[str, ...] = ()
    dst_web_domains: tuple[str, ...] = ()
    dst_web_matching_type: str = ""
    dst_app_ids: tuple[str, ...] = ()
    dst_app_category_ids: tuple[str, ...] = ()
    dst_macs: tuple[str, ...] = ()
    # Populated only for live policies fetched from the controller.
    policy_id: str | None = field(default=None, compare=False)
    # True for built-in/system rules the controller defines. Excluded from
    # export and never adopted into the ledger. Not part of semantic equality.
    predefined: bool = field(default=False, compare=False)
    # Connection state filter. None in desired means "don't override" — the create
    # path defaults to CUSTOM/["NEW"] and the update path preserves the live value.
    # Excluded from comparable() so unset desired rules never generate spurious diffs
    # against live rules that have an explicit state (e.g. ALL).
    connection_state_type: ConnectionStateType | None = field(default=None, compare=False)
    connection_states: tuple[str, ...] = field(default=(), compare=False)
    ip_version: IpVersion | None = field(default=None, compare=False)
    auto_return_traffic: bool | None = field(default=None, compare=False)

    def comparable(self) -> tuple:
        """Fields that define semantic equality (excludes id and name).

        Optional fields (``connection_state_type``, ``connection_states``) use
        ``_DONT_CARE`` when unset so a desired policy with no opinion on them never
        triggers a spurious diff against a live policy that carries an explicit value.
        When they are explicitly set in the YAML, the real value is used and a
        mismatch with the live rule IS detected and triggers an update."""
        return (
            self.enabled,
            self.action,
            # index intentionally excluded: the v2 controller ignores the index field on
            # both POST (assigns its own sequential value) and PUT (reordering is managed
            # internally). Sending it in the update body is harmless but never takes effect,
            # so including it in comparable() would cause a perpetual plan diff. The YAML
            # value is documentation of intended ordering only.
            self.src_zone,
            self.dst_zone,
            self.protocol,
            self.logging,
            # description intentionally excluded: the v2 API does not store this field
            # (it is omitted from both create and update bodies), so the live value is
            # always "". Including it would cause a perpetual diff for every rule that
            # carries a YAML description. Descriptions are documentation-only.
            self.src_ips,
            self.src_ports,
            self.src_networks,
            self.src_web_domains,
            self.src_web_matching_type,
            self.src_app_ids,
            self.src_app_category_ids,
            self.src_macs,
            self.dst_ips,
            self.dst_ports,
            self.dst_networks,
            self.dst_web_domains,
            self.dst_web_matching_type,
            self.dst_app_ids,
            self.dst_app_category_ids,
            self.dst_macs,
            # None → _DONT_CARE (unset in YAML, matches anything live).
            # Explicit value → compared normally; mismatch triggers an update.
            self.connection_state_type if self.connection_state_type is not None else _DONT_CARE,
            self.connection_states if self.connection_states else _DONT_CARE,
            self.ip_version if self.ip_version is not None else _DONT_CARE,
            self.auto_return_traffic if self.auto_return_traffic is not None else _DONT_CARE,
        )


def from_desired(policy: FirewallPolicy) -> NormalizedPolicy:
    s = policy.spec
    return NormalizedPolicy(
        name=policy.name,
        enabled=s.enabled,
        action=s.action,
        index=s.index,
        src_zone=s.source.zone,
        dst_zone=s.destination.zone,
        protocol=s.protocol,
        logging=s.logging,
        description=s.description,
        src_ips=tuple(s.source.ips),
        src_ports=tuple(s.source.ports),
        src_networks=tuple(s.source.networks),
        src_web_domains=tuple(s.source.web_domains),
        src_web_matching_type=s.source.web_matching_type if s.source.web_domains else "",
        src_app_ids=tuple(s.source.app_ids),
        src_app_category_ids=tuple(s.source.app_category_ids),
        src_macs=tuple(s.source.macs),
        dst_ips=tuple(s.destination.ips),
        dst_ports=tuple(s.destination.ports),
        dst_networks=tuple(s.destination.networks),
        dst_web_domains=tuple(s.destination.web_domains),
        dst_web_matching_type=s.destination.web_matching_type if s.destination.web_domains else "",
        dst_app_ids=tuple(s.destination.app_ids),
        dst_app_category_ids=tuple(s.destination.app_category_ids),
        dst_macs=tuple(s.destination.macs),
        # Identity is the controller id, carried through from metadata so the diff
        # engine matches desired↔live by id (names are non-unique labels).
        policy_id=policy.metadata.id,
        connection_state_type=s.connection_state_type,
        connection_states=tuple(s.connection_states),
        ip_version=s.ip_version,
        auto_return_traffic=s.auto_return_traffic,
    )


def to_desired_doc(p: NormalizedPolicy) -> dict:
    """Project a normalized policy back onto the declarative document shape that
    ``model.FirewallPolicy`` validates and ``loader`` reads. Used by ``export``
    to materialize live rules as YAML. Empty ip/port refinements are omitted so
    the output stays minimal."""
    source: dict = {"zone": p.src_zone}
    if p.src_ips:
        source["ips"] = list(p.src_ips)
    if p.src_ports:
        source["ports"] = list(p.src_ports)
    if p.src_networks:
        source["networks"] = list(p.src_networks)
    if p.src_web_domains:
        source["web_domains"] = list(p.src_web_domains)
        source["web_matching_type"] = p.src_web_matching_type or "DOMAIN"
    if p.src_app_ids:
        source["app_ids"] = list(p.src_app_ids)
    if p.src_app_category_ids:
        source["app_category_ids"] = list(p.src_app_category_ids)
    if p.src_macs:
        source["macs"] = list(p.src_macs)
    destination: dict = {"zone": p.dst_zone}
    if p.dst_ips:
        destination["ips"] = list(p.dst_ips)
    if p.dst_ports:
        destination["ports"] = list(p.dst_ports)
    if p.dst_networks:
        destination["networks"] = list(p.dst_networks)
    if p.dst_web_domains:
        destination["web_domains"] = list(p.dst_web_domains)
        destination["web_matching_type"] = p.dst_web_matching_type or "DOMAIN"
    if p.dst_app_ids:
        destination["app_ids"] = list(p.dst_app_ids)
    if p.dst_app_category_ids:
        destination["app_category_ids"] = list(p.dst_app_category_ids)
    if p.dst_macs:
        destination["macs"] = list(p.dst_macs)
    metadata: dict = {"name": p.name}
    if p.policy_id:
        metadata["id"] = p.policy_id
    spec: dict = {
        "enabled": p.enabled,
        "action": p.action.value,
        "index": p.index,
        "source": source,
        "destination": destination,
        "protocol": p.protocol.value,
        "logging": p.logging,
        "description": p.description,
    }
    if p.connection_state_type is not None:
        spec["connection_state_type"] = p.connection_state_type.value
        if p.connection_states:
            spec["connection_states"] = list(p.connection_states)
    if p.ip_version is not None:
        spec["ip_version"] = p.ip_version.value
    if p.auto_return_traffic is not None:
        spec["auto_return_traffic"] = p.auto_return_traffic
    return {
        "apiVersion": "firewall.echobase.network/v1",
        "kind": "FirewallPolicy",
        "metadata": metadata,
        "spec": spec,
    }
