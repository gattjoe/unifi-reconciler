"""Declarative firewall-rule schema — the human-facing abstraction.

These pydantic models are the *desired state* contract authored under the
rules directory (``--rules``). They are deliberately decoupled from the UniFi
wire format; the
translation to/from the Integration API JSON lives entirely in ``client.py`` so
the uncertain wire boundary is isolated in one place.
"""

from __future__ import annotations

import re
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field, field_validator

_MAC_RE = re.compile(r"^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\Z")


class Action(str, Enum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    REJECT = "REJECT"


class Protocol(str, Enum):
    ALL = "all"
    TCP = "tcp"
    UDP = "udp"
    TCP_UDP = "tcp_udp"
    ICMP = "icmp"


class ConnectionStateType(str, Enum):
    ALL = "ALL"
    RESPOND_ONLY = "RESPOND_ONLY"
    CUSTOM = "CUSTOM"


class IpVersion(str, Enum):
    IPV4 = "IPV4"
    IPV6 = "IPV6"
    BOTH = "BOTH"


class Endpoint(BaseModel):
    """Source or destination selector. ``zone`` is required; the rest refine it."""

    model_config = ConfigDict(extra="forbid")

    zone: str
    """Zone name (resolved to an id at apply time). e.g. LAN, WAN, IoT, Guest, VPN."""

    ips: list[str] = Field(default_factory=list)
    """Optional CIDR/host refinements within the zone."""

    ports: list[str] = Field(default_factory=list)
    """Optional port / port-range refinements (e.g. "443", "8000-8100")."""

    networks: list[str] = Field(default_factory=list)
    """Optional network-name refinements within the zone (resolved to network_ids at
    apply time). Only effective when the live rule side's matching_target is NETWORK;
    a mismatch is refused at apply time rather than silently ignored."""

    web_domains: list[str] = Field(default_factory=list)
    """Optional domain list (e.g. "youtube.com"). Sets matching_target to WEB."""

    web_matching_type: str = ""
    """Match method for web_domains. Defaults to "DOMAIN" when web_domains is set.
    Known values: "DOMAIN" (domain + subdomains), "KEYWORD", "REGEX", "CUSTOM"."""

    app_ids: list[str] = Field(default_factory=list)
    """Optional UniFi application IDs. Sets matching_target to APP."""

    app_category_ids: list[str] = Field(default_factory=list)
    """Optional UniFi application category IDs. Sets matching_target to APP_CATEGORY."""

    macs: list[str] = Field(default_factory=list)
    """Optional client MAC addresses. Sets matching_target to CLIENT on the source side.
    Format: colon-separated hex octets, e.g. "aa:bb:cc:dd:ee:ff".

    To modify a live CLIENT rule's MAC list, provide the complete desired list (the
    reconciler overlays it onto the live rule). Leaving macs empty preserves whatever
    client_macs the live rule already carries — there is no YAML path to clear all MACs
    to an empty list; that must be done via the controller UI.

    Cannot be combined with ips: on the same endpoint — the CLIENT matching_target
    does not support IP refinement, and the reconciler will reject the combination."""

    @field_validator("macs")
    @classmethod
    def _validate_macs(cls, v: list[str]) -> list[str]:
        for mac in v:
            if not _MAC_RE.match(mac):
                raise ValueError(f"invalid MAC address: {mac!r} (expected xx:xx:xx:xx:xx:xx)")
        return [m.lower() for m in v]

    @field_validator("app_ids", "app_category_ids", mode="before")
    @classmethod
    def _coerce_ids_to_str(cls, v: object) -> object:
        if isinstance(v, list):
            return [str(x) for x in v]
        return v


class FirewallPolicyMeta(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    """Human label, mirroring the real UniFi policy name (may contain spaces). NOT
    an identity key — UniFi allows duplicate names (e.g. 60 'K8s Egress URLS'), so
    ownership and matching key on ``id`` instead."""

    id: str | None = None
    """The controller's stable, unique policy id (``_id`` on the v2 wire). This is
    the ownership/match key: a policy is managed iff this id is in the ledger
    (``managed-state.json``). Absent only for not-yet-created rules."""

    @field_validator("name")
    @classmethod
    def _valid_name(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("policy name must be non-empty")
        if len(v) > 128:
            raise ValueError("policy name too long (max 128)")
        if any(ord(c) < 0x20 for c in v):
            raise ValueError("policy name must not contain control characters")
        return v


class FirewallPolicySpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = True
    action: Action
    # UniFi catch-all/default rules use INT_MAX (2147483647) as their index, so the
    # upper bound has to admit it — the exported live ruleset contains such rules.
    index: int = Field(ge=0, le=2147483647)
    source: Endpoint
    destination: Endpoint
    protocol: Protocol = Protocol.ALL
    logging: bool = False
    description: str = ""
    # None means "don't override" — preserves live value on updates, uses CUSTOM/NEW on
    # creates. Set explicitly (e.g. connection_state_type: ALL) to override.
    connection_state_type: ConnectionStateType | None = None
    # Required when connection_state_type is CUSTOM. Ignored for ALL/RESPOND_ONLY.
    # Defaults to ["NEW"] at apply time when connection_state_type is CUSTOM and this
    # list is empty.
    connection_states: list[str] = Field(default_factory=list)
    # None means "don't override" — preserves live value on updates, uses IPV4 on
    # creates. Set explicitly (e.g. ip_version: BOTH) to override.
    ip_version: IpVersion | None = None
    # None means "don't override". True causes the controller to auto-create a
    # matching return-direction rule for established/related traffic. Required for
    # rules where the response direction is not otherwise covered (e.g. Internal↔Internal
    # UDP rules, or any rule where the live "auto allow return traffic" box was ticked).
    auto_return_traffic: bool | None = None


class FirewallPolicy(BaseModel):
    """A single declarative policy document (one YAML file under rules/policies/)."""

    model_config = ConfigDict(extra="forbid")

    apiVersion: str = "firewall.echobase.network/v1"
    kind: str = "FirewallPolicy"
    metadata: FirewallPolicyMeta
    spec: FirewallPolicySpec

    @field_validator("kind")
    @classmethod
    def _kind(cls, v: str) -> str:
        if v != "FirewallPolicy":
            raise ValueError(f"unexpected kind {v!r}, expected 'FirewallPolicy'")
        return v

    @property
    def name(self) -> str:
        return self.metadata.name

    @property
    def id(self) -> str | None:
        return self.metadata.id
