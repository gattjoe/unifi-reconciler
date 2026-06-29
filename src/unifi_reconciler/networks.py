"""Read-only introspection of the UDM's L3 networks and their firewall-zone
membership.

This is *context* for firewall-rule analysis — it is deliberately NOT part of the
reconcile/write path. Networks themselves stay managed in the UniFi UI; the
reconciler only ever reads them so a human (or an analysis pass) can tell which
zone a subnet belongs to.

The join is pure (``build_network_map``) so it unit-tests offline without HTTP,
mirroring ``export.collect``.
"""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass

# Plain YAML scalar: starts with an alphanumeric char and contains only
# safe printable chars. Anything else gets JSON-quoted (valid YAML double-quoted
# scalar) so UDM-supplied names with newlines / colons cannot inject YAML structure.
_PLAIN_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9 ._/-]*$')


def _yaml_str(v: str | None) -> str:
    """Return a YAML-safe scalar for an externally-supplied string value.

    Simple names are emitted as plain scalars; anything containing YAML-special
    characters (newlines, colons, quotes, …) is emitted as a JSON double-quoted
    string, which is a valid YAML scalar and prevents structural injection."""
    if v is None:
        return "null"
    if _PLAIN_RE.match(v):
        return v
    return json.dumps(v, ensure_ascii=False)


@dataclass(frozen=True)
class Network:
    name: str
    network_id: str
    zone: str | None      # firewall-zone name, or None if the net is in no zone
    vlan: int | None      # 802.1q tag; None for the untagged/default network
    cidr: str | None      # normalized network CIDR, e.g. 192.168.3.0/28 (None for WAN)
    purpose: str          # controller's purpose field: corporate | wan | guest | ...


def _zone_by_network(raw_zones: list[dict]) -> dict[str, str]:
    """Map each networkconf ``_id`` to its firewall-zone name via the zone's
    ``network_ids`` membership list (the authoritative direction on zone-based
    firmware — ``networkconf`` itself carries a null ``zone_id``)."""
    out: dict[str, str] = {}
    for z in raw_zones:
        name = z.get("name")
        if name is not None:
            for nid in z.get("network_ids") or []:
                out[str(nid)] = str(name)
    return out


def _norm_cidr(ip_subnet: str | None) -> str | None:
    """Normalize a host/prefix string (``192.168.3.1/28``) to its network CIDR
    (``192.168.3.0/28``). Returns the input unchanged if it can't be parsed, and
    None for WAN/dynamic networks that report no subnet."""
    if not ip_subnet:
        return None
    try:
        return str(ipaddress.ip_interface(ip_subnet).network)
    except ValueError:
        return ip_subnet


def build_network_map(raw_networks: list[dict], raw_zones: list[dict]) -> list[Network]:
    """Join raw ``networkconf`` objects with raw firewall-zone objects into a
    flat, zone-annotated network list. Sorted by zone, then vlan, then name."""
    zone_of = _zone_by_network(raw_zones)
    nets: list[Network] = []
    for nw in raw_networks:
        nid = str(nw.get("_id", ""))
        nets.append(
            Network(
                name=nw.get("name", ""),
                network_id=nid,
                zone=zone_of.get(nid),
                vlan=nw.get("vlan"),
                cidr=_norm_cidr(nw.get("ip_subnet")),
                purpose=nw.get("purpose", ""),
            )
        )
    nets.sort(key=lambda n: (n.zone or "~", n.vlan or 0, n.name))
    return nets


def render_networks_yaml(networks: list[Network]) -> str:
    """Scaffold a ``networks.yaml`` context file: factual fields pulled from the
    controller, soft fields left as ``TODO`` for a human to fill in. Hand-rolled
    (not yaml.safe_dump) so it can carry guiding comments."""
    lines = [
        "# Descriptive map of L3 networks -> firewall zones, scaffolded from the live",
        "# controller by `unifi-reconciler networks --write`. Context for firewall-rule analysis;",
        "# NOT consumed by the reconciler (networks stay managed in the UniFi UI).",
        "# Factual fields (zone/vlan/cidr/udm_purpose) come from the UDM; fill in the",
        "# TODO fields (trust/description/internet/key_hosts) by hand.",
        "apiVersion: firewall.echobase.network/v1",
        "kind: NetworkMap",
        "networks:",
    ]
    for n in networks:
        lines += [
            f"  - name: {_yaml_str(n.name)}",
            f"    zone: {_yaml_str(n.zone)}",
            f"    vlan: {n.vlan if n.vlan is not None else 'null'}",
            f"    cidr: {_yaml_str(n.cidr)}",
            f"    udm_purpose: {_yaml_str(n.purpose or None)}",
            "    trust: TODO          # high | medium | low | guest | iot",
            "    description: TODO     # what lives here / what it's for",
            "    internet: TODO        # allowed | filtered | blocked",
            "    key_hosts: []         # - { ip: 192.168.x.y, role: ... }",
        ]
    return "\n".join(lines) + "\n"
