"""Offline tests for the read-only network-introspection join."""

from __future__ import annotations

import yaml

from unifi_reconciler.networks import Network, _zone_by_network, build_network_map, render_networks_yaml

# Shaped like the live wire data: networkconf carries _id/name/vlan/ip_subnet/
# purpose with a NULL zone_id; the firewall-zone objects carry network_ids[].
RAW_NETWORKS = [
    {"_id": "n-wan1", "name": "Spectrum", "purpose": "wan", "ip_subnet": None, "vlan": None},
    {"_id": "n-lan", "name": "Default", "purpose": "corporate", "ip_subnet": "192.168.1.1/24", "vlan": None},
    {"_id": "n-app", "name": "APP", "purpose": "corporate", "ip_subnet": "192.168.3.1/28", "vlan": 3},
    {"_id": "n-iot", "name": "IOT", "purpose": "corporate", "ip_subnet": "192.168.2.1/24", "vlan": 2},
    {"_id": "n-orphan", "name": "Unzoned", "purpose": "corporate", "ip_subnet": "10.0.0.1/24", "vlan": 9},
]
RAW_ZONES = [
    {"_id": "z-int", "name": "Internal", "network_ids": ["n-lan", "n-app", "n-iot"]},
    {"_id": "z-ext", "name": "External", "network_ids": ["n-wan1"]},
    {"_id": "z-vpn", "name": "Vpn", "network_ids": None},
]


def _by_name(nets):
    return {n.name: n for n in nets}


def test_join_assigns_zone_from_membership():
    nets = _by_name(build_network_map(RAW_NETWORKS, RAW_ZONES))
    assert nets["Default"].zone == "Internal"
    assert nets["APP"].zone == "Internal"
    assert nets["IOT"].zone == "Internal"
    assert nets["Spectrum"].zone == "External"


def test_network_not_in_any_zone_is_none():
    nets = _by_name(build_network_map(RAW_NETWORKS, RAW_ZONES))
    assert nets["Unzoned"].zone is None


def test_zone_without_name_skips_its_networks():
    """A zone missing a name field must not map network IDs to None."""
    result = _zone_by_network([{"network_ids": ["n-x", "n-y"]}])
    assert result == {}


def test_cidr_normalized_to_network_address():
    # 192.168.3.1/28 (gateway form) -> 192.168.3.0/28 (network form)
    nets = _by_name(build_network_map(RAW_NETWORKS, RAW_ZONES))
    assert nets["APP"].cidr == "192.168.3.0/28"


def test_wan_has_no_cidr():
    nets = _by_name(build_network_map(RAW_NETWORKS, RAW_ZONES))
    assert nets["Spectrum"].cidr is None


def test_sorted_by_zone_then_vlan():
    nets = build_network_map(RAW_NETWORKS, RAW_ZONES)
    # External < Internal < (none->"~") by the sort key
    zones = [n.zone for n in nets]
    assert zones == sorted(zones, key=lambda z: z or "~")


def test_render_yaml_has_facts_and_todos():
    out = render_networks_yaml(build_network_map(RAW_NETWORKS, RAW_ZONES))
    assert "kind: NetworkMap" in out
    assert "zone: Internal" in out
    assert "cidr: 192.168.3.0/28" in out
    assert "udm_purpose: wan" in out
    assert "trust: TODO" in out          # soft fields left for a human
    assert "zone: null" in out           # the unzoned network renders explicitly


def test_render_yaml_sanitizes_names_with_newlines():
    """A UDM network name with a newline must not inject a second YAML entry."""
    crafted = Network(
        name="foo\n  - name: injected", network_id="x",
        zone="Internal", vlan=None, cidr=None, purpose="corporate",
    )
    out = render_networks_yaml([crafted])
    # Output must parse as valid YAML with exactly one network entry.
    doc = yaml.safe_load(out)
    assert len(doc["networks"]) == 1
    # The literal word "injected" should NOT appear as a separate network name.
    names = [n["name"] for n in doc["networks"]]
    assert "injected" not in names
    # The full injected payload is preserved as the (quoted) name value.
    assert "foo" in names[0]
