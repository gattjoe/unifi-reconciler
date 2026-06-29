"""Import live UDM firewall policies into declarative YAML + the ownership ledger.

``unifi-reconciler export`` reads every live policy from the controller (read-only — only
GETs) and materializes it as:

  * one ``policies/<slug>.yaml`` document per rule (real name preserved),
  * the ownership ledger ``managed-state.json`` listing every adopted rule, which
    is what makes the reconciler treat them as managed,
  * an *uncommitted* ``export-raw.json`` sidecar with the full wire objects, so
    you can verify nothing important was dropped before you ever ``apply``.

FIDELITY NOTE
-------------
The declarative model captures a deliberately small slice of a policy (action,
zones, ip/port refinements, protocol, logging, index). A zone-based rule carries
many more fields (the ``matching_target`` union, connection states, ip-version,
schedules, …). These are **preserved** on update — the v2 client does a
read-modify-write, overlaying only modeled fields onto the live policy — but they
are **not** editable from YAML. ``collect`` flags any *unrecognized* keys per rule
so a truly new wire field is visible (extend the model in ``client.py`` +
``model.py`` if you need to manage it declaratively).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from . import STATE_FILENAME
from .client import policy_from_wire
from .normalized import NormalizedPolicy, to_desired_doc

# Wire keys we recognize — modeled (round-tripped) OR knowingly preserved verbatim
# by the v2 read-modify-write update. Anything outside these is an unrecognized
# field worth surfacing. Includes the v2 matching_target union + scalar fields.
_KNOWN_TOP = {
    # modeled
    "name", "enabled", "action", "index", "rule_index", "protocol", "logging",
    "description", "source", "destination", "id", "_id", "predefined", "system",
    # v2-only, preserved by RMW or now modeled
    "connection_state_type", "connection_states", "create_allow_respond",
    "icmp_typename", "icmp_v6_typename", "ip_version", "match_ip_sec",
    "match_ip_sec_type", "match_opposite_protocol", "origin_id", "schedule",
}
_KNOWN_ENDPOINT = {
    "zone_id", "zone", "ips", "ports", "port", "network_ids",  # modeled
    "web_domains", "web_matching_type",                          # modeled
    "app_ids", "app_category_ids",                               # modeled
    "client_macs",                                               # modeled (CLIENT matching_target)
    # v2 matching_target union, preserved by RMW (not in declarative model)
    "matching_target", "matching_target_type",
    "match_mac", "match_opposite_networks", "match_opposite_ips",
    "match_opposite_ports", "port_matching_type",
}


@dataclass(frozen=True)
class ExportedPolicy:
    policy: NormalizedPolicy
    filename: str
    unmodeled: tuple[str, ...]  # wire keys present but not represented in the model


@dataclass
class ExportPlan:
    policies: list[ExportedPolicy] = field(default_factory=list)
    skipped_predefined: list[str] = field(default_factory=list)
    zones: dict[str, str] = field(default_factory=dict)  # name -> id
    raw: list[dict] = field(default_factory=list)

    @property
    def has_lossy(self) -> bool:
        return any(e.unmodeled for e in self.policies)


def slugify(name: str) -> str:
    """Filesystem-safe slug for a policy filename. Names can contain spaces and
    punctuation; we lowercase, keep [a-z0-9], and join the rest with hyphens."""
    slug = re.sub(r"[^a-z0-9]+", "-", name.strip().lower()).strip("-")
    return slug or "policy"


def _unmodeled_keys(raw: dict) -> tuple[str, ...]:
    extra = [k for k in raw if k not in _KNOWN_TOP]
    for side in ("source", "destination"):
        sub = raw.get(side)
        if isinstance(sub, dict):
            extra += [f"{side}.{k}" for k in sub if k not in _KNOWN_ENDPOINT]
    return tuple(sorted(extra))


def collect(
    raw_policies: list[dict],
    zones_by_id: dict[str, str],
    networks_by_id: dict[str, str] | None = None,
) -> ExportPlan:
    """Project raw wire policies into an export plan. Predefined/system rules are
    skipped (never adopted). Filenames are ``{slug}-{shortid}`` — names are
    non-unique (60 'K8s Egress URLS'), so the id suffix keeps them distinct *and*
    stable across re-exports (no order-dependent ``-2/-3`` churn)."""
    plan = ExportPlan(zones={v: k for k, v in zones_by_id.items()})
    nb = networks_by_id or {}
    for raw in raw_policies:
        normalized = policy_from_wire(raw, zones_by_id, nb)
        if normalized.predefined:
            plan.skipped_predefined.append(normalized.name)
            continue
        shortid = (normalized.policy_id or "noid")[-8:]
        filename = f"{slugify(normalized.name)}-{shortid}.yaml"
        plan.policies.append(
            ExportedPolicy(normalized, filename, _unmodeled_keys(raw))
        )
        plan.raw.append(raw)
    plan.policies.sort(key=lambda e: e.filename)
    plan.skipped_predefined.sort()
    return plan


def render_policy_yaml(exported: ExportedPolicy) -> str:
    doc = to_desired_doc(exported.policy)
    header = [
        f"# Exported from the live UDM and adopted into {STATE_FILENAME}.",
        "# Managed by unifi-reconciler: edits here are applied on the next sync.",
    ]
    if exported.unmodeled:
        header.append(
            "# NOTE: the live rule carries unrecognized wire fields (preserved as-is "
            "on update, but not editable from this file): " + ", ".join(exported.unmodeled)
        )
    body = yaml.safe_dump(doc, sort_keys=False, default_flow_style=False, width=100)
    return "\n".join(header) + "\n" + body


def render_state_json(plan: ExportPlan) -> str:
    managed = sorted(
        [{"name": e.policy.name, "id": e.policy.policy_id} for e in plan.policies],
        key=lambda m: str(m["name"]),
    )
    doc = {
        "apiVersion": "firewall.echobase.network/v1",
        "kind": "ManagedState",
        "managed": managed,
    }
    return json.dumps(doc, indent=2) + "\n"


def render_zones_yaml(plan: ExportPlan) -> str:
    doc = {
        "apiVersion": "firewall.echobase.network/v1",
        "kind": "ZoneList",
        "zones": [{"name": name, "purpose": ""} for name in sorted(plan.zones)],
    }
    return yaml.safe_dump(doc, sort_keys=False, default_flow_style=False)


def write_export(plan: ExportPlan, out_dir: Path, *, write_zones: bool) -> list[Path]:
    """Write the policy files, ledger, and raw sidecar under ``out_dir``. Existing
    ``zones.yaml`` is left untouched (it carries human-authored purposes) unless it
    is missing or ``write_zones`` is set. Returns the list of paths written."""
    written: list[Path] = []
    policies_dir = out_dir / "policies"
    policies_dir.mkdir(parents=True, exist_ok=True)

    for exported in plan.policies:
        path = policies_dir / exported.filename
        path.write_text(render_policy_yaml(exported))
        written.append(path)

    state_path = out_dir / STATE_FILENAME
    state_path.write_text(render_state_json(plan))
    written.append(state_path)

    zones_path = out_dir / "zones.yaml"
    if write_zones or not zones_path.is_file():
        zones_path.write_text(render_zones_yaml(plan))
        written.append(zones_path)

    raw_path = out_dir / "export-raw.json"
    raw_path.write_text(json.dumps(plan.raw, indent=2) + "\n")
    written.append(raw_path)

    return written
