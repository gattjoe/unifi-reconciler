import json

from unifi_reconciler.export import collect, slugify, write_export
from unifi_reconciler.loader import load_managed_state, load_policies
from unifi_reconciler.model import Action
from unifi_reconciler.normalized import to_desired_doc

ZONES_BY_ID = {"z-lan": "LAN", "z-iot": "IoT", "z-wan": "WAN"}


def raw(name, **over):
    base = {
        "id": f"id-{name}",
        "name": name,
        "action": "BLOCK",
        "index": 10,
        "protocol": "all",
        "logging": False,
        "description": "",
        "source": {"zone_id": "z-iot"},
        "destination": {"zone_id": "z-lan"},
    }
    base.update(over)
    return base


def test_slugify():
    assert slugify("Block IoT to LAN") == "block-iot-to-lan"
    assert slugify("  Weird/Name!!  ") == "weird-name"
    assert slugify("***") == "policy"


def test_collect_skips_predefined():
    plan = collect([raw("Real"), raw("Builtin", predefined=True)], ZONES_BY_ID)
    assert [e.policy.name for e in plan.policies] == ["Real"]
    assert plan.skipped_predefined == ["Builtin"]


def test_collect_filenames_are_id_suffixed_and_stable():
    # Same name, distinct ids -> distinct, id-stable files (no order-dependent -2).
    plan = collect([raw("Dup", id="aaaa1111"), raw("Dup", id="bbbb2222")], ZONES_BY_ID)
    assert sorted(e.filename for e in plan.policies) == ["dup-aaaa1111.yaml", "dup-bbbb2222.yaml"]


def test_collect_flags_only_unrecognized_fields():
    plan = collect(
        [raw("Fancy",
             connection_states=["ESTABLISHED"],          # known v2 field, preserved by RMW
             bogus_top=1,                                  # genuinely unknown
             source={"zone_id": "z-iot", "client_macs": ["x"], "weird_key": True})],
        ZONES_BY_ID,
    )
    unmodeled = plan.policies[0].unmodeled
    assert "connection_states" not in unmodeled        # recognized, not flagged
    assert "source.client_macs" not in unmodeled        # recognized union field
    assert "bogus_top" in unmodeled                      # unknown -> surfaced
    assert "source.weird_key" in unmodeled


def test_export_roundtrips_through_loader(tmp_path):
    plan = collect([raw("Block IoT", action="REJECT", index=42)], ZONES_BY_ID)
    write_export(plan, tmp_path, write_zones=True)

    # The ledger owns the exported rule by id...
    assert load_managed_state(tmp_path) == {"id-Block IoT"}
    # ...and the emitted YAML re-loads cleanly with id + fields intact.
    loaded = load_policies(tmp_path)
    assert [p.name for p in loaded] == ["Block IoT"]
    assert loaded[0].id == "id-Block IoT"
    assert loaded[0].spec.action == Action.REJECT
    assert loaded[0].spec.index == 42

    # Raw sidecar is written for fidelity review.
    raw_dump = json.loads((tmp_path / "export-raw.json").read_text())
    assert raw_dump[0]["name"] == "Block IoT"


def test_existing_zones_yaml_preserved(tmp_path):
    (tmp_path / "zones.yaml").write_text("zones:\n  - name: LAN\n    purpose: keep me\n")
    plan = collect([raw("X")], ZONES_BY_ID)
    write_export(plan, tmp_path, write_zones=False)
    assert "keep me" in (tmp_path / "zones.yaml").read_text()


def test_to_desired_doc_omits_empty_refinements():
    plan = collect([raw("X")], ZONES_BY_ID)
    doc = to_desired_doc(plan.policies[0].policy)
    assert doc["spec"]["source"] == {"zone": "IoT"}
    assert "ips" not in doc["spec"]["source"]
