import pytest

from unifi_reconciler.loader import (
    RuleLoadError,
    load_managed_state,
    load_policies,
)
from tests.conftest import write_policy, write_state

GOOD = """
metadata:
  name: Block IoT
  id: p1
spec:
  action: BLOCK
  index: 10
  source: {zone: IoT}
  destination: {zone: LAN}
"""


def _with_id(pid: str) -> str:
    return GOOD.replace("id: p1", f"id: {pid}")


def test_load_policies_ok(rules_dir):
    write_policy(rules_dir, "iot.yaml", GOOD)
    policies = load_policies(rules_dir)
    assert [p.name for p in policies] == ["Block IoT"]
    assert policies[0].id == "p1"


def test_duplicate_names_allowed(rules_dir):
    # UniFi names are non-unique; identity is the id, so distinct ids are fine.
    write_policy(rules_dir, "a.yaml", _with_id("p1"))
    write_policy(rules_dir, "b.yaml", _with_id("p2"))
    assert [p.id for p in load_policies(rules_dir)] == ["p1", "p2"]


def test_duplicate_ids_rejected(rules_dir):
    write_policy(rules_dir, "a.yaml", _with_id("dup"))
    write_policy(rules_dir, "b.yaml", _with_id("dup"))
    with pytest.raises(RuleLoadError, match="duplicate policy id"):
        load_policies(rules_dir)


def test_invalid_yaml_rejected(rules_dir):
    write_policy(rules_dir, "bad.yaml", "metadata: [unclosed")
    with pytest.raises(RuleLoadError):
        load_policies(rules_dir)


def test_missing_policies_dir_is_empty(tmp_path):
    assert load_policies(tmp_path) == []


def test_managed_state_absent_is_empty(tmp_path):
    assert load_managed_state(tmp_path) == set()


def test_managed_state_loads_ids(rules_dir):
    write_state(rules_dir, ["id-a", "id-b"])
    assert load_managed_state(rules_dir) == {"id-a", "id-b"}


def test_managed_state_rejects_bad_shape(rules_dir):
    (rules_dir / "managed-state.json").write_text('{"managed": "nope"}')
    with pytest.raises(RuleLoadError, match="managed"):
        load_managed_state(rules_dir)


def test_managed_state_rejects_bad_json(rules_dir):
    (rules_dir / "managed-state.json").write_text("{not json")
    with pytest.raises(RuleLoadError, match="invalid JSON"):
        load_managed_state(rules_dir)
